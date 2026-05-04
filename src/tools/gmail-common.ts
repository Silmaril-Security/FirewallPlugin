import { HookLabel } from "@silmaril-security/sdk";
import {
  buildBenignPayload,
  buildGuardedPayload,
  isMaliciousPrediction,
  runClassification,
  sha256,
  wrapAndTruncate,
  type FirewallClassifier,
  type Logger,
  type WrapperContext,
} from "../core";
import type { GoogleTokenCache } from "../auth";

export const DEFAULT_GMAIL_MAX_CHARS = 20_000;
const MAX_GMAIL_SCAN_CHARS = 100_000;

export type GmailToolOptions = {
  firewall: FirewallClassifier;
  logger?: Logger;
  fetchImpl?: typeof fetch;
  tokenCache: GoogleTokenCache;
};

export async function fetchGmailJson(path: string, options: GmailToolOptions): Promise<unknown> {
  const token = await options.tokenCache.get();
  const response = await (options.fetchImpl ?? fetch)(`https://gmail.googleapis.com/gmail/v1/${path}`, {
    headers: {
      Authorization: `${token.tokenType} ${token.accessToken}`,
      Accept: "application/json",
    },
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Gmail API request failed (${response.status}): ${text.slice(0, 500)}`);
  }
  return text ? JSON.parse(text) : {};
}

export async function runInspectedGmailTool(input: {
  ctx: WrapperContext;
  contentText: string;
  scanText: string;
  identityFields: Record<string, unknown>;
  identityLines: readonly string[];
  contentNoun: string;
  maxChars: number;
  tookMs: number;
}): Promise<Record<string, unknown>> {
  const contentHash = sha256(input.contentText);
  const firewallResult = await runClassification({
    firewall: input.ctx.firewall,
    text: input.scanText,
    hook: HookLabel.TOOL_RESPONSE,
    toolName: input.ctx.toolName,
    logger: input.ctx.logger,
  });

  if (isMaliciousPrediction(firewallResult.prediction)) {
    return buildGuardedPayload({
      ctx: input.ctx,
      contentText: input.contentText,
      contentHash,
      contentNoun: input.contentNoun,
      identityFields: input.identityFields,
      identityLines: input.identityLines,
      firewallResult,
      hook: HookLabel.TOOL_RESPONSE,
      tookMs: input.tookMs,
      sanitizedReason: `Firewall classified fetched ${input.contentNoun} as MALICIOUS.`,
    });
  }

  const wrapped = wrapAndTruncate({
    value: input.contentText,
    source: input.ctx.toolName,
    maxChars: input.maxChars,
  });
  return buildBenignPayload({
    ctx: input.ctx,
    text: wrapped.text,
    rawLength: input.contentText.length,
    contentHash,
    identityFields: input.identityFields,
    firewallResult,
    hook: HookLabel.TOOL_RESPONSE,
    tookMs: input.tookMs,
    truncated: wrapped.truncated,
  });
}

export async function runGmailToolSafely(
  toolName: string,
  source: "gmail_message" | "gmail_thread" | "gmail_search",
  logger: Logger | undefined,
  run: () => Promise<Record<string, unknown>>,
): Promise<Record<string, unknown>> {
  try {
    return await run();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger?.warn?.(`firewall-plugin: ${toolName} wrapper failed open with structured error: ${message}`);
    return {
      error: true,
      source,
      toolName,
      message,
      firewall: {
        inspected: false,
        failOpen: true,
      },
      text: `${toolName} failed before firewall inspection: ${message}`,
    };
  }
}

export function decodeMessagePayload(payload: unknown, depth = 0): string {
  const record = readRecord(payload);
  if (!record) return "";
  const mimeType = readString(record.mimeType);
  const bodyText = decodeBody(record.body);
  if (bodyText && mimeType === "text/html") return htmlToText(bodyText);
  if (bodyText) return bodyText;

  if (depth >= 5) return "";
  const parts = Array.isArray(record.parts) ? record.parts : [];
  const textParts: string[] = [];
  const htmlParts: string[] = [];
  for (const part of parts) {
    const partRecord = readRecord(part);
    const partMime = readString(partRecord?.mimeType);
    const decoded = decodeMessagePayload(part, depth + 1);
    if (!decoded) continue;
    if (partMime === "text/html") htmlParts.push(decoded);
    else if (!partMime || partMime.startsWith("text/") || partMime.startsWith("multipart/")) textParts.push(decoded);
  }
  return (textParts.length ? textParts : htmlParts).join("\n\n");
}

export function renderGmailMessage(message: Record<string, unknown>, bodyText = decodeMessagePayload(message.payload)): string {
  const headers = readHeaders(readRecord(message.payload)?.headers);
  return [
    `Gmail message: ${readString(message.id)}`,
    `Thread: ${readString(message.threadId)}`,
    `From: ${headers.from ?? ""}`,
    `To: ${headers.to ?? ""}`,
    `Subject: ${headers.subject ?? ""}`,
    `Date: ${headers.date ?? ""}`,
    "",
    "Message body:",
    bodyText || "(empty)",
  ].join("\n");
}

export function buildGmailScanText(toolName: string, content: unknown): string {
  return JSON.stringify({
    source: "openclaw",
    tool_name: toolName,
    content: truncate(String(content), MAX_GMAIL_SCAN_CHARS),
  });
}

export function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function readRequiredString(value: unknown, label: string): string {
  const parsed = readString(value);
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

export function readNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export function readRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function decodeBody(body: unknown): string {
  const data = readString(readRecord(body)?.data);
  return data ? base64UrlDecode(data) : "";
}

function base64UrlDecode(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function readHeaders(value: unknown): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!Array.isArray(value)) return headers;
  for (const header of value) {
    const record = readRecord(header);
    const name = readString(record?.name)?.toLowerCase();
    const headerValue = readString(record?.value);
    if (name && headerValue) headers[name] = headerValue;
  }
  return headers;
}

function htmlToText(value: string): string {
  return value
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<\/(p|div|li|h[1-6])>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+\n/g, "\n")
    .replace(/[ \t]+/g, " ")
    .trim();
}

function truncate(value: string, maxChars: number): string {
  return value.length > maxChars ? value.slice(0, maxChars) : value;
}
