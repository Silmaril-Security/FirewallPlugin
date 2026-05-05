import { HookLabel } from "@silmaril-security/sdk";
import { truncateText } from "openclaw/plugin-sdk/provider-web-fetch";
import type { FirewallFalsePositiveReviewStore } from "../false-positive-review-store";
import {
  buildApprovalHandle,
  buildBenignPayload,
  buildGuardedPayload,
  isMaliciousPrediction,
  runClassification,
  sha256,
  wrapAndTruncate,
  type FirewallClassifier,
  type Logger,
  type SourceLabel,
  type WrapperContext,
} from "../core";

export const DEFAULT_GITHUB_MAX_CHARS = 20_000;
export const MAX_GITHUB_SCAN_CHARS = 100_000;

export type GitHubToolOptions = {
  firewall: FirewallClassifier;
  logger?: Logger;
  fetchImpl?: typeof fetch;
  githubToken?: string;
  falsePositiveReviewStore?: FirewallFalsePositiveReviewStore;
};

export type GitHubToolRef = {
  owner: string;
  repo: string;
};

export async function runInspectedGitHubTool(input: {
  ctx: WrapperContext;
  contentText: string;
  scanText: string;
  identityFields: Record<string, unknown>;
  identityLines: readonly string[];
  contentNoun: string;
  urlForHash?: string;
  maxChars: number;
  tookMs: number;
  falsePositiveReviewStore?: FirewallFalsePositiveReviewStore;
}): Promise<Record<string, unknown>> {
  const contentHash = sha256(input.contentText);
  const urlHash = input.urlForHash ? sha256(input.urlForHash) : undefined;
  const firewallResult = await runClassification({
    firewall: input.ctx.firewall,
    text: input.scanText,
    hook: HookLabel.TOOL_RESPONSE,
    toolName: input.ctx.toolName,
    logger: input.ctx.logger,
  });

  input.ctx.logger?.info?.(
    `firewall-plugin: ${input.ctx.toolName} wrapper classified content as ${firewallResult.prediction}`,
  );

  const blocked = isMaliciousPrediction(firewallResult.prediction);
  const approvalHandle = blocked ? buildApprovalHandle(input.ctx.source, contentHash) : undefined;
  input.ctx.logger?.info?.(
    `firewall-plugin: primary firewall decision source=${input.ctx.source} toolName=${input.ctx.toolName} hook=${HookLabel.TOOL_RESPONSE} prediction=${firewallResult.prediction} score=${firewallResult.score} contentHash=sha256:${contentHash}${urlHash ? ` urlHash=sha256:${urlHash}` : ""}${approvalHandle ? ` approvalHandle=${approvalHandle}` : ""}`,
  );

  if (blocked) {
    return buildGuardedPayload({
      ctx: input.ctx,
      contentText: input.contentText,
      contentHash,
      urlHash,
      contentNoun: input.contentNoun,
      identityFields: input.identityFields,
      identityLines: input.identityLines,
      firewallResult,
      hook: HookLabel.TOOL_RESPONSE,
      tookMs: input.tookMs,
      falsePositiveReview: input.falsePositiveReviewStore
        ? {
            store: input.falsePositiveReviewStore,
            firewallInput: {
              text: input.scanText,
              options: {
                hook: HookLabel.TOOL_RESPONSE,
                toolName: input.ctx.toolName,
              },
            },
            metadata: {
              contentNoun: input.contentNoun,
              ...(urlHash ? { urlHash } : {}),
            },
          }
        : undefined,
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
    urlHash,
    identityFields: input.identityFields,
    firewallResult,
    hook: HookLabel.TOOL_RESPONSE,
    tookMs: input.tookMs,
    truncated: wrapped.truncated,
  });
}

export async function runGitHubToolSafely(
  toolName: string,
  source: SourceLabel,
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

export function readString(value: unknown, label: string, required = false): string | undefined {
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  if (required) {
    throw new Error(`${label} is required`);
  }
  return undefined;
}

export function readPositiveInteger(value: unknown, label: string, required = false): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return value;
  }
  if (typeof value === "string" && /^\d+$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }
  if (required) {
    throw new Error(`${label} must be a positive integer`);
  }
  return undefined;
}

export function readMaxChars(params: Record<string, unknown>): number {
  const raw = params.maxChars;
  if (typeof raw !== "number" || !Number.isFinite(raw)) return DEFAULT_GITHUB_MAX_CHARS;
  return Math.max(100, Math.floor(raw));
}

export function encodePathSegments(pathValue: string): string {
  return pathValue.split("/").map(encodeURIComponent).join("/");
}

export function truncateForScan(value: string): string {
  return truncateText(value, MAX_GITHUB_SCAN_CHARS).text;
}

export function readRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

export function readOptionalString(record: Record<string, unknown> | undefined, key: string): string {
  const value = record?.[key];
  return typeof value === "string" ? value : "";
}

export function readOptionalNumber(record: Record<string, unknown> | undefined, key: string): number {
  const value = record?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export function readArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => !!readRecord(item)) : [];
}

export function apiBase(owner: string, repo: string): string {
  return `https://api.github.com/repos/${owner}/${repo}`;
}
