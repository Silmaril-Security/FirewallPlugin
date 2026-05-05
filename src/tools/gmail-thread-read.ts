import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import type { WrapperContext } from "../core";
import {
  buildGmailScanText,
  decodeMessagePayload,
  fetchGmailJson,
  readNumber,
  readRecord,
  readRequiredString,
  renderGmailMessage,
  runGmailToolSafely,
  runInspectedGmailTool,
  type GmailToolOptions,
} from "./gmail-common";

export const FIREWALL_GMAIL_THREAD_TOOL_NAME = "gmail_thread_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    threadId: { type: "string" },
    maxChars: { type: "number", minimum: 100 },
  },
  required: ["threadId"],
} as const;

export function createFirewallGmailThreadTool(options: GmailToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GMAIL_THREAD_TOOL_NAME,
    source: "gmail_thread",
    markerKind: "GMAIL",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GMAIL_THREAD_TOOL_NAME,
    label: "Gmail Thread Read",
    description: "Read a Gmail thread through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGmailToolSafely(FIREWALL_GMAIL_THREAD_TOOL_NAME, "gmail_thread", options.logger, () =>
          runFirewallGmailThreadRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGmailThreadRead(input: {
  ctx: WrapperContext;
  options: GmailToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const threadId = readRequiredString(input.rawParams.threadId, "threadId");
  const startedAt = Date.now();
  const thread = readRecord(
    await fetchGmailJson(`users/me/threads/${encodeURIComponent(threadId)}?format=full`, input.options),
  );
  const messages = Array.isArray(thread?.messages) ? thread.messages.filter((item): item is Record<string, unknown> => !!readRecord(item)) : [];
  if (!messages.length) throw new Error("Gmail thread has no messages");
  const rendered = messages.map((message, index) => `Thread message ${index + 1}\n${renderGmailMessage(message, decodeMessagePayload(message.payload))}`);
  const contentText = [`Gmail thread: ${threadId}`, "", ...rendered].join("\n\n");

  return runInspectedGmailTool({
    ctx: input.ctx,
    contentText,
    scanText: buildGmailScanText(FIREWALL_GMAIL_THREAD_TOOL_NAME, contentText),
    identityFields: {
      threadId,
      messageCount: messages.length,
    },
    identityLines: [`thread_id: ${threadId}`, `message_count: ${messages.length}`],
    contentNoun: "Gmail thread content",
    maxChars: readNumber(input.rawParams.maxChars, 20_000),
    tookMs: Date.now() - startedAt,
    falsePositiveReviewStore: input.options.falsePositiveReviewStore,
  });
}
