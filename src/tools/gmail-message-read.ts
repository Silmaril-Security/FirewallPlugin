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

export const FIREWALL_GMAIL_MESSAGE_TOOL_NAME = "gmail_message_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    messageId: { type: "string" },
    maxChars: { type: "number", minimum: 100 },
  },
  required: ["messageId"],
} as const;

export function createFirewallGmailMessageTool(options: GmailToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GMAIL_MESSAGE_TOOL_NAME,
    source: "gmail_message",
    markerKind: "GMAIL",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GMAIL_MESSAGE_TOOL_NAME,
    label: "Gmail Message Read",
    description: "Read a Gmail message through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGmailToolSafely(FIREWALL_GMAIL_MESSAGE_TOOL_NAME, "gmail_message", options.logger, () =>
          runFirewallGmailMessageRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGmailMessageRead(input: {
  ctx: WrapperContext;
  options: GmailToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const messageId = readRequiredString(input.rawParams.messageId, "messageId");
  const startedAt = Date.now();
  const message = readRecord(
    await fetchGmailJson(`users/me/messages/${encodeURIComponent(messageId)}?format=full`, input.options),
  );
  if (!message) throw new Error("Gmail message API returned an unexpected response");
  const bodyText = decodeMessagePayload(message.payload);
  if (!bodyText.trim()) throw new Error("Gmail message body is empty");
  const contentText = renderGmailMessage(message, bodyText);

  return runInspectedGmailTool({
    ctx: input.ctx,
    contentText,
    scanText: buildGmailScanText(FIREWALL_GMAIL_MESSAGE_TOOL_NAME, contentText),
    identityFields: {
      messageId,
      threadId: message.threadId,
    },
    identityLines: [`message_id: ${messageId}`, `thread_id: ${String(message.threadId ?? "")}`],
    contentNoun: "Gmail message content",
    maxChars: readNumber(input.rawParams.maxChars, 20_000),
    tookMs: Date.now() - startedAt,
    falsePositiveReviewStore: input.options.falsePositiveReviewStore,
  });
}
