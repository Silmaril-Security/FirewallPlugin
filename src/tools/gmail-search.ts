import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import type { WrapperContext } from "../core";
import {
  buildGmailScanText,
  fetchGmailJson,
  readNumber,
  readRecord,
  readRequiredString,
  readString,
  runGmailToolSafely,
  runInspectedGmailTool,
  type GmailToolOptions,
} from "./gmail-common";

export const FIREWALL_GMAIL_SEARCH_TOOL_NAME = "gmail_search" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    query: { type: "string" },
    maxResults: { type: "number", minimum: 1, maximum: 25, default: 10 },
    maxChars: { type: "number", minimum: 100 },
  },
  required: ["query"],
} as const;

export function createFirewallGmailSearchTool(options: GmailToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GMAIL_SEARCH_TOOL_NAME,
    source: "gmail_search",
    markerKind: "GMAIL",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GMAIL_SEARCH_TOOL_NAME,
    label: "Gmail Search",
    description: "Search Gmail snippets through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGmailToolSafely(FIREWALL_GMAIL_SEARCH_TOOL_NAME, "gmail_search", options.logger, () =>
          runFirewallGmailSearch({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGmailSearch(input: {
  ctx: WrapperContext;
  options: GmailToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const query = readRequiredString(input.rawParams.query, "query");
  const maxResults = Math.max(1, Math.min(25, Math.floor(readNumber(input.rawParams.maxResults, 10))));
  const startedAt = Date.now();
  const search = readRecord(
    await fetchGmailJson(
      `users/me/messages?q=${encodeURIComponent(query)}&maxResults=${maxResults}`,
      input.options,
    ),
  );
  const messages = Array.isArray(search?.messages) ? search.messages.filter((item): item is Record<string, unknown> => !!readRecord(item)) : [];
  const snippets: Array<Record<string, unknown>> = [];
  for (const message of messages) {
    const id = readString(message.id);
    if (!id) continue;
    const raw = readRecord(
      await fetchGmailJson(`users/me/messages/${encodeURIComponent(id)}?format=metadata`, input.options),
    );
    snippets.push({
      id,
      threadId: raw?.threadId,
      snippet: raw?.snippet,
    });
  }
  const contentText = JSON.stringify({ query, results: snippets }, null, 2);

  return runInspectedGmailTool({
    ctx: input.ctx,
    contentText,
    scanText: buildGmailScanText(FIREWALL_GMAIL_SEARCH_TOOL_NAME, contentText),
    identityFields: {
      query,
      resultCount: snippets.length,
    },
    identityLines: [`query: ${query}`, `result_count: ${snippets.length}`],
    contentNoun: "Gmail search results",
    maxChars: readNumber(input.rawParams.maxChars, 20_000),
    tookMs: Date.now() - startedAt,
    falsePositiveReviewStore: input.options.falsePositiveReviewStore,
  });
}
