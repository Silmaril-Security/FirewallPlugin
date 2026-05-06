#!/usr/bin/env node
import { createFirewallWebFetchTool } from "../src/tools/web-fetch.ts";

const url = process.argv[2] ?? "https://example.com";

const firewall = {
  async classify(text, options) {
    return {
      prediction: "BENIGN",
      score: 0.01,
      smoke: true,
      inspectedChars: text.length,
      hook: options?.hook,
      toolName: options?.toolName,
    };
  },
};

const logger = {
  info: (message) => console.log(message),
  warn: (message) => console.warn(message),
  error: (message) => console.error(message),
};

const tool = createFirewallWebFetchTool({
  firewall,
  logger,
  fetchConfig: {
    maxChars: 4000,
    maxResponseBytes: 128_000,
    timeoutSeconds: 20,
  },
});

const result = await tool.execute("manual-web-fetch-smoke", {
  url,
  maxChars: 4000,
});

const payload = result?.json;
if (!payload || payload?.firewall?.prediction !== "BENIGN" || typeof payload.text !== "string") {
  console.error(JSON.stringify(result, null, 2));
  throw new Error("web_fetch smoke failed: expected benign JSON payload with text");
}

console.log(JSON.stringify({
  tool: tool.name,
  url: payload.url,
  finalUrl: payload.finalUrl,
  status: payload.status,
  contentType: payload.contentType,
  prediction: payload.firewall.prediction,
  score: payload.firewall.score,
  textPreview: payload.text.slice(0, 240),
}, null, 2));
