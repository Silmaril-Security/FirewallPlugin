import assert from "node:assert/strict";
import test from "node:test";
import { EMAIL_BYPASS_PATTERNS } from "../bypass/email-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGmailSearchTool } from "./gmail-search";

test("gmail_search returns wrapped benign search results", async () => {
  const result = await runSearch("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "gmail_search" });
});

test("gmail_search returns guarded malicious search results", async () => {
  const result = await runSearch("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "gmail_search", markerKind: "GMAIL" });
});

test("gmail_search returns structured errors for API failure and invalid params", async () => {
  const apiError = await createFirewallGmailSearchTool({
    firewall: createFakeFirewall(),
    tokenCache: fakeTokenCache(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { query: "from:a" });
  assert.equal(apiError.json.error, true);
  const invalid = await createFirewallGmailSearchTool({ firewall: createFakeFirewall(), tokenCache: fakeTokenCache() }).execute("1", {});
  assert.equal(invalid.json.error, true);
});

test("gmail_search returns snippets as JSON array and classifier sees structured text", async () => {
  const calls: string[] = [];
  const result = await withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGmailSearchTool({
      firewall: {
        async classify(text) {
          calls.push(text);
          return { prediction: "BENIGN", score: 0.1 };
        },
      },
      tokenCache: fakeTokenCache(),
      fetchImpl: searchFetch(),
    }).execute("1", { query: "from:a", maxResults: 2 }),
  );
  assert.equal(result.json.resultCount, 2);
  assert.match(calls[0], /results/);
});

test("gmail_search bypass detects search API reads", () => {
  const pattern = EMAIL_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "gmail_search")!;
  assert.equal(pattern.detect("curl https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from%3Aa").matched, true);
});

async function runSearch(prediction: "BENIGN" | "MALICIOUS") {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGmailSearchTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      tokenCache: fakeTokenCache(),
      fetchImpl: searchFetch(),
    }).execute("1", { query: "from:a", maxResults: 2 }),
  );
}

function searchFetch(): typeof fetch {
  return (async (url: string | URL | Request) => {
    const text = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    if (text.includes("format=metadata")) {
      const id = /messages\/([^?]+)/.exec(text)?.[1] ?? "m";
      return new Response(JSON.stringify({ id, threadId: "t1", snippet: `snippet ${id}` }), { status: 200 });
    }
    return new Response(JSON.stringify({ messages: [{ id: "m1" }, { id: "m2" }] }), { status: 200 });
  }) as typeof fetch;
}

function fakeTokenCache() {
  return { async get() { return { accessToken: "token", tokenType: "Bearer", expiresAt: Date.now() + 1000 }; } };
}
