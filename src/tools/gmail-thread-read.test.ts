import assert from "node:assert/strict";
import test from "node:test";
import { EMAIL_BYPASS_PATTERNS } from "../bypass/email-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGmailThreadTool } from "./gmail-thread-read";

test("gmail_thread_read returns wrapped benign thread", async () => {
  const result = await runThread("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "gmail_thread" });
});

test("gmail_thread_read returns guarded malicious thread", async () => {
  const result = await runThread("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "gmail_thread", markerKind: "GMAIL" });
});

test("gmail_thread_read returns structured errors for API failure and invalid params", async () => {
  const apiError = await createFirewallGmailThreadTool({
    firewall: createFakeFirewall(),
    tokenCache: fakeTokenCache(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { threadId: "t1" });
  assert.equal(apiError.json.error, true);
  const invalid = await createFirewallGmailThreadTool({ firewall: createFakeFirewall(), tokenCache: fakeTokenCache() }).execute("1", {});
  assert.equal(invalid.json.error, true);
});

test("gmail_thread_read renders messages in order and truncates long thread", async () => {
  const result = await runThread("BENIGN", "x".repeat(5_000), { maxChars: 500 });
  assert.equal(result.json.truncated, true);
  assert.match(String(result.json.text), /Thread message 1/);
});

test("gmail_thread_read bypass detects thread API reads", () => {
  const pattern = EMAIL_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "gmail_thread_read")!;
  assert.equal(pattern.detect("curl https://gmail.googleapis.com/gmail/v1/users/me/threads/t1").matched, true);
});

async function runThread(prediction: "BENIGN" | "MALICIOUS", body = "hello", params: Record<string, unknown> = {}) {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGmailThreadTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      tokenCache: fakeTokenCache(),
      fetchImpl: (async () => new Response(JSON.stringify(thread(body)), { status: 200 })) as typeof fetch,
    }).execute("1", { threadId: "t1", ...params }),
  );
}

function thread(body: string) {
  return {
    id: "t1",
    messages: [
      { id: "m1", threadId: "t1", payload: { mimeType: "text/plain", body: { data: b64(body) } } },
      { id: "m2", threadId: "t1", payload: { mimeType: "text/plain", body: { data: b64("second") } } },
    ],
  };
}

function fakeTokenCache() {
  return { async get() { return { accessToken: "token", tokenType: "Bearer", expiresAt: Date.now() + 1000 }; } };
}

function b64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}
