import assert from "node:assert/strict";
import test from "node:test";
import { EMAIL_BYPASS_PATTERNS } from "../bypass/email-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { decodeMessagePayload } from "./gmail-common";
import { createFirewallGmailMessageTool } from "./gmail-message-read";

test("gmail_message_read returns wrapped benign message", async () => {
  const result = await runMessage("BENIGN", plainMessage());
  expectBenignPayload(result.json as Record<string, unknown>, { source: "gmail_message" });
});

test("gmail_message_read returns guarded malicious message", async () => {
  const result = await runMessage("MALICIOUS", plainMessage());
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "gmail_message", markerKind: "GMAIL" });
});

test("gmail_message_read returns structured error for API failure and invalid params", async () => {
  const apiError = await createFirewallGmailMessageTool({
    firewall: createFakeFirewall(),
    tokenCache: fakeTokenCache(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { messageId: "m1" });
  assert.equal(apiError.json.error, true);

  const invalid = await createFirewallGmailMessageTool({
    firewall: createFakeFirewall(),
    tokenCache: fakeTokenCache(),
  }).execute("1", {});
  assert.equal(invalid.json.error, true);
});

test("gmail_message_read decodes plain text, html, alternative, and mixed MIME", () => {
  assert.equal(decodeMessagePayload({ mimeType: "text/plain", body: { data: b64("plain") } }), "plain");
  assert.equal(decodeMessagePayload({ mimeType: "text/html", body: { data: b64("<p>html</p>") } }), "html");
  assert.equal(
    decodeMessagePayload({
      mimeType: "multipart/alternative",
      parts: [
        { mimeType: "text/plain", body: { data: b64("plain alt") } },
        { mimeType: "text/html", body: { data: b64("<p>html alt</p>") } },
      ],
    }),
    "plain alt",
  );
  assert.equal(
    decodeMessagePayload({
      mimeType: "multipart/mixed",
      parts: [
        { mimeType: "text/plain", body: { data: b64("text") } },
        { mimeType: "application/pdf", body: { data: b64("ignored") } },
      ],
    }),
    "text",
  );
});

test("gmail_message_read returns clear error for empty bodies and bypass detects API reads", async () => {
  const empty = await runMessage("BENIGN", { id: "m1", threadId: "t1", payload: { mimeType: "text/plain", body: {} } });
  assert.equal(empty.json.error, true);
  const pattern = EMAIL_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "gmail_message_read")!;
  assert.equal(pattern.detect("curl https://gmail.googleapis.com/gmail/v1/users/me/messages/m1").matched, true);
});

async function runMessage(prediction: "BENIGN" | "MALICIOUS", message: Record<string, unknown>) {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGmailMessageTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      tokenCache: fakeTokenCache(),
      fetchImpl: (async () => new Response(JSON.stringify(message), { status: 200 })) as typeof fetch,
    }).execute("1", { messageId: "m1" }),
  );
}

function plainMessage() {
  return {
    id: "m1",
    threadId: "t1",
    payload: {
      mimeType: "text/plain",
      headers: [{ name: "Subject", value: "Quarterly report" }],
      body: { data: b64("Revenue increased 12%.") },
    },
  };
}

function fakeTokenCache() {
  return { async get() { return { accessToken: "token", tokenType: "Bearer", expiresAt: Date.now() + 1000 }; } };
}

function b64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}
