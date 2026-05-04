import assert from "node:assert/strict";
import test from "node:test";
import { EMAIL_BYPASS_PATTERNS } from "./email-patterns";
import type { BypassPattern } from "./types";

test("EMAIL_BYPASS_PATTERNS is typed and covers Gmail wrappers", () => {
  const patterns: readonly BypassPattern[] = EMAIL_BYPASS_PATTERNS;
  assert.equal(patterns.length, 3);
  assert.equal(patterns.some((pattern) => pattern.toolName === "gmail_message_read"), true);
  assert.equal(patterns.some((pattern) => pattern.toolName === "gmail_thread_read"), true);
  assert.equal(patterns.some((pattern) => pattern.toolName === "gmail_search"), true);
});

test("EMAIL_BYPASS_PATTERNS detects Gmail API reads and avoids unrelated commands", () => {
  const message = EMAIL_BYPASS_PATTERNS.find((pattern) => pattern.toolName === "gmail_message_read")!;
  const thread = EMAIL_BYPASS_PATTERNS.find((pattern) => pattern.toolName === "gmail_thread_read")!;
  const search = EMAIL_BYPASS_PATTERNS.find((pattern) => pattern.toolName === "gmail_search")!;

  assert.equal(message.detect("curl https://gmail.googleapis.com/gmail/v1/users/me/messages/abc").matched, true);
  assert.equal(thread.detect("curl https://gmail.googleapis.com/gmail/v1/users/me/threads/thr").matched, true);
  assert.equal(search.detect("curl https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from%3Aa").matched, true);
  assert.equal(message.detect("echo hello").matched, false);
});
