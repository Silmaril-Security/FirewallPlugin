import assert from "node:assert/strict";
import test from "node:test";
import { wrapAndTruncate } from "./content-truncate";

test("wrapAndTruncate wraps short content without truncating", () => {
  const result = wrapAndTruncate({
    value: "hello",
    source: "web_fetch",
    maxChars: 1_000,
  });

  assert.equal(result.truncated, false);
  assert.match(result.text, /UNTRUSTED_WEB_CONTENT/);
  assert.match(result.text, /hello/);
});

test("wrapAndTruncate truncates long wrapped content", () => {
  const result = wrapAndTruncate({
    value: "x".repeat(1_000),
    source: "github_issue",
    maxChars: 50,
  });

  assert.equal(result.truncated, true);
  assert.equal(result.text.length, 50);
});
