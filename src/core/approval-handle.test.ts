import assert from "node:assert/strict";
import test from "node:test";

import { buildApprovalHandle } from "./approval-handle";
import type { SourceLabel } from "./types";

const SOURCES: SourceLabel[] = [
  "web_fetch",
  "github_issue",
  "github_pr",
  "github_pr_diff",
  "github_file",
  "github_discussion",
  "github_release",
  "gmail_message",
  "gmail_thread",
  "gmail_search",
];

test("buildApprovalHandle uses source with dashes and a 16-character hash", () => {
  const contentHash = "abcdef1234567890ffffffffffffffffffffffffffffffffffffffffffffffff";

  for (const source of SOURCES) {
    const handle = buildApprovalHandle(source, contentHash);
    assert.equal(handle, `silmaril-${source.replace(/_/g, "-")}-abcdef1234567890`);
    assert.match(handle, /^silmaril-[a-z-]+-[0-9a-f]{16}$/);
  }
});
