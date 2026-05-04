import assert from "node:assert/strict";
import test from "node:test";
import { HookLabel } from "@silmaril-security/sdk";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "./__test__/test-helpers";
import { buildBenignPayload, buildGuardedPayload } from "./guarded-payload";
import type { WrapperContext } from "./types";

const ctx: WrapperContext = {
  toolName: "github_issue_read",
  source: "github_issue",
  markerKind: "GITHUB",
  firewall: createFakeFirewall(),
};

test("buildGuardedPayload creates blocked approval payload", () => {
  const payload = withFixedDate("2026-05-03T00:00:00.000Z", () =>
    buildGuardedPayload({
      ctx,
      contentText: "issue body",
      contentHash: "a".repeat(64),
      urlHash: "b".repeat(64),
      contentNoun: "GitHub issue content",
      identityFields: {
        owner: "octocat",
        repo: "Hello-World",
        issueNumber: 1,
      },
      identityLines: ["repository: octocat/Hello-World", "issue_number: 1"],
      firewallResult: { prediction: "MALICIOUS", score: 0.9 },
      hook: HookLabel.TOOL_RESPONSE,
      tookMs: 0,
    }),
  );

  expectGuardedPayload(payload, { source: "github_issue", markerKind: "GITHUB" });
  assert.equal(payload.owner, "octocat");
  assert.equal(payload.fetchedAt, "2026-05-03T00:00:00.000Z");
});

test("buildBenignPayload creates inspected content payload", () => {
  const payload = withFixedDate("2026-05-03T00:00:00.000Z", () =>
    buildBenignPayload({
      ctx,
      text: "wrapped issue body",
      rawLength: 10,
      contentHash: "a".repeat(64),
      urlHash: "b".repeat(64),
      identityFields: {
        owner: "octocat",
        repo: "Hello-World",
      },
      firewallResult: { prediction: "BENIGN", score: 0.1 },
      hook: HookLabel.TOOL_RESPONSE,
      tookMs: 0,
      truncated: false,
    }),
  );

  expectBenignPayload(payload, { source: "github_issue", minLength: 10 });
  assert.equal(payload.fetchedAt, "2026-05-03T00:00:00.000Z");
});
