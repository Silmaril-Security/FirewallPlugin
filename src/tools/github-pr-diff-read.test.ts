import assert from "node:assert/strict";
import test from "node:test";
import { GITHUB_BYPASS_PATTERNS } from "../bypass/github-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGitHubPullRequestDiffTool } from "./github-pr-diff-read";

test("github_pr_diff_read returns wrapped benign diff", async () => {
  const result = await runDiff("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "github_pr_diff" });
});

test("github_pr_diff_read returns guarded malicious diff", async () => {
  const result = await runDiff("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "github_pr_diff", markerKind: "GITHUB" });
});

test("github_pr_diff_read returns structured error for 404", async () => {
  const result = await createFirewallGitHubPullRequestDiffTool({
    firewall: createFakeFirewall(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { url: "https://github.com/octocat/Hello-World/pull/42" });
  assert.equal(result.json.error, true);
});

test("github_pr_diff_read returns structured error for invalid params", async () => {
  const result = await createFirewallGitHubPullRequestDiffTool({ firewall: createFakeFirewall() }).execute("1", {});
  assert.equal(result.json.error, true);
});

test("github_pr_diff_read bypass pattern detects direct diff reads but not PR status", () => {
  const pattern = GITHUB_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "github_pr_diff_read")!;
  assert.equal(pattern.detect("gh pr diff 42 --repo octocat/Hello-World").matched, true);
  assert.equal(pattern.detect("gh pr status --repo octocat/Hello-World").matched, false);
});

test("github_pr_diff_read renders multi-file diffs", async () => {
  const result = await runDiff("BENIGN", "diff --git a/a.ts b/a.ts\n+one\ndiff --git a/b.ts b/b.ts\n+two");
  assert.match(String(result.json.text), /b\.ts/);
});

async function runDiff(prediction: "BENIGN" | "MALICIOUS", diff = "diff --git a/report.md b/report.md\n+Revenue increased") {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGitHubPullRequestDiffTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      fetchImpl: (async () => new Response(diff, { status: 200 })) as typeof fetch,
    }).execute("1", { url: "https://github.com/octocat/Hello-World/pull/42" }),
  );
}
