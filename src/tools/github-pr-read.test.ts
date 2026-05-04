import assert from "node:assert/strict";
import test from "node:test";
import { GITHUB_BYPASS_PATTERNS } from "../bypass/github-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGitHubPullRequestTool } from "./github-pr-read";

test("github_pr_read returns wrapped benign content", async () => {
  const result = await runPr("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "github_pr" });
});

test("github_pr_read returns guarded malicious content", async () => {
  const result = await runPr("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "github_pr", markerKind: "GITHUB" });
});

test("github_pr_read returns structured error for 404", async () => {
  const result = await createFirewallGitHubPullRequestTool({
    firewall: createFakeFirewall(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { url: "https://github.com/octocat/Hello-World/pull/42" });
  assert.equal(result.json.error, true);
});

test("github_pr_read returns structured error for invalid params", async () => {
  const result = await createFirewallGitHubPullRequestTool({ firewall: createFakeFirewall() }).execute("1", {});
  assert.equal(result.json.error, true);
});

test("github_pr_read bypass pattern detects direct PR reads but not PR lists", () => {
  const pattern = GITHUB_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "github_pr_read")!;
  assert.equal(pattern.detect("gh pr view 42 --repo octocat/Hello-World").matched, true);
  assert.equal(pattern.detect("gh pr list --repo octocat/Hello-World").matched, false);
});

test("github_pr_read handles PR with no body and many comments", async () => {
  const result = await runPr("BENIGN", { body: null, commentCount: 51 });
  assert.match(String(result.json.text), /Comments \(51\)/);
});

async function runPr(prediction: "BENIGN" | "MALICIOUS", opts: { body?: string | null; commentCount?: number } = {}) {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGitHubPullRequestTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      fetchImpl: createPrFetch(opts),
    }).execute("1", { url: "https://github.com/octocat/Hello-World/pull/42" }),
  );
}

function createPrFetch(opts: { body?: string | null; commentCount?: number }): typeof fetch {
  return (async (url: string | URL | Request) => {
    const text = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    if (text.includes("/issues/42/comments")) {
      return new Response(
        JSON.stringify(
          Array.from({ length: opts.commentCount ?? 1 }, (_, index) => ({
            id: index + 1,
            body: `comment ${index + 1}`,
            user: { login: "reviewer" },
          })),
        ),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        number: 42,
        title: "Improve report",
        body: opts.body === undefined ? "Pull request body" : opts.body,
        state: "open",
        html_url: "https://github.com/octocat/Hello-World/pull/42",
        user: { login: "octocat" },
      }),
      { status: 200 },
    );
  }) as typeof fetch;
}
