import assert from "node:assert/strict";
import test from "node:test";
import { GITHUB_BYPASS_PATTERNS } from "../bypass/github-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGitHubDiscussionTool } from "./github-discussion-read";

test("github_discussion_read returns wrapped benign discussion", async () => {
  const result = await runDiscussion("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "github_discussion" });
});

test("github_discussion_read returns guarded malicious discussion", async () => {
  const result = await runDiscussion("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "github_discussion", markerKind: "GITHUB" });
});

test("github_discussion_read returns structured error for GraphQL errors", async () => {
  const result = await createFirewallGitHubDiscussionTool({
    firewall: createFakeFirewall(),
    fetchImpl: (async () => new Response(JSON.stringify({ errors: [{ message: "nope" }] }), { status: 200 })) as typeof fetch,
  }).execute("1", { owner: "octocat", repo: "Hello-World", discussionNumber: 7 });
  assert.equal(result.json.error, true);
});

test("github_discussion_read returns structured error for invalid params", async () => {
  const result = await createFirewallGitHubDiscussionTool({ firewall: createFakeFirewall() }).execute("1", {});
  assert.equal(result.json.error, true);
});

test("github_discussion_read bypass pattern detects discussion reads but not issue lists", () => {
  const pattern = GITHUB_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "github_discussion_read")!;
  assert.equal(pattern.detect("gh discussion view 7 --repo octocat/Hello-World").matched, true);
  assert.equal(pattern.detect("gh issue list --repo octocat/Hello-World").matched, false);
});

test("github_discussion_read handles answers, comments, and not found", async () => {
  const result = await runDiscussion("BENIGN");
  assert.match(String(result.json.text), /Answer:/);
  assert.match(String(result.json.text), /Comments \(1\)/);
  const missing = await createFirewallGitHubDiscussionTool({
    firewall: createFakeFirewall(),
    fetchImpl: (async () => new Response(JSON.stringify({ data: { repository: { discussion: null } } }), { status: 200 })) as typeof fetch,
  }).execute("1", { owner: "octocat", repo: "Hello-World", discussionNumber: 7 });
  assert.equal(missing.json.error, true);
});

async function runDiscussion(prediction: "BENIGN" | "MALICIOUS") {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGitHubDiscussionTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      fetchImpl: (async () =>
        new Response(
          JSON.stringify({
            data: {
              repository: {
                discussion: {
                  number: 7,
                  title: "Quarterly discussion",
                  bodyText: "Discussion body",
                  url: "https://github.com/octocat/Hello-World/discussions/7",
                  createdAt: "2026-05-01T00:00:00Z",
                  author: { login: "octocat" },
                  answer: { bodyText: "Accepted answer", author: { login: "hubot" } },
                  comments: {
                    nodes: [{ bodyText: "One comment", author: { login: "hubot" } }],
                  },
                },
              },
            },
          }),
          { status: 200 },
        )) as typeof fetch,
    }).execute("1", { owner: "octocat", repo: "Hello-World", discussionNumber: 7 }),
  );
}
