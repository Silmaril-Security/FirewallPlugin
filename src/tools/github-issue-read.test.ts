import assert from "node:assert/strict";
import test from "node:test";
import {
  createFakeFirewall,
  expectBenignPayload,
  expectGuardedPayload,
  withFixedDate,
} from "../core/__test__/test-helpers";
import {
  buildGitHubIssueReadBypassBlockReason,
  createFirewallGitHubIssueTool,
  isGitHubIssueReadBypass,
} from "./github-issue-read";

test("github_issue_read returns wrapped benign content", async () => {
  const result = await runIssue({ prediction: "BENIGN" });
  expectBenignPayload(result.json as Record<string, unknown>, { source: "github_issue" });
});

test("github_issue_read returns guarded malicious content", async () => {
  const result = await runIssue({ prediction: "MALICIOUS" });
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "github_issue", markerKind: "GITHUB" });
});

test("github_issue_read includes LLM review marker and registers false-positive candidate", async () => {
  const candidates: Record<string, unknown>[] = [];
  const result = await runIssue({
    prediction: "MALICIOUS",
    falsePositiveReviewStore: {
      threshold: 0.6,
      registerCandidate(candidate) {
        candidates.push(candidate as unknown as Record<string, unknown>);
      },
      handleMessageSending() {
        return undefined;
      },
    },
  });

  const payload = result.json as Record<string, unknown>;
  assert.equal(payload.firewall.llmReviewRequired, true);
  assert.equal(payload.firewall.llmReviewThreshold, 0.6);
  assert.match(String(payload.text), /<<<SILMARIL_FIREWALL_LLM_REVIEW>>>/);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].source, "github_issue");
  assert.equal(candidates[0].approvalHandle, payload.firewall.approvalHandle);
  assert.match(String((candidates[0].firewallInput as any).text), /Please review the report/);
});

test("github_issue_read returns structured error for 404", async () => {
  const fetchImpl = (async () => new Response("missing", { status: 404, statusText: "Not Found" })) as typeof fetch;
  const result = await createFirewallGitHubIssueTool({
    firewall: createFakeFirewall(),
    fetchImpl,
  }).execute("1", { url: "https://github.com/octocat/Hello-World/issues/1" });

  assert.equal(result.json.error, true);
  assert.equal(result.json.firewall.inspected, false);
});

test("github_issue_read returns structured error for invalid params", async () => {
  const result = await createFirewallGitHubIssueTool({ firewall: createFakeFirewall() }).execute("1", {
    url: "https://github.com/octocat/Hello-World/pull/1",
  });

  assert.equal(result.json.error, true);
  assert.match(String(result.json.message), /GitHub issue URL/);
});

test("github_issue_read bypass detection blocks direct shell issue reads", () => {
  assert.equal(
    isGitHubIssueReadBypass("exec", { command: "gh issue view 1 --repo octocat/Hello-World" }),
    true,
  );
  assert.equal(isGitHubIssueReadBypass("exec", { command: "gh issue list --repo octocat/Hello-World" }), false);
  assert.match(buildGitHubIssueReadBypassBlockReason({ toolName: "exec", timestamp: "now" }), /github_issue_read/);
});

async function runIssue(params: {
  prediction: "BENIGN" | "MALICIOUS";
  falsePositiveReviewStore?: Parameters<typeof createFirewallGitHubIssueTool>[0]["falsePositiveReviewStore"];
}) {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGitHubIssueTool({
      firewall: createFakeFirewall({
        prediction: params.prediction,
        score: params.prediction === "MALICIOUS" ? 0.9 : 0.1,
      }),
      fetchImpl: createIssueFetch(),
      falsePositiveReviewStore: params.falsePositiveReviewStore,
    }).execute("1", { url: "https://github.com/octocat/Hello-World/issues/1" }),
  );
}

function createIssueFetch(): typeof fetch {
  return (async (url: string | URL | Request) => {
    const urlText = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    if (urlText.endsWith("/comments?per_page=100")) {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    return new Response(
      JSON.stringify({
        number: 1,
        title: "Quarterly issue",
        body: "Please review the report.",
        state: "open",
        html_url: "https://github.com/octocat/Hello-World/issues/1",
        user: { login: "octocat" },
        created_at: "2026-05-01T00:00:00Z",
        updated_at: "2026-05-02T00:00:00Z",
      }),
      { status: 200 },
    );
  }) as typeof fetch;
}
