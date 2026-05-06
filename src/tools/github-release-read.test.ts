import assert from "node:assert/strict";
import test from "node:test";
import { GITHUB_BYPASS_PATTERNS } from "../bypass/github-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGitHubReleaseTool } from "./github-release-read";

test("github_release_read returns wrapped benign release", async () => {
  const result = await runRelease("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "github_release" });
});

test("github_release_read returns guarded malicious release", async () => {
  const result = await runRelease("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "github_release", markerKind: "GITHUB" });
});

test("github_release_read returns structured error for 404", async () => {
  const result = await createFirewallGitHubReleaseTool({
    firewall: createFakeFirewall(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { owner: "octocat", repo: "Hello-World", tag: "v1.0.0" });
  assert.equal(result.json.error, true);
});

test("github_release_read returns structured error for invalid params", async () => {
  const result = await createFirewallGitHubReleaseTool({ firewall: createFakeFirewall() }).execute("1", {
    owner: "octocat",
    repo: "Hello-World",
  });
  assert.equal(result.json.error, true);
});

test("github_release_read bypass pattern detects release reads but not repo views", () => {
  const pattern = GITHUB_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "github_release_read")!;
  assert.equal(pattern.detect("gh release view v1.0.0 --repo octocat/Hello-World").matched, true);
  assert.equal(pattern.detect("gh repo view octocat/Hello-World").matched, false);
});

test("github_release_read handles latest and empty body releases", async () => {
  const result = await runRelease("BENIGN", { body: "", latest: true });
  assert.equal(result.json.latest, true);
  assert.match(String(result.json.text), /\(empty\)/);
});

async function runRelease(
  prediction: "BENIGN" | "MALICIOUS",
  opts: { body?: string; latest?: boolean } = {},
) {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGitHubReleaseTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      fetchImpl: (async () =>
        new Response(
          JSON.stringify({
            tag_name: "v1.0.0",
            name: "Release v1",
            body: opts.body ?? "Release notes",
            html_url: "https://github.com/octocat/Hello-World/releases/tag/v1.0.0",
            author: { login: "octocat" },
            published_at: "2026-05-01T00:00:00Z",
          }),
          { status: 200 },
        )) as typeof fetch,
    }).execute("1", { owner: "octocat", repo: "Hello-World", tag: "v1.0.0", latest: opts.latest }),
  );
}
