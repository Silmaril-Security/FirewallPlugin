import assert from "node:assert/strict";
import test from "node:test";
import { GITHUB_BYPASS_PATTERNS } from "../bypass/github-patterns";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate } from "../core/__test__/test-helpers";
import { createFirewallGitHubFileTool } from "./github-file-read";

test("github_file_read returns wrapped benign file", async () => {
  const result = await runFile("BENIGN");
  expectBenignPayload(result.json as Record<string, unknown>, { source: "github_file" });
});

test("github_file_read returns guarded malicious file", async () => {
  const result = await runFile("MALICIOUS");
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "github_file", markerKind: "GITHUB" });
});

test("github_file_read returns structured error for 404", async () => {
  const result = await createFirewallGitHubFileTool({
    firewall: createFakeFirewall(),
    fetchImpl: (async () => new Response("missing", { status: 404 })) as typeof fetch,
  }).execute("1", { url: "https://github.com/octocat/Hello-World/blob/main/README.md" });
  assert.equal(result.json.error, true);
});

test("github_file_read returns structured error for invalid params", async () => {
  const result = await createFirewallGitHubFileTool({ firewall: createFakeFirewall() }).execute("1", {});
  assert.equal(result.json.error, true);
});

test("github_file_read bypass pattern detects raw file reads but not git log", () => {
  const pattern = GITHUB_BYPASS_PATTERNS.find((candidate) => candidate.toolName === "github_file_read")!;
  assert.equal(pattern.detect("curl https://raw.githubusercontent.com/octocat/Hello-World/main/README.md").matched, true);
  assert.equal(pattern.detect("git log --oneline").matched, false);
});

test("github_file_read handles branch refs and rejects binary files", async () => {
  const branchResult = await runFile("BENIGN", "hello", { ref: "dev" });
  assert.equal(branchResult.json.ref, "dev");
  const binaryResult = await runFile("BENIGN", "abc\u0000def");
  assert.equal(binaryResult.json.error, true);
});

async function runFile(
  prediction: "BENIGN" | "MALICIOUS",
  body = "Quarterly vendor report",
  params: Record<string, unknown> = {},
) {
  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    createFirewallGitHubFileTool({
      firewall: createFakeFirewall({ prediction, score: prediction === "MALICIOUS" ? 0.9 : 0.1 }),
      fetchImpl: (async () => new Response(body, { status: 200 })) as typeof fetch,
    }).execute("1", {
      owner: "octocat",
      repo: "Hello-World",
      path: "README.md",
      ...params,
    }),
  );
}
