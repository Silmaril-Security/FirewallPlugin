import assert from "node:assert/strict";
import test from "node:test";
import { GITHUB_BYPASS_PATTERNS } from "./github-patterns";

const issuePattern = GITHUB_BYPASS_PATTERNS[0]!;

test("GitHub issue bypass pattern detects direct issue reads", () => {
  for (const command of [
    "gh issue view 1 --repo octocat/Hello-World",
    "gh api repos/octocat/Hello-World/issues/1",
    "curl https://api.github.com/repos/octocat/Hello-World/issues/1",
    "curl https://github.com/octocat/Hello-World/issues/1",
  ]) {
    assert.equal(issuePattern.detect(command).matched, true, command);
  }
});

test("GitHub issue bypass pattern avoids unrelated GitHub commands", () => {
  for (const command of [
    "gh issue list --repo octocat/Hello-World",
    "gh repo view octocat/Hello-World",
    "git log --oneline",
    "gh pr list --repo octocat/Hello-World",
  ]) {
    assert.equal(issuePattern.detect(command).matched, false, command);
  }
});

test("GitHub issue bypass retry hint points to wrapper tool", () => {
  const result = issuePattern.detect("gh issue view 1 --repo octocat/Hello-World");
  assert.equal(result.matched, true);
  if (result.matched) {
    assert.match(issuePattern.buildRetryHint(result.details), /github_issue_read/);
  }
});
