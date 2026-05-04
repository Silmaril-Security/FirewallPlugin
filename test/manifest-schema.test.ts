import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("openclaw manifest includes config schema and ui hints for wrapper config", () => {
  const manifest = JSON.parse(readFileSync(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
  const properties = manifest.configSchema.properties;
  const uiHints = manifest.uiHints;

  for (const key of [
    "apiKey",
    "silmarilApiKey",
    "userEmail",
    "apiUrl",
    "falsePositiveReportUrl",
    "enableWebFetchWrapper",
    "llmFalsePositiveReviewThreshold",
    "githubToken",
    "google",
    "enableGitHubWrappers",
    "enableGmailWrappers",
  ]) {
    assert.ok(properties[key], `missing schema for ${key}`);
    assert.ok(uiHints[key], `missing ui hint for ${key}`);
  }

  assert.equal(uiHints.apiKey.sensitive, true);
  assert.equal(uiHints.silmarilApiKey.sensitive, true);
  assert.equal(uiHints.githubToken.sensitive, true);
  assert.equal(uiHints["google.clientSecret"].sensitive, true);
  assert.equal(uiHints["google.refreshToken"].sensitive, true);
  assert.equal(properties.enableGitHubWrappers.properties.issue.default, true);
  assert.equal(properties.enableGitHubWrappers.properties.pr.default, false);
  assert.equal(properties.enableGmailWrappers.properties.message.default, false);
});

test("openclaw manifest advertises all planned wrapper tools", () => {
  const manifest = JSON.parse(readFileSync(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
  for (const tool of [
    "web_fetch",
    "github_issue_read",
    "github_pr_read",
    "github_pr_diff_read",
    "github_file_read",
    "github_discussion_read",
    "github_release_read",
    "gmail_message_read",
    "gmail_thread_read",
    "gmail_search",
    "firewall_report_false_positive",
  ]) {
    assert.ok(manifest.contracts.tools.includes(tool), `missing tool contract ${tool}`);
  }
});
