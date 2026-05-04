#!/usr/bin/env node
import { createFirewallGitHubIssueTool } from "../src/tools/github-issue-read.ts";

const [owner = "octocat", repo = "Hello-World", issueNumberText = "1"] = process.argv.slice(2);
const issueNumber = Number(issueNumberText);

if (!Number.isSafeInteger(issueNumber) || issueNumber <= 0) {
  throw new Error("Usage: node --import tsx scripts/manual-github-smoke.mjs [owner] [repo] [issueNumber]");
}

const firewall = {
  async classify(text, options) {
    return {
      prediction: "BENIGN",
      score: 0.01,
      smoke: true,
      inspectedChars: text.length,
      hook: options?.hook,
      toolName: options?.toolName,
    };
  },
};

const logger = {
  info: (message) => console.log(message),
  warn: (message) => console.warn(message),
  error: (message) => console.error(message),
};

const tool = createFirewallGitHubIssueTool({
  firewall,
  logger,
  githubToken: process.env.GITHUB_TOKEN,
});

const result = await tool.execute("manual-github-smoke", {
  owner,
  repo,
  issueNumber,
  includeComments: false,
  maxChars: 4000,
});

const payload = result?.json;
if (!payload || payload?.firewall?.prediction !== "BENIGN" || typeof payload.text !== "string") {
  console.error(JSON.stringify(result, null, 2));
  throw new Error("github_issue_read smoke failed: expected benign JSON payload with text");
}

console.log(JSON.stringify({
  tool: tool.name,
  repository: `${payload.owner}/${payload.repo}`,
  issueNumber: payload.issueNumber,
  title: payload.title,
  state: payload.state,
  prediction: payload.firewall.prediction,
  score: payload.firewall.score,
  textPreview: payload.text.slice(0, 240),
}, null, 2));
