import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import { fetchGitHubText, parseGitHubPullRequestUrl, validateGitHubPathPart, type WrapperContext } from "../core";
import {
  apiBase,
  readMaxChars,
  readPositiveInteger,
  readString,
  runGitHubToolSafely,
  runInspectedGitHubTool,
  truncateForScan,
  type GitHubToolOptions,
} from "./github-common";

export const FIREWALL_GITHUB_PR_DIFF_TOOL_NAME = "github_pr_diff_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    url: { type: "string" },
    owner: { type: "string" },
    repo: { type: "string" },
    pullNumber: { type: "number", minimum: 1 },
    maxChars: { type: "number", minimum: 100 },
  },
} as const;

export function createFirewallGitHubPullRequestDiffTool(options: GitHubToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GITHUB_PR_DIFF_TOOL_NAME,
    source: "github_pr_diff",
    markerKind: "GITHUB",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GITHUB_PR_DIFF_TOOL_NAME,
    label: "GitHub Pull Request Diff Read",
    description: "Read a GitHub pull request diff through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGitHubToolSafely(FIREWALL_GITHUB_PR_DIFF_TOOL_NAME, "github_pr_diff", options.logger, () =>
          runFirewallGitHubPullRequestDiffRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGitHubPullRequestDiffRead(input: {
  ctx: WrapperContext;
  options: GitHubToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const ref = readPullRequestRef(input.rawParams);
  const startedAt = Date.now();
  const apiUrl = `${apiBase(ref.owner, ref.repo)}/pulls/${ref.pullNumber}`;
  const diff = await fetchGitHubText(apiUrl, {
    fetchImpl: input.options.fetchImpl,
    token: input.options.githubToken,
    acceptDiff: true,
  });
  const htmlUrl = `https://github.com/${ref.owner}/${ref.repo}/pull/${ref.pullNumber}.diff`;
  const contentText = [`GitHub pull request diff: ${ref.owner}/${ref.repo}#${ref.pullNumber}`, "", diff].join("\n");

  return runInspectedGitHubTool({
    ctx: input.ctx,
    contentText,
    scanText: JSON.stringify({
      source: "openclaw",
      tool_name: FIREWALL_GITHUB_PR_DIFF_TOOL_NAME,
      owner: ref.owner,
      repo: ref.repo,
      pull_number: ref.pullNumber,
      diff: truncateForScan(diff),
    }),
    identityFields: {
      url: htmlUrl,
      apiUrl,
      owner: ref.owner,
      repo: ref.repo,
      pullNumber: ref.pullNumber,
    },
    identityLines: [`repository: ${ref.owner}/${ref.repo}`, `pull_number: ${ref.pullNumber}`],
    contentNoun: "GitHub pull request diff content",
    urlForHash: htmlUrl,
    maxChars: readMaxChars(input.rawParams),
    tookMs: Date.now() - startedAt,
  });
}

function readPullRequestRef(params: Record<string, unknown>): { owner: string; repo: string; pullNumber: number } {
  const url = readString(params.url, "url");
  if (url) {
    const parsed = parseGitHubPullRequestUrl(url.replace(/\.diff$|\.patch$/i, ""));
    if (!parsed) throw new Error("url must be a GitHub pull request URL like https://github.com/owner/repo/pull/123");
    return parsed;
  }
  return {
    owner: validateGitHubPathPart(readString(params.owner, "owner", true)!, "owner"),
    repo: validateGitHubPathPart(readString(params.repo, "repo", true)!, "repo"),
    pullNumber: readPositiveInteger(params.pullNumber, "pullNumber", true)!,
  };
}
