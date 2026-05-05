import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import {
  fetchGitHubJson,
  fetchGitHubPaginated,
  parseGitHubPullRequestUrl,
  validateGitHubPathPart,
  type WrapperContext,
} from "../core";
import {
  apiBase,
  readArray,
  readMaxChars,
  readOptionalString,
  readPositiveInteger,
  readRecord,
  readString,
  runGitHubToolSafely,
  runInspectedGitHubTool,
  truncateForScan,
  type GitHubToolOptions,
} from "./github-common";

export const FIREWALL_GITHUB_PR_TOOL_NAME = "github_pr_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    url: { type: "string" },
    owner: { type: "string" },
    repo: { type: "string" },
    pullNumber: { type: "number", minimum: 1 },
    includeComments: { type: "boolean", default: true },
    maxChars: { type: "number", minimum: 100 },
  },
} as const;

export function createFirewallGitHubPullRequestTool(options: GitHubToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GITHUB_PR_TOOL_NAME,
    source: "github_pr",
    markerKind: "GITHUB",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GITHUB_PR_TOOL_NAME,
    label: "GitHub Pull Request Read",
    description: "Read a GitHub pull request through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGitHubToolSafely(FIREWALL_GITHUB_PR_TOOL_NAME, "github_pr", options.logger, () =>
          runFirewallGitHubPullRequestRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGitHubPullRequestRead(input: {
  ctx: WrapperContext;
  options: GitHubToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const ref = readPullRequestRef(input.rawParams);
  const startedAt = Date.now();
  const pull = readRecord(
    await fetchGitHubJson(`${apiBase(ref.owner, ref.repo)}/pulls/${ref.pullNumber}`, {
      fetchImpl: input.options.fetchImpl,
      token: input.options.githubToken,
    }),
  );
  if (!pull) throw new Error("GitHub pull request API returned an unexpected response");

  const includeComments = input.rawParams.includeComments !== false;
  const comments = includeComments
    ? await fetchGitHubPaginated(
        `${apiBase(ref.owner, ref.repo)}/issues/${ref.pullNumber}/comments?per_page=100`,
        (raw) => readRecord(raw) ?? {},
        {
          fetchImpl: input.options.fetchImpl,
          token: input.options.githubToken,
          maxPages: 5,
        },
      )
    : [];
  const contentText = renderPullRequest(ref, pull, comments, includeComments);
  const htmlUrl = readOptionalString(pull, "html_url") || `https://github.com/${ref.owner}/${ref.repo}/pull/${ref.pullNumber}`;

  return runInspectedGitHubTool({
    ctx: input.ctx,
    contentText,
    scanText: JSON.stringify({
      source: "openclaw",
      tool_name: FIREWALL_GITHUB_PR_TOOL_NAME,
      owner: ref.owner,
      repo: ref.repo,
      pull_number: ref.pullNumber,
      title: readOptionalString(pull, "title"),
      body: truncateForScan(readOptionalString(pull, "body")),
      comments: comments.map((comment) => ({
        id: comment.id,
        body: truncateForScan(readOptionalString(comment, "body")),
        author: readOptionalString(readRecord(comment.user), "login"),
      })),
    }),
    identityFields: {
      url: htmlUrl,
      apiUrl: `${apiBase(ref.owner, ref.repo)}/pulls/${ref.pullNumber}`,
      owner: ref.owner,
      repo: ref.repo,
      pullNumber: ref.pullNumber,
      title: readOptionalString(pull, "title"),
      state: readOptionalString(pull, "state"),
    },
    identityLines: [`repository: ${ref.owner}/${ref.repo}`, `pull_number: ${ref.pullNumber}`],
    contentNoun: "GitHub pull request content",
    urlForHash: htmlUrl,
    maxChars: readMaxChars(input.rawParams),
    tookMs: Date.now() - startedAt,
    falsePositiveReviewStore: input.options.falsePositiveReviewStore,
  });
}

function readPullRequestRef(params: Record<string, unknown>): { owner: string; repo: string; pullNumber: number } {
  const url = readString(params.url, "url");
  if (url) {
    const parsed = parseGitHubPullRequestUrl(url);
    if (!parsed) throw new Error("url must be a GitHub pull request URL like https://github.com/owner/repo/pull/123");
    return parsed;
  }
  return {
    owner: validateGitHubPathPart(readString(params.owner, "owner", true)!, "owner"),
    repo: validateGitHubPathPart(readString(params.repo, "repo", true)!, "repo"),
    pullNumber: readPositiveInteger(params.pullNumber, "pullNumber", true)!,
  };
}

function renderPullRequest(
  ref: { owner: string; repo: string; pullNumber: number },
  pull: Record<string, unknown>,
  comments: Record<string, unknown>[],
  includeComments: boolean,
): string {
  const parts = [
    `GitHub pull request: ${ref.owner}/${ref.repo}#${ref.pullNumber}`,
    `URL: ${readOptionalString(pull, "html_url")}`,
    `Title: ${readOptionalString(pull, "title")}`,
    `State: ${readOptionalString(pull, "state")}`,
    `Author: ${readOptionalString(readRecord(pull.user), "login")}`,
    `Created: ${readOptionalString(pull, "created_at")}`,
    `Updated: ${readOptionalString(pull, "updated_at")}`,
    "",
    "Pull request body:",
    readOptionalString(pull, "body") || "(empty)",
  ];
  if (includeComments) {
    parts.push("", `Comments (${comments.length}):`);
    for (const comment of comments) {
      parts.push("", `Comment ${comment.id ?? ""}`, readOptionalString(comment, "body") || "(empty)");
    }
  }
  const requestedReviewers = readArray(pull.requested_reviewers);
  if (requestedReviewers.length) {
    parts.push("", `Requested reviewers: ${requestedReviewers.map((reviewer) => readOptionalString(reviewer, "login")).join(", ")}`);
  }
  return parts.join("\n");
}
