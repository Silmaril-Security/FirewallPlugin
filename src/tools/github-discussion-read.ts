import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import { fetchGitHubGraphql, parseGitHubDiscussionUrl, validateGitHubPathPart, type WrapperContext } from "../core";
import {
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

export const FIREWALL_GITHUB_DISCUSSION_TOOL_NAME = "github_discussion_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    url: { type: "string" },
    owner: { type: "string" },
    repo: { type: "string" },
    discussionNumber: { type: "number", minimum: 1 },
    maxChars: { type: "number", minimum: 100 },
  },
} as const;

const DISCUSSION_QUERY = `
query FirewallDiscussion($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    discussion(number: $number) {
      number
      title
      bodyText
      url
      createdAt
      updatedAt
      author { login }
      answer { bodyText author { login } }
      comments(first: 50) {
        nodes {
          bodyText
          createdAt
          author { login }
        }
      }
    }
  }
}
`;

export function createFirewallGitHubDiscussionTool(options: GitHubToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GITHUB_DISCUSSION_TOOL_NAME,
    source: "github_discussion",
    markerKind: "GITHUB",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GITHUB_DISCUSSION_TOOL_NAME,
    label: "GitHub Discussion Read",
    description: "Read a GitHub discussion through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGitHubToolSafely(FIREWALL_GITHUB_DISCUSSION_TOOL_NAME, "github_discussion", options.logger, () =>
          runFirewallGitHubDiscussionRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGitHubDiscussionRead(input: {
  ctx: WrapperContext;
  options: GitHubToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const ref = readDiscussionRef(input.rawParams);
  const startedAt = Date.now();
  const data = await fetchGitHubGraphql<Record<string, unknown>>(
    DISCUSSION_QUERY,
    { owner: ref.owner, repo: ref.repo, number: ref.discussionNumber },
    {
      fetchImpl: input.options.fetchImpl,
      token: input.options.githubToken,
    },
  );
  const discussion = readRecord(readRecord(data.repository)?.discussion);
  if (!discussion) throw new Error("GitHub discussion not found");
  const htmlUrl =
    readOptionalString(discussion, "url") ||
    `https://github.com/${ref.owner}/${ref.repo}/discussions/${ref.discussionNumber}`;
  const comments = readArray(readRecord(discussion.comments)?.nodes);
  const contentText = renderDiscussion(ref, discussion, comments);

  return runInspectedGitHubTool({
    ctx: input.ctx,
    contentText,
    scanText: JSON.stringify({
      source: "openclaw",
      tool_name: FIREWALL_GITHUB_DISCUSSION_TOOL_NAME,
      owner: ref.owner,
      repo: ref.repo,
      discussion_number: ref.discussionNumber,
      title: readOptionalString(discussion, "title"),
      body: truncateForScan(readOptionalString(discussion, "bodyText")),
      comments: comments.map((comment) => ({
        author: readOptionalString(readRecord(comment.author), "login"),
        body: truncateForScan(readOptionalString(comment, "bodyText")),
      })),
    }),
    identityFields: {
      url: htmlUrl,
      owner: ref.owner,
      repo: ref.repo,
      discussionNumber: ref.discussionNumber,
      title: readOptionalString(discussion, "title"),
    },
    identityLines: [`repository: ${ref.owner}/${ref.repo}`, `discussion_number: ${ref.discussionNumber}`],
    contentNoun: "GitHub discussion content",
    urlForHash: htmlUrl,
    maxChars: readMaxChars(input.rawParams),
    tookMs: Date.now() - startedAt,
  });
}

function readDiscussionRef(params: Record<string, unknown>): { owner: string; repo: string; discussionNumber: number } {
  const url = readString(params.url, "url");
  if (url) {
    const parsed = parseGitHubDiscussionUrl(url);
    if (!parsed) throw new Error("url must be a GitHub discussion URL");
    return parsed;
  }
  return {
    owner: validateGitHubPathPart(readString(params.owner, "owner", true)!, "owner"),
    repo: validateGitHubPathPart(readString(params.repo, "repo", true)!, "repo"),
    discussionNumber: readPositiveInteger(params.discussionNumber, "discussionNumber", true)!,
  };
}

function renderDiscussion(
  ref: { owner: string; repo: string; discussionNumber: number },
  discussion: Record<string, unknown>,
  comments: Record<string, unknown>[],
): string {
  const answer = readRecord(discussion.answer);
  const parts = [
    `GitHub discussion: ${ref.owner}/${ref.repo}#${ref.discussionNumber}`,
    `URL: ${readOptionalString(discussion, "url")}`,
    `Title: ${readOptionalString(discussion, "title")}`,
    `Author: ${readOptionalString(readRecord(discussion.author), "login")}`,
    `Created: ${readOptionalString(discussion, "createdAt")}`,
    "",
    "Discussion body:",
    readOptionalString(discussion, "bodyText") || "(empty)",
  ];
  if (answer) {
    parts.push("", "Answer:", readOptionalString(answer, "bodyText") || "(empty)");
  }
  parts.push("", `Comments (${comments.length}):`);
  for (const comment of comments) {
    parts.push("", `Author: ${readOptionalString(readRecord(comment.author), "login")}`, readOptionalString(comment, "bodyText"));
  }
  return parts.join("\n");
}
