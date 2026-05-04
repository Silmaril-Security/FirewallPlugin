import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import { fetchGitHubJson, parseGitHubReleaseUrl, validateGitHubPathPart, type WrapperContext } from "../core";
import {
  apiBase,
  readMaxChars,
  readOptionalString,
  readRecord,
  readString,
  runGitHubToolSafely,
  runInspectedGitHubTool,
  truncateForScan,
  type GitHubToolOptions,
} from "./github-common";

export const FIREWALL_GITHUB_RELEASE_TOOL_NAME = "github_release_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    url: { type: "string" },
    owner: { type: "string" },
    repo: { type: "string" },
    tag: { type: "string" },
    latest: { type: "boolean", default: false },
    maxChars: { type: "number", minimum: 100 },
  },
} as const;

export function createFirewallGitHubReleaseTool(options: GitHubToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GITHUB_RELEASE_TOOL_NAME,
    source: "github_release",
    markerKind: "GITHUB",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GITHUB_RELEASE_TOOL_NAME,
    label: "GitHub Release Read",
    description: "Read a GitHub release through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGitHubToolSafely(FIREWALL_GITHUB_RELEASE_TOOL_NAME, "github_release", options.logger, () =>
          runFirewallGitHubReleaseRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGitHubReleaseRead(input: {
  ctx: WrapperContext;
  options: GitHubToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const ref = readReleaseRef(input.rawParams);
  const startedAt = Date.now();
  const apiUrl = ref.latest
    ? `${apiBase(ref.owner, ref.repo)}/releases/latest`
    : `${apiBase(ref.owner, ref.repo)}/releases/tags/${encodeURIComponent(ref.tag!)}`;
  const release = readRecord(
    await fetchGitHubJson(apiUrl, {
      fetchImpl: input.options.fetchImpl,
      token: input.options.githubToken,
    }),
  );
  if (!release) throw new Error("GitHub release API returned an unexpected response");
  const htmlUrl = readOptionalString(release, "html_url") || `https://github.com/${ref.owner}/${ref.repo}/releases`;
  const contentText = renderRelease(ref, release);

  return runInspectedGitHubTool({
    ctx: input.ctx,
    contentText,
    scanText: JSON.stringify({
      source: "openclaw",
      tool_name: FIREWALL_GITHUB_RELEASE_TOOL_NAME,
      owner: ref.owner,
      repo: ref.repo,
      tag: readOptionalString(release, "tag_name") || ref.tag,
      name: readOptionalString(release, "name"),
      body: truncateForScan(readOptionalString(release, "body")),
    }),
    identityFields: {
      url: htmlUrl,
      apiUrl,
      owner: ref.owner,
      repo: ref.repo,
      tag: readOptionalString(release, "tag_name") || ref.tag,
      latest: !!ref.latest,
      title: readOptionalString(release, "name"),
    },
    identityLines: [
      `repository: ${ref.owner}/${ref.repo}`,
      `release: ${ref.latest ? "latest" : ref.tag}`,
    ],
    contentNoun: "GitHub release content",
    urlForHash: htmlUrl,
    maxChars: readMaxChars(input.rawParams),
    tookMs: Date.now() - startedAt,
  });
}

function readReleaseRef(params: Record<string, unknown>): { owner: string; repo: string; tag?: string; latest?: boolean } {
  const url = readString(params.url, "url");
  if (url) {
    const parsed = parseGitHubReleaseUrl(url);
    if (!parsed) throw new Error("url must be a GitHub release URL");
    return parsed;
  }
  const latest = params.latest === true;
  const tag = readString(params.tag, "tag", !latest);
  return {
    owner: validateGitHubPathPart(readString(params.owner, "owner", true)!, "owner"),
    repo: validateGitHubPathPart(readString(params.repo, "repo", true)!, "repo"),
    latest,
    tag,
  };
}

function renderRelease(
  ref: { owner: string; repo: string; tag?: string; latest?: boolean },
  release: Record<string, unknown>,
): string {
  return [
    `GitHub release: ${ref.owner}/${ref.repo} ${readOptionalString(release, "tag_name") || ref.tag || "latest"}`,
    `URL: ${readOptionalString(release, "html_url")}`,
    `Name: ${readOptionalString(release, "name") || "(empty)"}`,
    `Author: ${readOptionalString(readRecord(release.author), "login")}`,
    `Published: ${readOptionalString(release, "published_at")}`,
    "",
    "Release notes:",
    readOptionalString(release, "body") || "(empty)",
  ].join("\n");
}
