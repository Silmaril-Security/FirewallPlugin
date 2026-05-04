import { jsonResult } from "openclaw/plugin-sdk/provider-web-fetch";
import { fetchGitHubText, parseGitHubFileUrl, validateGitHubPathPart, type WrapperContext } from "../core";
import {
  apiBase,
  encodePathSegments,
  readMaxChars,
  readString,
  runGitHubToolSafely,
  runInspectedGitHubTool,
  truncateForScan,
  type GitHubToolOptions,
} from "./github-common";

export const FIREWALL_GITHUB_FILE_TOOL_NAME = "github_file_read" as const;

const PARAMETERS = {
  type: "object",
  additionalProperties: false,
  properties: {
    url: { type: "string" },
    owner: { type: "string" },
    repo: { type: "string" },
    path: { type: "string" },
    ref: { type: "string" },
    maxChars: { type: "number", minimum: 100 },
  },
} as const;

export function createFirewallGitHubFileTool(options: GitHubToolOptions) {
  const ctx: WrapperContext = {
    toolName: FIREWALL_GITHUB_FILE_TOOL_NAME,
    source: "github_file",
    markerKind: "GITHUB",
    firewall: options.firewall,
    logger: options.logger,
  };
  return {
    name: FIREWALL_GITHUB_FILE_TOOL_NAME,
    label: "GitHub File Read",
    description: "Read a GitHub repository file through Silmaril firewall inspection.",
    parameters: PARAMETERS,
    async execute(_toolCallId: string, rawParams: Record<string, unknown>) {
      return jsonResult(
        await runGitHubToolSafely(FIREWALL_GITHUB_FILE_TOOL_NAME, "github_file", options.logger, () =>
          runFirewallGitHubFileRead({ ctx, options, rawParams }),
        ),
      );
    },
  };
}

export async function runFirewallGitHubFileRead(input: {
  ctx: WrapperContext;
  options: GitHubToolOptions;
  rawParams: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const ref = readFileRef(input.rawParams);
  const startedAt = Date.now();
  const apiUrl = `${apiBase(ref.owner, ref.repo)}/contents/${encodePathSegments(ref.path)}?ref=${encodeURIComponent(ref.ref)}`;
  const fileText = await fetchGitHubText(apiUrl, {
    fetchImpl: input.options.fetchImpl,
    token: input.options.githubToken,
    acceptRaw: true,
  });
  if (looksBinary(fileText)) {
    throw new Error("GitHub file appears to be binary; only text files can be inspected");
  }
  const htmlUrl = `https://github.com/${ref.owner}/${ref.repo}/blob/${encodeURIComponent(ref.ref)}/${ref.path}`;
  const contentText = [`GitHub file: ${ref.owner}/${ref.repo}/${ref.path}@${ref.ref}`, "", fileText].join("\n");

  return runInspectedGitHubTool({
    ctx: input.ctx,
    contentText,
    scanText: JSON.stringify({
      source: "openclaw",
      tool_name: FIREWALL_GITHUB_FILE_TOOL_NAME,
      owner: ref.owner,
      repo: ref.repo,
      path: ref.path,
      ref: ref.ref,
      file_text: truncateForScan(fileText),
    }),
    identityFields: {
      url: htmlUrl,
      apiUrl,
      owner: ref.owner,
      repo: ref.repo,
      path: ref.path,
      ref: ref.ref,
    },
    identityLines: [`repository: ${ref.owner}/${ref.repo}`, `path: ${ref.path}`, `ref: ${ref.ref}`],
    contentNoun: "GitHub file content",
    urlForHash: htmlUrl,
    maxChars: readMaxChars(input.rawParams),
    tookMs: Date.now() - startedAt,
  });
}

function readFileRef(params: Record<string, unknown>): { owner: string; repo: string; path: string; ref: string } {
  const url = readString(params.url, "url");
  if (url) {
    const parsed = parseGitHubFileUrl(url);
    if (!parsed) throw new Error("url must be a GitHub file URL like https://github.com/owner/repo/blob/main/path");
    return parsed;
  }
  return {
    owner: validateGitHubPathPart(readString(params.owner, "owner", true)!, "owner"),
    repo: validateGitHubPathPart(readString(params.repo, "repo", true)!, "repo"),
    path: readString(params.path, "path", true)!,
    ref: readString(params.ref, "ref") ?? "main",
  };
}

function looksBinary(value: string): boolean {
  return value.includes("\u0000");
}
