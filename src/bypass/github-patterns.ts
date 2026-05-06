import { FIREWALL_GITHUB_ISSUE_TOOL_NAME, parseGitHubIssueReferenceFromUrl } from "../tools/github-issue-read";
import { FIREWALL_GITHUB_DISCUSSION_TOOL_NAME } from "../tools/github-discussion-read";
import { FIREWALL_GITHUB_FILE_TOOL_NAME } from "../tools/github-file-read";
import { FIREWALL_GITHUB_PR_DIFF_TOOL_NAME } from "../tools/github-pr-diff-read";
import { FIREWALL_GITHUB_PR_TOOL_NAME } from "../tools/github-pr-read";
import { FIREWALL_GITHUB_RELEASE_TOOL_NAME } from "../tools/github-release-read";
import type { BypassPattern } from "./types";

export const GITHUB_BYPASS_PATTERNS: readonly BypassPattern[] = [
  {
    toolName: FIREWALL_GITHUB_ISSUE_TOOL_NAME,
    label: "GitHub issue direct read",
    detect(command) {
      const details = detectGitHubIssueRead(command);
      return details ? { matched: true, details } : { matched: false };
    },
    buildRetryHint(details) {
      return buildGitHubIssueRetryHint(details);
    },
  },
  createGitHubNumberPattern({
    toolName: FIREWALL_GITHUB_PR_TOOL_NAME,
    label: "GitHub pull request direct read",
    kind: "pull request",
    requiredTool: FIREWALL_GITHUB_PR_TOOL_NAME,
    regexes: [
      /\bgh\s+pr\s+view\s+(\d+)\b[\s\S]*?\s--repo\s+([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i,
      /\bgh\s+api\s+repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/pulls\/(\d+)(?:\b|\/)/i,
      /https:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/pulls\/(\d+)(?:\b|[/?#])/i,
      /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/pull\/(\d+)(?:\b|[/?#])/i,
    ],
  }),
  createGitHubNumberPattern({
    toolName: FIREWALL_GITHUB_PR_DIFF_TOOL_NAME,
    label: "GitHub pull request diff direct read",
    kind: "GitHub pull request diff",
    requiredTool: FIREWALL_GITHUB_PR_DIFF_TOOL_NAME,
    regexes: [
      /\bgh\s+pr\s+diff\s+(\d+)\b[\s\S]*?\s--repo\s+([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i,
      /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/pull\/(\d+)\.(?:diff|patch)(?:\b|[/?#])/i,
      /https:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/pulls\/(\d+)\.(?:diff|patch)(?:\b|[/?#])/i,
    ],
  }),
  {
    toolName: FIREWALL_GITHUB_FILE_TOOL_NAME,
    label: "GitHub file direct read",
    detect(command) {
      const details = detectGitHubFileRead(command);
      return details ? { matched: true, details } : { matched: false };
    },
    buildRetryHint(details) {
      return buildGenericRetryHint("GitHub file", FIREWALL_GITHUB_FILE_TOOL_NAME, details);
    },
  },
  {
    toolName: FIREWALL_GITHUB_RELEASE_TOOL_NAME,
    label: "GitHub release direct read",
    detect(command) {
      const details = detectGitHubReleaseRead(command);
      return details ? { matched: true, details } : { matched: false };
    },
    buildRetryHint(details) {
      return buildGenericRetryHint("GitHub release", FIREWALL_GITHUB_RELEASE_TOOL_NAME, details);
    },
  },
  createGitHubNumberPattern({
    toolName: FIREWALL_GITHUB_DISCUSSION_TOOL_NAME,
    label: "GitHub discussion direct read",
    kind: "GitHub discussion",
    requiredTool: FIREWALL_GITHUB_DISCUSSION_TOOL_NAME,
    regexes: [
      /\bgh\s+discussion\s+view\s+(\d+)\b[\s\S]*?\s--repo\s+([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i,
      /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/discussions\/(\d+)(?:\b|[/?#])/i,
      /\bgh\s+api\s+graphql\b[\s\S]*?\bdiscussion\b[\s\S]*?(?:number:\s*(\d+)|discussion\s*\(\s*number:\s*(\d+))/i,
    ],
  }),
];

function detectGitHubIssueRead(command: string): Record<string, unknown> | undefined {
  const githubUrl = /https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/issues\/\d+/i.exec(command)?.[0];
  if (githubUrl) {
    const ref = parseGitHubIssueReferenceFromUrl(githubUrl);
    if (ref) {
      return {
        owner: ref.owner,
        repo: ref.repo,
        issueNumber: ref.issueNumber,
        url: ref.htmlUrl,
      };
    }
  }

  const ghIssueView = /\bgh\s+issue\s+view\s+(\d+)\b[\s\S]*?\s--repo\s+([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i.exec(command);
  if (ghIssueView?.[1] && ghIssueView[2] && ghIssueView[3]) {
    return {
      owner: ghIssueView[2],
      repo: ghIssueView[3],
      issueNumber: Number(ghIssueView[1]),
    };
  }

  const ghApiIssue = /\bgh\s+api\s+repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/issues\/(\d+)(?:\b|\/)/i.exec(command);
  if (ghApiIssue?.[1] && ghApiIssue[2] && ghApiIssue[3]) {
    return {
      owner: ghApiIssue[1],
      repo: ghApiIssue[2],
      issueNumber: Number(ghApiIssue[3]),
    };
  }

  const apiCurlIssue = /https:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/issues\/(\d+)(?:\b|[/?#])/i.exec(command);
  if (apiCurlIssue?.[1] && apiCurlIssue[2] && apiCurlIssue[3]) {
    return {
      owner: apiCurlIssue[1],
      repo: apiCurlIssue[2],
      issueNumber: Number(apiCurlIssue[3]),
    };
  }

  return undefined;
}

function buildGitHubIssueRetryHint(details: Record<string, unknown>): string {
  const repo =
    typeof details.owner === "string" && typeof details.repo === "string"
      ? `${details.owner}/${details.repo}`
      : "unknown";
  const issueNumber = typeof details.issueNumber === "number" ? details.issueNumber : "unknown";

  return `
GitHub issue reads must go through the Silmaril GitHub issue wrapper before the issue body or comments reach the model.
source: before_tool_call
required_tool: ${FIREWALL_GITHUB_ISSUE_TOOL_NAME}
repository: ${repo}
issue_number: ${issueNumber}

Retry by calling ${FIREWALL_GITHUB_ISSUE_TOOL_NAME} with the GitHub issue URL, owner/repo/issue number, or equivalent structured parameters.
Do not use gh issue view, gh api, curl, wget, shell commands, generic GitHub tools, or raw browser fetches to read GitHub issue content.
`.trim();
}

function createGitHubNumberPattern(params: {
  toolName: string;
  label: string;
  kind: string;
  requiredTool: string;
  regexes: readonly RegExp[];
}): BypassPattern {
  return {
    toolName: params.toolName,
    label: params.label,
    detect(command) {
      for (const regex of params.regexes) {
        const match = regex.exec(command);
        if (!match) continue;
        const values = match.slice(1).filter(Boolean);
        if (values.length >= 3 && /^\d+$/.test(values[0]!)) {
          return {
            matched: true,
            details: {
              number: Number(values[0]),
              owner: values[1],
              repo: values[2],
            },
          };
        }
        if (values.length >= 3 && /^\d+$/.test(values[2]!)) {
          return {
            matched: true,
            details: {
              owner: values[0],
              repo: values[1],
              number: Number(values[2]),
            },
          };
        }
        if (values.length >= 1 && /^\d+$/.test(values[0]!)) {
          return {
            matched: true,
            details: {
              number: Number(values[0]),
            },
          };
        }
      }
      return { matched: false };
    },
    buildRetryHint(details) {
      return buildGenericRetryHint(params.kind, params.requiredTool, details);
    },
  };
}

function detectGitHubFileRead(command: string): Record<string, unknown> | undefined {
  const raw = /https:\/\/raw\.githubusercontent\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/([^/\s]+)\/([^\s'"]+)/i.exec(command);
  if (raw?.[1] && raw[2] && raw[3] && raw[4]) {
    return { owner: raw[1], repo: raw[2], ref: raw[3], path: raw[4] };
  }
  const blob = /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/blob\/([^/\s]+)\/([^\s'"]+)/i.exec(command);
  if (blob?.[1] && blob[2] && blob[3] && blob[4]) {
    return { owner: blob[1], repo: blob[2], ref: blob[3], path: blob[4] };
  }
  const contents = /\bgh\s+api\s+repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/contents\/([^\s'"]+)/i.exec(command);
  if (contents?.[1] && contents[2] && contents[3]) {
    return { owner: contents[1], repo: contents[2], path: contents[3] };
  }
  return undefined;
}

function detectGitHubReleaseRead(command: string): Record<string, unknown> | undefined {
  const gh = /\bgh\s+release\s+view(?:\s+([^\s]+))?\b[\s\S]*?\s--repo\s+([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i.exec(command);
  if (gh?.[2] && gh[3]) {
    return { owner: gh[2], repo: gh[3], tag: gh[1] ?? "latest" };
  }
  const api = /https:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/releases(?:\/(?:tags\/([^/?#\s]+)|latest))?/i.exec(command);
  if (api?.[1] && api[2]) {
    return { owner: api[1], repo: api[2], tag: api[3] ?? "latest" };
  }
  const web = /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/releases\/(?:tag\/([^/?#\s]+)|latest)/i.exec(command);
  if (web?.[1] && web[2]) {
    return { owner: web[1], repo: web[2], tag: web[3] ?? "latest" };
  }
  return undefined;
}

function buildGenericRetryHint(kind: string, requiredTool: string, details: Record<string, unknown>): string {
  const repo =
    typeof details.owner === "string" && typeof details.repo === "string"
      ? `${details.owner}/${details.repo}`
      : "unknown";
  return `
${kind} reads must go through the Silmaril ${requiredTool} wrapper before external content reaches the model.
source: before_tool_call
required_tool: ${requiredTool}
repository: ${repo}

Retry by calling ${requiredTool} with the equivalent structured parameters.
Do not use gh, curl, wget, shell commands, generic GitHub tools, or raw browser fetches to read this GitHub content.
`.trim();
}
