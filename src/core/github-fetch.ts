export type GitHubFetchInit = {
  fetchImpl?: typeof fetch;
  token?: string;
  acceptDiff?: boolean;
  acceptRaw?: boolean;
  signal?: AbortSignal;
};

export type GitHubIssueRef = {
  owner: string;
  repo: string;
  issueNumber: number;
};

export type GitHubPullRequestRef = {
  owner: string;
  repo: string;
  pullNumber: number;
};

export type GitHubFileRef = {
  owner: string;
  repo: string;
  ref: string;
  path: string;
};

export type GitHubDiscussionRef = {
  owner: string;
  repo: string;
  discussionNumber: number;
};

export type GitHubReleaseRef = {
  owner: string;
  repo: string;
  tag?: string;
  latest?: boolean;
};

export async function fetchGitHubJson(url: string, init: GitHubFetchInit = {}): Promise<unknown> {
  const response = await fetchGitHub(url, init);
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GitHub API request failed (${response.status}): ${truncate(text, 500)}`);
  }

  return JSON.parse(text);
}

export async function fetchGitHubText(url: string, init: GitHubFetchInit = {}): Promise<string> {
  const response = await fetchGitHub(url, init);
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GitHub API request failed (${response.status}): ${truncate(text, 500)}`);
  }

  return text;
}

export async function fetchGitHubPaginated<T>(
  url: string,
  mapFn: (raw: unknown) => T,
  opts: GitHubFetchInit & { maxPages?: number } = {},
): Promise<T[]> {
  const results: T[] = [];
  let nextUrl: string | undefined = url;
  let pages = 0;
  const maxPages = opts.maxPages ?? 10;

  while (nextUrl && pages < maxPages) {
    pages += 1;
    const response = await fetchGitHub(nextUrl, opts);
    const text = await response.text();

    if (!response.ok) {
      throw new Error(`GitHub API request failed (${response.status}): ${truncate(text, 500)}`);
    }

    const raw = JSON.parse(text);
    if (Array.isArray(raw)) {
      results.push(...raw.map(mapFn));
    } else {
      results.push(mapFn(raw));
    }
    nextUrl = parseNextLink(response.headers.get("link"));
  }

  return results;
}

export async function fetchGitHubGraphql<T>(
  query: string,
  variables: object,
  init: GitHubFetchInit = {},
): Promise<T> {
  const fetchImpl = init.fetchImpl ?? fetch;
  const response = await fetchImpl("https://api.github.com/graphql", {
    method: "POST",
    headers: buildGitHubHeaders(init),
    body: JSON.stringify({ query, variables }),
    signal: init.signal,
  });
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GitHub GraphQL request failed (${response.status}): ${truncate(text, 500)}`);
  }

  const raw = JSON.parse(text) as { data?: T; errors?: unknown };
  if (Array.isArray(raw.errors) && raw.errors.length > 0) {
    throw new Error(`GitHub GraphQL errors: ${JSON.stringify(raw.errors)}`);
  }
  if (raw.data === undefined) {
    throw new Error("GitHub GraphQL response missing data");
  }
  return raw.data;
}

export function validateGitHubPathPart(value: string, label: string): string {
  const trimmed = value.trim();
  if (
    !trimmed ||
    trimmed.includes("..") ||
    /[\\/]/.test(trimmed) ||
    /[\u0000-\u001f\u007f]/.test(trimmed) ||
    !/^[A-Za-z0-9_.-]+$/.test(trimmed)
  ) {
    throw new Error(`invalid GitHub ${label}`);
  }
  return trimmed;
}

export function parseGitHubIssueUrl(value: string): GitHubIssueRef | undefined {
  const parts = parseGitHubPath(value);
  if (!parts || parts.kind !== "issues") return undefined;
  const issueNumber = parsePositiveInteger(parts.number);
  if (!issueNumber) return undefined;
  return {
    owner: parts.owner,
    repo: parts.repo,
    issueNumber,
  };
}

export function parseGitHubPullRequestUrl(value: string): GitHubPullRequestRef | undefined {
  const parts = parseGitHubPath(value);
  if (!parts || parts.kind !== "pull") return undefined;
  const pullNumber = parsePositiveInteger(parts.number);
  if (!pullNumber) return undefined;
  return {
    owner: parts.owner,
    repo: parts.repo,
    pullNumber,
  };
}

export function parseGitHubFileUrl(value: string): GitHubFileRef | undefined {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return undefined;
  }

  if (parsed.hostname.toLowerCase() !== "github.com") return undefined;
  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 5 || parts[2] !== "blob") return undefined;

  try {
    return {
      owner: validateGitHubPathPart(parts[0] ?? "", "owner"),
      repo: validateGitHubPathPart(parts[1] ?? "", "repo"),
      ref: parts[3] ?? "",
      path: parts.slice(4).join("/"),
    };
  } catch {
    return undefined;
  }
}

export function parseGitHubDiscussionUrl(value: string): GitHubDiscussionRef | undefined {
  const parts = parseGitHubPath(value);
  if (!parts || parts.kind !== "discussions") return undefined;
  const discussionNumber = parsePositiveInteger(parts.number);
  if (!discussionNumber) return undefined;
  return {
    owner: parts.owner,
    repo: parts.repo,
    discussionNumber,
  };
}

export function parseGitHubReleaseUrl(value: string): GitHubReleaseRef | undefined {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return undefined;
  }

  if (parsed.hostname.toLowerCase() !== "github.com") return undefined;
  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 4 || parts[2] !== "releases") return undefined;

  try {
    const owner = validateGitHubPathPart(parts[0] ?? "", "owner");
    const repo = validateGitHubPathPart(parts[1] ?? "", "repo");
    if (parts[3] === "latest") {
      return { owner, repo, latest: true };
    }
    if (parts[3] === "tag" && parts[4]) {
      return { owner, repo, tag: decodeURIComponent(parts.slice(4).join("/")) };
    }
  } catch {
    return undefined;
  }

  return undefined;
}

function fetchGitHub(url: string, init: GitHubFetchInit): Promise<Response> {
  const fetchImpl = init.fetchImpl ?? fetch;
  return fetchImpl(url, {
    headers: buildGitHubHeaders(init),
    signal: init.signal,
  });
}

function buildGitHubHeaders(init: GitHubFetchInit): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: init.acceptDiff
      ? "application/vnd.github.v3.diff"
      : init.acceptRaw
        ? "application/vnd.github.v3.raw"
        : "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "silmaril-openclaw-firewall-plugin",
  };
  if (init.token) {
    headers.Authorization = `Bearer ${init.token}`;
  }
  return headers;
}

function parseNextLink(link: string | null): string | undefined {
  if (!link) return undefined;
  for (const part of link.split(",")) {
    const match = /<([^>]+)>;\s*rel="next"/.exec(part.trim());
    if (match?.[1]) return match[1];
  }
  return undefined;
}

function parseGitHubPath(value: string):
  | {
      owner: string;
      repo: string;
      kind: string;
      number: string | undefined;
    }
  | undefined {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return undefined;
  }

  if (parsed.hostname.toLowerCase() !== "github.com") return undefined;
  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 4) return undefined;

  try {
    return {
      owner: validateGitHubPathPart(parts[0] ?? "", "owner"),
      repo: validateGitHubPathPart(parts[1] ?? "", "repo"),
      kind: parts[2] ?? "",
      number: parts[3],
    };
  } catch {
    return undefined;
  }
}

function parsePositiveInteger(value: string | undefined): number | undefined {
  if (!value || !/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function truncate(value: string, maxChars: number): string {
  return value.length > maxChars ? `${value.slice(0, maxChars)}...` : value;
}
