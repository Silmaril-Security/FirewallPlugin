import assert from "node:assert/strict";
import test from "node:test";

import {
  fetchGitHubGraphql,
  fetchGitHubJson,
  fetchGitHubPaginated,
  fetchGitHubText,
  parseGitHubDiscussionUrl,
  parseGitHubFileUrl,
  parseGitHubIssueUrl,
  parseGitHubPullRequestUrl,
  parseGitHubReleaseUrl,
  validateGitHubPathPart,
} from "./github-fetch";

test("fetchGitHubJson sends standard headers and optional auth", async () => {
  const calls: RequestInit[] = [];
  const result = await fetchGitHubJson("https://api.github.com/repos/o/r/issues/1", {
    token: "secret-token",
    fetchImpl: async (_url, init) => {
      calls.push(init ?? {});
      return jsonResponse({ ok: true });
    },
  });

  assert.deepEqual(result, { ok: true });
  assert.deepEqual(calls[0]?.headers, {
    Accept: "application/vnd.github+json",
    Authorization: "Bearer secret-token",
    "User-Agent": "silmaril-openclaw-firewall-plugin",
    "X-GitHub-Api-Version": "2022-11-28",
  });
});

test("fetchGitHubText sends diff accept header", async () => {
  let headers: HeadersInit | undefined;
  const result = await fetchGitHubText("https://api.github.com/repos/o/r/pulls/1", {
    acceptDiff: true,
    fetchImpl: async (_url, init) => {
      headers = init?.headers;
      return textResponse("diff --git");
    },
  });

  assert.equal(result, "diff --git");
  assert.equal((headers as Record<string, string>).Accept, "application/vnd.github.v3.diff");
});

test("fetchGitHubPaginated follows next links and respects maxPages", async () => {
  const urls: string[] = [];
  const results = await fetchGitHubPaginated(
    "https://api.github.com/items?page=1",
    (raw) => (raw as { id: number }).id,
    {
      maxPages: 2,
      fetchImpl: async (url) => {
        urls.push(String(url));
        if (String(url).endsWith("page=1")) {
          return jsonResponse([{ id: 1 }], {
            Link: '<https://api.github.com/items?page=2>; rel="next"',
          });
        }
        return jsonResponse([{ id: 2 }], {
          Link: '<https://api.github.com/items?page=3>; rel="next"',
        });
      },
    },
  );

  assert.deepEqual(urls, ["https://api.github.com/items?page=1", "https://api.github.com/items?page=2"]);
  assert.deepEqual(results, [1, 2]);
});

test("fetchGitHubGraphql posts query and variables and returns data", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const data = await fetchGitHubGraphql<{ viewer: { login: string } }>(
    "query($owner:String!){ viewer { login } }",
    { owner: "octocat" },
    {
      token: "token",
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init: init ?? {} });
        return jsonResponse({ data: { viewer: { login: "octocat" } } });
      },
    },
  );

  assert.deepEqual(data, { viewer: { login: "octocat" } });
  assert.equal(calls[0]?.url, "https://api.github.com/graphql");
  assert.equal(calls[0]?.init.method, "POST");
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), {
    query: "query($owner:String!){ viewer { login } }",
    variables: { owner: "octocat" },
  });
});

test("fetchGitHubGraphql throws on GraphQL errors", async () => {
  await assert.rejects(
    fetchGitHubGraphql("query", {}, {
      fetchImpl: async () => jsonResponse({ errors: [{ message: "bad query" }] }),
    }),
    /bad query/,
  );
});

test("GitHub URL parsers accept valid URLs", () => {
  assert.deepEqual(parseGitHubIssueUrl("https://github.com/owner/repo/issues/123"), {
    owner: "owner",
    repo: "repo",
    issueNumber: 123,
  });
  assert.deepEqual(parseGitHubPullRequestUrl("https://github.com/owner/repo/pull/42"), {
    owner: "owner",
    repo: "repo",
    pullNumber: 42,
  });
  assert.deepEqual(parseGitHubFileUrl("https://github.com/owner/repo/blob/main/src/index.ts"), {
    owner: "owner",
    repo: "repo",
    ref: "main",
    path: "src/index.ts",
  });
  assert.deepEqual(parseGitHubDiscussionUrl("https://github.com/owner/repo/discussions/7"), {
    owner: "owner",
    repo: "repo",
    discussionNumber: 7,
  });
  assert.deepEqual(parseGitHubReleaseUrl("https://github.com/owner/repo/releases/latest"), {
    owner: "owner",
    repo: "repo",
    latest: true,
  });
  assert.deepEqual(parseGitHubReleaseUrl("https://github.com/owner/repo/releases/tag/v1.2.3"), {
    owner: "owner",
    repo: "repo",
    tag: "v1.2.3",
  });
});

test("GitHub URL parsers reject invalid URLs", () => {
  for (const value of [
    "not a url",
    "https://example.com/owner/repo/issues/1",
    "https://github.com/owner/repo/issues/not-number",
    "https://github.com/owner/repo/pulls/1",
    "https://github.com/owner/repo/blob",
    "https://github.com/owner/repo/releases",
  ]) {
    assert.equal(parseGitHubIssueUrl(value), undefined);
    assert.equal(parseGitHubPullRequestUrl(value), undefined);
    assert.equal(parseGitHubFileUrl(value), undefined);
    assert.equal(parseGitHubDiscussionUrl(value), undefined);
    assert.equal(parseGitHubReleaseUrl(value), undefined);
  }
});

test("validateGitHubPathPart rejects dangerous path parts", () => {
  assert.equal(validateGitHubPathPart("octo-cat_1.repo", "owner"), "octo-cat_1.repo");
  for (const value of ["", "..", "owner/repo", "owner\\repo", "bad\u0000value", "white space"]) {
    assert.throws(() => validateGitHubPathPart(value, "owner"), /invalid GitHub owner/);
  }
});

function jsonResponse(value: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function textResponse(value: string, status = 200): Response {
  return new Response(value, { status });
}
