import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createFirewallGitHubIssueTool } from "../src/tools/github-issue-read";
import { createFirewallWebFetchTool } from "../src/tools/web-fetch";
import { withFixedDate, withGlobalFetch } from "../src/core/__test__/test-helpers";

const FIXED_NOW = "2026-05-03T00:00:00.000Z";

test("web_fetch benign payload matches baseline", async () => {
  const actual = await runWebFetchBaseline("BENIGN");
  assert.equal(actual, readBaseline("web-fetch-benign"));
});

test("web_fetch malicious payload matches baseline", async () => {
  const actual = await runWebFetchBaseline("MALICIOUS");
  assert.equal(actual, readBaseline("web-fetch-malicious"));
});

test("github_issue_read benign payload matches baseline", async () => {
  const actual = await runGitHubIssueBaseline("BENIGN");
  assert.equal(actual, readBaseline("github-issue-benign"));
});

test("github_issue_read malicious payload matches baseline", async () => {
  const actual = await runGitHubIssueBaseline("MALICIOUS");
  assert.equal(actual, readBaseline("github-issue-malicious"));
});

async function runWebFetchBaseline(prediction: "BENIGN" | "MALICIOUS"): Promise<string> {
  return withFixedDate(FIXED_NOW, () =>
    withGlobalFetch(createBaselineWebFetch(), async () =>
      JSON.stringify(
        await createFirewallWebFetchTool({
          firewall: createBaselineFirewall(prediction),
          fetchConfig: { maxChars: 20_000 },
        }).execute("baseline", { url: "https://example.com/report?token=secret" }),
        null,
        2,
      ) + "\n",
    ),
  );
}

async function runGitHubIssueBaseline(prediction: "BENIGN" | "MALICIOUS"): Promise<string> {
  return withFixedDate(FIXED_NOW, async () =>
    JSON.stringify(
      await createFirewallGitHubIssueTool({
        firewall: createBaselineFirewall(prediction),
        fetchImpl: createBaselineGitHubFetch(),
      }).execute("baseline", { url: "https://github.com/octocat/Hello-World/issues/1" }),
      null,
      2,
    ) + "\n",
  );
}

function readBaseline(name: string): string {
  return readFileSync(new URL(`./fixtures/baseline/${name}.txt`, import.meta.url), "utf8");
}

function createBaselineFirewall(prediction: "BENIGN" | "MALICIOUS") {
  return {
    async classify() {
      return {
        prediction,
        score: prediction === "MALICIOUS" ? 0.91 : 0.12,
      };
    },
  };
}

function createBaselineWebFetch(): typeof fetch {
  return (async () =>
    new Response(
      "<!doctype html><title>Quarterly report</title><h1>Quarterly vendor report</h1><p>Revenue increased 12%.</p>",
      {
        status: 200,
        headers: { "content-type": "text/html" },
      },
    )) as typeof fetch;
}

function createBaselineGitHubFetch(): typeof fetch {
  return (async (url: string | URL | Request) => {
    const urlText = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    if (urlText.endsWith("/comments?per_page=100")) {
      return new Response(
        JSON.stringify([
          {
            id: 10,
            body: "Looks good.",
            user: { login: "hubot" },
            created_at: "2026-05-01T00:00:00Z",
            updated_at: "2026-05-01T00:00:00Z",
          },
        ]),
        { status: 200 },
      );
    }

    return new Response(
      JSON.stringify({
        number: 1,
        title: "Quarterly issue",
        body: "Please review the report.",
        state: "open",
        html_url: "https://github.com/octocat/Hello-World/issues/1",
        user: { login: "octocat" },
        created_at: "2026-05-01T00:00:00Z",
        updated_at: "2026-05-02T00:00:00Z",
      }),
      { status: 200 },
    );
  }) as typeof fetch;
}
