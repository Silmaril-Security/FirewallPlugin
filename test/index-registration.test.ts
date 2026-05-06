import assert from "node:assert/strict";
import test from "node:test";
import plugin from "../index";

test("index registers github_issue_read by default and gates it off explicitly", () => {
  assert.ok(registeredToolNames({ apiKey: "key", apiUrl: "https://api.example" }).includes("github_issue_read"));
  assert.equal(
    registeredToolNames({
      apiKey: "key",
      apiUrl: "https://api.example",
      enableGitHubWrappers: { issue: false },
    }).includes("github_issue_read"),
    false,
  );
});

test("index registers GitHub wrappers when individually enabled", () => {
  const names = registeredToolNames({
    apiKey: "key",
    apiUrl: "https://api.example",
    enableGitHubWrappers: {
      pr: true,
      prDiff: true,
      file: true,
      discussion: true,
      release: true,
    },
  });

  assert.equal(names.includes("github_pr_read"), true);
  assert.equal(names.includes("github_pr_diff_read"), true);
  assert.equal(names.includes("github_file_read"), true);
  assert.equal(names.includes("github_discussion_read"), true);
  assert.equal(names.includes("github_release_read"), true);
});

test("index registers Gmail wrappers only with complete Google config", () => {
  const missingGoogleWarnings: string[] = [];
  const missingNames = registeredToolNames(
    {
      apiKey: "key",
      apiUrl: "https://api.example",
      enableGmailWrappers: { message: true, thread: true, search: true },
    },
    missingGoogleWarnings,
  );
  assert.equal(missingNames.includes("gmail_message_read"), false);
  assert.equal(missingGoogleWarnings.some((message) => message.includes("google.* not configured")), true);

  const names = registeredToolNames({
    apiKey: "key",
    apiUrl: "https://api.example",
    google: { clientId: "client", clientSecret: "secret", refreshToken: "refresh" },
    enableGmailWrappers: { message: true, thread: true, search: true },
  });
  assert.equal(names.includes("gmail_message_read"), true);
  assert.equal(names.includes("gmail_thread_read"), true);
  assert.equal(names.includes("gmail_search"), true);
});

function registeredToolNames(pluginConfig: Record<string, unknown>, warnings: string[] = []): string[] {
  const names: string[] = [];
  const api = {
    pluginConfig,
    config: {},
    logger: {
      info() {},
      warn(message: string) {
        warnings.push(message);
      },
      error() {},
    },
    on() {},
    registerWebFetchProvider() {},
    registerTool(factoryOrTool: unknown, options?: { name?: string }) {
      if (options?.name) {
        names.push(options.name);
        return;
      }
      if (typeof factoryOrTool === "function") {
        const tool = (factoryOrTool as () => { name?: string })();
        if (tool?.name) names.push(tool.name);
      } else if (factoryOrTool && typeof factoryOrTool === "object" && "name" in factoryOrTool) {
        names.push(String((factoryOrTool as { name: unknown }).name));
      }
    },
  };

  plugin.register(api as any);
  return names;
}
