import assert from "node:assert/strict";
import test from "node:test";
import plugin from "../index";

test("full integration registers all wrappers and hooks when enabled", () => {
  const state = registerWithConfig({
    apiKey: "key",
    apiUrl: "https://api.example",
    enableWebFetchWrapper: true,
    githubToken: "github-token",
    google: { clientId: "client", clientSecret: "secret", refreshToken: "refresh" },
    enableGitHubWrappers: {
      issue: true,
      pr: true,
      prDiff: true,
      file: true,
      discussion: true,
      release: true,
    },
    enableGmailWrappers: {
      message: true,
      thread: true,
      search: true,
    },
  });

  for (const tool of [
    "firewall_report_false_positive",
    "web_fetch",
    "github_issue_read",
    "github_pr_read",
    "github_pr_diff_read",
    "github_file_read",
    "github_discussion_read",
    "github_release_read",
    "gmail_message_read",
    "gmail_thread_read",
    "gmail_search",
  ]) {
    assert.ok(state.tools.includes(tool), `missing ${tool}`);
  }
  assert.ok(state.providers.includes("silmaril-firewall"));
  for (const hook of [
    "before_tool_call",
    "message_sending",
    "before_message_write",
    "tool_result_persist",
    "before_prompt_build",
    "gateway_start",
    "gateway_stop",
  ]) {
    assert.ok(state.hooks.includes(hook), `missing hook ${hook}`);
  }
});

test("full integration with wrappers disabled registers only reporter and provider", () => {
  const state = registerWithConfig({
    apiKey: "key",
    apiUrl: "https://api.example",
    enableGitHubWrappers: {
      issue: false,
      pr: false,
      prDiff: false,
      file: false,
      discussion: false,
      release: false,
    },
    enableGmailWrappers: {
      message: false,
      thread: false,
      search: false,
    },
  });

  assert.deepEqual(state.tools, ["firewall_report_false_positive"]);
  assert.deepEqual(state.providers, ["silmaril-firewall"]);
});

function registerWithConfig(pluginConfig: Record<string, unknown>) {
  const tools: string[] = [];
  const providers: string[] = [];
  const hooks: string[] = [];
  const api = {
    pluginConfig,
    config: { tools: { web: { fetch: { enabled: false } } } },
    logger: {
      info() {},
      warn() {},
      error() {},
    },
    on(name: string) {
      hooks.push(name);
    },
    registerWebFetchProvider(provider: { id?: string }) {
      if (provider?.id) providers.push(provider.id);
    },
    registerTool(factoryOrTool: unknown, options?: { name?: string }) {
      if (options?.name) {
        tools.push(options.name);
      } else if (factoryOrTool && typeof factoryOrTool === "object" && "name" in factoryOrTool) {
        tools.push(String((factoryOrTool as { name: unknown }).name));
      }
    },
  };

  plugin.register(api as any);
  return { tools, providers, hooks };
}
