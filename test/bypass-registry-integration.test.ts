import assert from "node:assert/strict";
import test from "node:test";
import plugin from "../index";

test("before_tool_call blocks GitHub issue shell bypass via registry", async () => {
  const hooks: Record<string, Array<(event: any, ctx: any) => unknown | Promise<unknown>>> = {};
  const api = {
    pluginConfig: {
      apiKey: "test-key",
      apiUrl: "https://firewall.example.invalid",
    },
    config: {},
    logger: {
      info() {},
      warn() {},
      error() {},
    },
    on(name: string, handler: (event: any, ctx: any) => unknown | Promise<unknown>) {
      hooks[name] ??= [];
      hooks[name].push(handler);
    },
    registerTool() {},
    registerWebFetchProvider() {},
  };

  plugin.register(api as any);

  const results = [];
  for (const handler of hooks.before_tool_call ?? []) {
    results.push(
      await handler(
        {
          toolName: "exec",
          params: {
            command: "gh issue view 1 --repo octocat/Hello-World",
          },
        },
        {},
      ),
    );
  }

  const block = results.find((result: any) => result?.block);
  assert.equal(block?.block, true);
  assert.match(block?.blockReason, /github_issue_read/);
});
