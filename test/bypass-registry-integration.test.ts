import assert from "node:assert/strict";
import test from "node:test";
import { Firewall } from "@silmaril-security/sdk";
import plugin from "../index";

test("before_tool_call blocks GitHub issue shell bypass via registry", async () => {
  const { hooks } = registerForBypassTest({
    apiKey: "test-key",
    apiUrl: "https://firewall.example.invalid",
  });

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

test("before_tool_call only blocks bypasses for wrapper tools registered in this OpenClaw session", async () => {
  const originalClassify = Firewall.prototype.classify;
  Firewall.prototype.classify = async () => ({ prediction: "BENIGN", score: 0 }) as any;
  try {
    const disabled = registerForBypassTest({
      apiKey: "test-key",
      apiUrl: "https://firewall.example.invalid",
      enableGitHubWrappers: {
        issue: false,
        pr: false,
        prDiff: false,
        file: false,
        discussion: false,
        release: false,
      },
    });

    assert.equal(disabled.tools.includes("github_pr_read"), false);
    const disabledResults = await runBeforeToolCall(disabled.hooks, {
      toolName: "exec",
      params: {
        command: "gh pr view 42 --repo octocat/Hello-World",
      },
    });
    assert.equal(disabledResults.some((result: any) => result?.blockReason?.includes("github_pr_read")), false);

    const enabled = registerForBypassTest({
      apiKey: "test-key",
      apiUrl: "https://firewall.example.invalid",
      enableGitHubWrappers: {
        pr: true,
      },
    });

    assert.equal(enabled.tools.includes("github_pr_read"), true);
    const enabledResults = await runBeforeToolCall(enabled.hooks, {
      toolName: "exec",
      params: {
        command: "gh pr view 42 --repo octocat/Hello-World",
      },
    });
    assert.equal(enabledResults.some((result: any) => result?.blockReason?.includes("github_pr_read")), true);
  } finally {
    Firewall.prototype.classify = originalClassify;
  }
});

test("before_tool_call does not block Gmail bypasses when Gmail wrappers were not registered", async () => {
  const originalClassify = Firewall.prototype.classify;
  Firewall.prototype.classify = async () => ({ prediction: "BENIGN", score: 0 }) as any;
  try {
    const state = registerForBypassTest({
      apiKey: "test-key",
      apiUrl: "https://firewall.example.invalid",
      enableGmailWrappers: {
        message: true,
        thread: true,
        search: true,
      },
    });

    assert.equal(state.tools.includes("gmail_message_read"), false);
    const results = await runBeforeToolCall(state.hooks, {
      toolName: "exec",
      params: {
        command: "curl https://gmail.googleapis.com/gmail/v1/users/me/messages/abc123",
      },
    });

    assert.equal(results.some((result: any) => result?.blockReason?.includes("gmail_message_read")), false);
  } finally {
    Firewall.prototype.classify = originalClassify;
  }
});

test("before_tool_call waits for async wrapper registration before activating bypass targets", async () => {
  const originalClassify = Firewall.prototype.classify;
  Firewall.prototype.classify = async () => ({ prediction: "BENIGN", score: 0 }) as any;
  try {
    let resolvePrRegistration: (() => void) | undefined;
    const state = registerForBypassTest(
      {
        apiKey: "test-key",
        apiUrl: "https://firewall.example.invalid",
        enableGitHubWrappers: {
          pr: true,
        },
      },
      {
        registerTool(_factoryOrTool, options) {
          if (options?.name === "github_pr_read") {
            return new Promise<void>((resolve) => {
              resolvePrRegistration = resolve;
            });
          }
          return undefined;
        },
      },
    );

    const event = {
      toolName: "exec",
      params: {
        command: "gh pr view 42 --repo octocat/Hello-World",
      },
    };

    const beforeRegistration = await runBeforeToolCall(state.hooks, event);
    assert.equal(beforeRegistration.some((result: any) => result?.blockReason?.includes("github_pr_read")), false);

    resolvePrRegistration?.();
    await Promise.resolve();

    const afterRegistration = await runBeforeToolCall(state.hooks, event);
    assert.equal(afterRegistration.some((result: any) => result?.blockReason?.includes("github_pr_read")), true);
  } finally {
    Firewall.prototype.classify = originalClassify;
  }
});

function registerForBypassTest(
  pluginConfig: Record<string, unknown>,
  overrides: {
    registerTool?: (_factoryOrTool: unknown, options?: { name?: string }) => unknown;
  } = {},
) {
  const hooks: Record<string, Array<(event: any, ctx: any) => unknown | Promise<unknown>>> = {};
  const tools: string[] = [];
  const api = {
    pluginConfig,
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
    registerTool(_factoryOrTool: unknown, options?: { name?: string }) {
      if (options?.name) tools.push(options.name);
      return overrides.registerTool?.(_factoryOrTool, options);
    },
    registerWebFetchProvider() {},
  };

  plugin.register(api as any);
  return { hooks, tools };
}

async function runBeforeToolCall(
  hooks: Record<string, Array<(event: any, ctx: any) => unknown | Promise<unknown>>>,
  event: any,
) {
  const results = [];
  for (const handler of hooks.before_tool_call ?? []) {
    results.push(await handler(event, {}));
  }
  return results;
}
