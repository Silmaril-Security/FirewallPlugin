import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdir, rm, readFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL, fileURLToPath } from "node:url";
import { build } from "esbuild";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, ".unit-test-build");
const outFile = path.join(outDir, "index-under-test.mjs");

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

await build({
  entryPoints: [path.join(repoRoot, "index.ts")],
  outfile: outFile,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  plugins: [{
    name: "unit-test-stubs",
    setup(buildApi) {
      buildApi.onResolve({ filter: /^openclaw\/plugin-sdk\/plugin-entry$/ }, (args) => ({
        path: args.path,
        namespace: "unit-test-stub",
      }));
      buildApi.onResolve({ filter: /^@silmaril-security\/sdk$/ }, (args) => ({
        path: args.path,
        namespace: "unit-test-stub",
      }));
      buildApi.onLoad({ filter: /.*/, namespace: "unit-test-stub" }, (args) => {
        if (args.path === "openclaw/plugin-sdk/plugin-entry") {
          return {
            loader: "js",
            contents: "export function definePluginEntry(entry) { return entry; }",
          };
        }
        return {
          loader: "js",
          contents: `
            export const HookLabel = {
              USER_INPUT: "USER_INPUT",
              TOOL_CALL: "TOOL_CALL",
              TOOL_RESPONSE: "TOOL_RESPONSE",
              LLM_OUTPUT: "LLM_OUTPUT"
            };
            export class Firewall {
              constructor(options) {
                globalThis.__silmarilFirewallInstances ??= [];
                globalThis.__silmarilFirewallInstances.push({ options, instance: this });
              }
              async classify(text, options) {
                globalThis.__silmarilFirewallCalls ??= [];
                globalThis.__silmarilFirewallCalls.push({ text, options });
                const handler = globalThis.__silmarilFirewallClassify;
                return handler
                  ? await handler(text, options)
                  : { prediction: "BENIGN", score: 0.01, threshold: 0.5, primaryOutcome: "benign" };
              }
            }
          `,
        };
      });
    },
  }],
});

const moduleUrl = `${pathToFileURL(outFile).href}?${Date.now()}`;
const mod = await import(moduleUrl);
const plugin = mod.default;
const t = mod.__testInternals;
const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

function makeMeta(overrides = {}) {
  return {
    hookName: "before_prompt_build",
    hook: "USER_INPUT",
    ...overrides,
  };
}

async function withConsoleCapture(fn) {
  const originalLog = console.log;
  const originalError = console.error;
  const logs = [];
  const errors = [];
  console.log = (...args) => logs.push(args.map(String).join(" "));
  console.error = (...args) => errors.push(args.map(String).join(" "));
  try {
    return await fn({ logs, errors });
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }
}

async function withSilencedConsole(fn) {
  const originalLog = console.log;
  const originalError = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }
}

async function loadDemoLauncher() {
  return import(`${pathToFileURL(path.join(repoRoot, "scripts", "open-playground.mjs")).href}?${Date.now()}`);
}

function resetFirewallStub() {
  delete globalThis.__silmarilFirewallClassify;
  globalThis.__silmarilFirewallCalls = [];
  globalThis.__silmarilFirewallInstances = [];
}

function registerPlugin({ config = { apiKey: "test-key", apiUrl: "https://alpha.example/classify" } } = {}) {
  resetFirewallStub();

  const hooks = new Map();
  const logger = {
    infos: [],
    warns: [],
    info(message) {
      this.infos.push(String(message));
    },
    warn(message) {
      this.warns.push(String(message));
    },
  };
  plugin.register({
    pluginConfig: config,
    logger,
    on(name, handler, options) {
      hooks.set(name, { handler, options });
    },
  });

  return { hooks, logger };
}

function hook(env, name) {
  const entry = env.hooks.get(name);
  assert.ok(entry, `expected hook ${name} to be registered`);
  return entry.handler;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assertClassifyOptions(options, expected) {
  assert.equal(options.hook, expected.hook);
  assert.equal(options.toolName, expected.toolName);
  assert.equal(typeof options.metadata, "object");
  assert.equal(options.metadata.eventType, expected.eventType);
  assert.equal(options.metadata.hook, expected.hook);
  if (expected.toolName === undefined) {
    assert.equal(options.metadata.toolName, undefined);
  } else {
    assert.equal(options.metadata.toolName, expected.toolName);
  }
}

test("config: missing or blank apiKey/apiUrl disables runtime config", () => {
  assert.equal(t.resolveRuntimeConfig(undefined), undefined);
  assert.equal(t.resolveRuntimeConfig({}), undefined);
  assert.equal(t.resolveRuntimeConfig({ apiKey: " ", apiUrl: "https://x" }), undefined);
  assert.equal(t.resolveRuntimeConfig({ apiKey: "key", apiUrl: "" }), undefined);
});

test("config: trims required fields and applies timeout default", () => {
  assert.deepEqual(t.resolveRuntimeConfig({ apiKey: " key ", apiUrl: " https://x " }), {
    apiKey: "key",
    apiUrl: "https://x",
    timeoutMs: 2500,
    shadowMode: true,
    blockMalicious: false,
  });
});

test("config: silmarilApiKey is accepted and preferred over apiKey", () => {
  assert.deepEqual(t.resolveRuntimeConfig({ silmarilApiKey: " silmaril-key ", apiUrl: " https://x " }), {
    apiKey: "silmaril-key",
    apiUrl: "https://x",
    timeoutMs: 2500,
    shadowMode: true,
    blockMalicious: false,
  });
  assert.equal(
    t.resolveRuntimeConfig({
      apiKey: "plugin-identity-key",
      silmarilApiKey: "silmaril-classifier-key",
      apiUrl: "https://x",
    }).apiKey,
    "silmaril-classifier-key",
  );
});

test("config: timeout bounds are enforced", () => {
  assert.equal(t.resolveRuntimeConfig({ apiKey: "k", apiUrl: "u", timeoutMs: "999.8" }).timeoutMs, 999);
  assert.equal(t.resolveRuntimeConfig({ apiKey: "k", apiUrl: "u", timeoutMs: 249 }).timeoutMs, 2500);
  assert.equal(t.resolveRuntimeConfig({ apiKey: "k", apiUrl: "u", timeoutMs: 10001 }).timeoutMs, 2500);
});

test("config: shadow and enforcement booleans are parsed conservatively", () => {
  assert.equal(t.readBoolean(true), true);
  assert.equal(t.readBoolean("yes"), true);
  assert.equal(t.readBoolean("off"), false);
  assert.equal(t.readBoolean(""), undefined);
  assert.deepEqual(t.resolveRuntimeConfig({
    apiKey: "k",
    apiUrl: "u",
    shadowMode: "false",
    blockMalicious: "true",
  }), {
    apiKey: "k",
    apiUrl: "u",
    timeoutMs: 2500,
    shadowMode: false,
    blockMalicious: true,
  });
});

test("package metadata: devDependencies is unique and complete", async () => {
  const packageSource = await readFile(path.join(repoRoot, "package.json"), "utf8");
  assert.equal((packageSource.match(/"devDependencies"\s*:/g) ?? []).length, 1);

  const packageJson = JSON.parse(packageSource);
  assert.equal(packageJson.license, "Apache-2.0");
  assert.ok(packageJson.files.includes(".env.example"));
  assert.ok(packageJson.files.includes("LICENSE"));
  assert.ok(packageJson.files.includes("NOTICE"));
  assert.ok(packageJson.files.includes("scripts/open-playground.mjs"));
  assert.deepEqual(Object.keys(packageJson.devDependencies).sort(), ["esbuild", "tsx"]);
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.4.2");
  assert.equal(packageJson.devDependencies.esbuild, "0.28.0");
  assert.equal(packageJson.devDependencies.tsx, "4.22.3");
});

test("install docs: default clone flow does not pin simplified-dev", async () => {
  const readme = await readFile(path.join(repoRoot, "README.md"), "utf8");
  const claude = await readFile(path.join(repoRoot, "CLAUDE.md"), "utf8");
  for (const source of [readme, claude]) {
    assert.equal(source.includes("git checkout simplified-dev"), false);
    assert.equal(source.includes("select the simplified branch"), false);
  }
});

test("demo launcher: builds public setup and playground URLs only", async () => {
  const demo = await loadDemoLauncher();
  assert.equal(demo.buildDemoUrl(undefined), "https://app.silmaril.dev/demo/setup-complete");
  assert.equal(demo.buildDemoUrl("app.silmaril.dev", "playground"), "https://app.silmaril.dev/demo/playground");
  assert.equal(demo.buildDemoUrl("http://localhost:3001", "setup"), "http://localhost:3001/demo/setup-complete");
  assert.equal(demo.buildDemoUrl("   "), "https://app.silmaril.dev/demo/setup-complete");
});

test("demo launcher: option values do not consume another flag", async () => {
  const demo = await loadDemoLauncher();
  const originalArgv = process.argv;
  try {
    process.argv = ["node", "scripts/open-playground.mjs", "--route", "--json"];
    assert.equal(demo.optionValue("--route"), undefined);

    process.argv = ["node", "scripts/open-playground.mjs", "--route", "playground", "--json"];
    assert.equal(demo.optionValue("--route"), "playground");
  } finally {
    process.argv = originalArgv;
  }
});

test("demo launcher: JSON status contains only the public demo URL", async () => {
  const demo = await loadDemoLauncher();
  const originalArgv = process.argv;
  try {
    process.argv = ["node", "scripts/open-playground.mjs", "--json"];
    await withConsoleCapture(async ({ logs }) => {
      await demo.printOrOpen("https://app.silmaril.dev/demo/setup-complete");
      assert.deepEqual(JSON.parse(logs[0]), {
        url: "https://app.silmaril.dev/demo/setup-complete",
      });
      assert.deepEqual(Object.keys(JSON.parse(logs[0])), ["url"]);
    });
  } finally {
    process.argv = originalArgv;
  }
});

test("demo launcher: opener ENOENT is handled without an unhandled error", async () => {
  const demo = await loadDemoLauncher();
  const originalArgv = process.argv;
  const originalExitCode = process.exitCode;
  try {
    process.argv = ["node", "scripts/open-playground.mjs", "--open"];
    process.exitCode = undefined;

    await withConsoleCapture(async ({ logs, errors }) => {
      const child = new EventEmitter();
      child.unref = () => {};
      let openerCommand;

      await demo.printOrOpen("https://app.silmaril.dev/demo/setup-complete", (command) => {
        openerCommand = command;
        setImmediate(() => child.emit("error", new Error("missing opener")));
        return child;
      });
      await new Promise((resolve) => setImmediate(resolve));

      assert.deepEqual(logs, ["https://app.silmaril.dev/demo/setup-complete"]);
      assert.deepEqual(errors, [`Could not open browser with ${openerCommand}: missing opener`]);
      assert.equal(process.exitCode, 1);
    });
  } finally {
    process.argv = originalArgv;
    process.exitCode = originalExitCode;
  }
});

test("primitive parsing handles strings and integers", () => {
  assert.equal(t.readString("  hello  "), "hello");
  assert.equal(t.readString("   "), undefined);
  assert.equal(t.readString(1), undefined);
  assert.equal(t.readIntegerInRange("42.9", 0, 100), 42);
  assert.equal(t.readIntegerInRange(Number.POSITIVE_INFINITY, 0, 100), undefined);
  assert.equal(t.readIntegerInRange("nope", 0, 100), undefined);
});

test("metadata: event fields take precedence over context and message fields", () => {
  const meta = t.buildHookLogMeta(
    "before_tool_call",
    "TOOL_CALL",
    {
      runId: "event-run",
      sessionKey: "event-session",
      trace: { id: "event-trace" },
      message: {
        id: "message-id",
        runId: "message-run",
        sessionKey: "message-session",
        toolName: "message-tool",
      },
    },
    {
      runId: "ctx-run",
      sessionKey: "ctx-session",
      traceId: "ctx-trace",
      toolName: "ctx-tool",
    },
  );
  assert.equal(meta.runId, "event-run");
  assert.equal(meta.sessionKey, "event-session");
  assert.equal(meta.toolName, "ctx-tool");
  assert.equal(meta.messageId, "message-id");
  assert.equal(meta.traceId, "event-trace");
});

test("metadata: trace id can be read from traceId or trace.id", () => {
  assert.equal(t.readTraceId({ traceId: "trace-1" }), "trace-1");
  assert.equal(t.readTraceId({ id: "trace-2" }), "trace-2");
  assert.equal(t.readTraceId("no"), undefined);
});

test("logging fields omit undefined values and keep present correlation fields", () => {
  assert.deepEqual(t.logFields({ hook: "USER_INPUT", runId: "run", sessionKey: "", traceId: undefined }), {
    hook: "USER_INPUT",
    runId: "run",
  });
});

test("classifier: empty payload skips without calling firewall", async () => {
  let calls = 0;
  await withConsoleCapture(async ({ logs }) => {
    const result = await t.classifyHookPayload({ classify: async () => calls++ }, "   ", makeMeta());
    assert.equal(result, undefined);
    assert.equal(calls, 0);
    assert.ok(logs.some((line) => line.includes("empty_payload")));
  });
});

test("classifier: non-empty payload passes hook and toolName", async () => {
  await withConsoleCapture(async ({ logs }) => {
    const result = await t.classifyHookPayload(
      {
        classify: async (text, options) => {
          assert.equal(text, "payload");
          assertClassifyOptions(options, {
            hook: "TOOL_CALL",
            toolName: "exec",
            eventType: "before_tool_call",
          });
          return { prediction: "BENIGN", score: 0.12, threshold: 0.5, primaryOutcome: "benign" };
        },
      },
      "payload",
      makeMeta({ hookName: "before_tool_call", hook: "TOOL_CALL", toolName: "exec" }),
    );
    assert.deepEqual(result, { prediction: "BENIGN", score: 0.12, threshold: 0.5, primaryOutcome: "benign" });
    assert.ok(logs.some((line) => line.includes("[firewall] before_tool_call result:")));
  });
});

test("tool result extraction handles strings, objects, arrays, and empty content", () => {
  assert.equal(t.extractToolResultText({ message: { content: "hello" } }), "hello");
  assert.equal(t.extractToolResultText({ message: { content: { text: "hello" } } }), "hello");
  assert.equal(t.extractToolResultText({ message: { content: ["a", { text: "b" }, { type: "image" }] } }), "a\nb\n");
  assert.equal(t.extractToolResultText({ message: { content: [{ type: "image" }] } }), "");
  assert.equal(t.extractToolResultText(undefined), "");
});

test("message sending extraction handles strings, objects, arrays, and empty content", () => {
  assert.equal(t.extractMessageSendingText({ content: "assistant text" }), "assistant text");
  assert.equal(t.extractMessageSendingText({ content: { text: "assistant text" } }), "assistant text");
  assert.equal(t.extractMessageSendingText({ content: ["a", { text: "b" }, { type: "image" }] }), "a\nb\n");
  assert.equal(t.extractMessageSendingText(undefined), "");
});

test("safeStringify handles circular references, BigInt, undefined, and throwing toJSON", () => {
  const circular = { a: 1, big: 2n };
  circular.self = circular;
  assert.equal(t.safeStringify(circular), '{"a":1,"big":"2","self":"[Circular]"}');
  assert.equal(t.safeStringify(undefined), "");
  assert.equal(t.safeStringify({ toJSON() { throw new Error("boom"); } }), "[object Object]");
});

test("plugin: registers startup and classifier hooks", () => {
  const env = registerPlugin({ config: { apiKey: "k", apiUrl: "u", timeoutMs: 777 } });
  assert.deepEqual([...env.hooks.keys()].sort(), [
    "before_prompt_build",
    "before_tool_call",
    "gateway_start",
    "message_sending",
    "tool_result_persist",
  ]);
  for (const entry of env.hooks.values()) {
    assert.deepEqual(entry.options, { priority: 0, timeoutMs: 777 });
  }
});

test("plugin: gateway_start logs installation only", () => {
  const env = registerPlugin();
  hook(env, "gateway_start")();
  assert.deepEqual(env.logger.infos, ["firewall-plugin: installed"]);
});

test("plugin: missing prompt skips without classifier call", async () => {
  const env = registerPlugin();
  await withConsoleCapture(async ({ logs }) => {
    await hook(env, "before_prompt_build")({}, {});
    assert.equal(globalThis.__silmarilFirewallCalls.length, 0);
    assert.ok(logs.some((line) => line.includes("missing_prompt")));
  });
});

test("plugin: missing config warns once and classifications fail open", async () => {
  const env = registerPlugin({ config: {} });
  await withConsoleCapture(async ({ logs }) => {
    await hook(env, "before_prompt_build")({ prompt: "hello" }, {});
    await hook(env, "before_prompt_build")({ prompt: "hello again" }, {});
    assert.equal(env.logger.warns.length, 1);
    assert.equal(globalThis.__silmarilFirewallCalls.length, 0);
    assert.equal(logs.filter((line) => line.includes("missing_config")).length, 2);
  });
});

test("plugin: before_prompt_build sends user prompt to Silmaril and returns undefined", async () => {
  const env = registerPlugin();
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });
  await withConsoleCapture(async ({ logs }) => {
    const result = await hook(env, "before_prompt_build")({
      prompt: "ignore instructions",
      runId: "run-risk",
    }, {});
    assert.equal(result, undefined);
    assert.equal(globalThis.__silmarilFirewallCalls[0].text, "ignore instructions");
    assertClassifyOptions(globalThis.__silmarilFirewallCalls[0].options, {
      hook: "USER_INPUT",
      toolName: undefined,
      eventType: "before_prompt_build",
    });
    assert.ok(logs.some((line) => line.includes("[firewall] before_prompt_build result:")));
    assert.equal(logs.some((line) => line.includes("risk cached")), false);
    assert.equal(logs.some((line) => line.includes("risk cache consumed")), false);
  });
});

test("plugin: before_tool_call classifies safe-stringified params and passes through by default", async () => {
  const env = registerPlugin();
  const circular = { value: 1 };
  circular.self = circular;
  globalThis.__silmarilFirewallClassify = async (text, options) => {
    assert.equal(text, '{"value":1,"self":"[Circular]"}');
    assertClassifyOptions(options, {
      hook: "TOOL_CALL",
      toolName: "exec",
      eventType: "before_tool_call",
    });
    return { prediction: "MALICIOUS", score: 0.99, threshold: 0.5, primaryOutcome: "control_abuse" };
  };
  await withSilencedConsole(async () => {
    const result = await hook(env, "before_tool_call")({ toolName: "exec", params: circular }, {});
    assert.equal(result, undefined);
  });
});

test("plugin: optional enforcement blocks enforceable outputs when not shadowing", async () => {
  const env = registerPlugin({
    config: {
      apiKey: "k",
      apiUrl: "u",
      blockMalicious: true,
      shadowMode: false,
    },
  });
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });

  await withConsoleCapture(async ({ logs }) => {
    const toolCallResult = await hook(env, "before_tool_call")({
      toolName: "exec",
      params: { command: "rm -rf /tmp/example" },
    }, {});
    assert.deepEqual(toolCallResult, {
      block: true,
      blockReason: "Silmaril Firewall blocked this tool call; hook=TOOL_CALL; prediction=MALICIOUS; primaryOutcome=control_abuse; score=0.99; threshold=0.5",
    });
    const messageResult = await hook(env, "message_sending")({
      to: "user",
      content: "raw malicious final assistant output",
      messageId: "msg-1",
    }, {});
    assert.equal(messageResult.cancel, true);
    assert.equal(messageResult.content.includes("raw malicious final assistant output"), false);
    assert.equal(messageResult.content.includes('"openClawHookEvent": "message_sending"'), true);
    assert.equal(messageResult.content.includes('"hook": "LLM_OUTPUT"'), true);
    assert.equal(messageResult.content.includes('"messageId": "msg-1"'), true);
    assert.equal(messageResult.content.includes('"score"'), false);
    assert.equal(messageResult.content.includes('"threshold"'), false);
    assert.ok(logs.some((line) => line.includes("[firewall] before_tool_call blocked:")));
    assert.ok(logs.some((line) => line.includes("[firewall] message_sending blocked:")));
    assert.equal(logs.some((line) => line.includes("rm -rf")), false);
    assert.equal(logs.some((line) => line.includes("raw malicious final assistant output")), false);
  });
});

test("plugin: shadowMode prevents blocking even when blockMalicious is true", async () => {
  const env = registerPlugin({
    config: {
      apiKey: "k",
      apiUrl: "u",
      blockMalicious: true,
      shadowMode: true,
    },
  });
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });

  await withSilencedConsole(async () => {
    const result = await hook(env, "before_tool_call")({ toolName: "exec", params: { command: "false" } }, {});
    const messageResult = await hook(env, "message_sending")({ to: "user", content: "assistant output" }, {});
    assert.equal(result, undefined);
    assert.equal(messageResult, undefined);
  });
});

test("decision: benign predictions pass and thresholds block conflicts", () => {
  const config = {
    apiKey: "k",
    apiUrl: "u",
    timeoutMs: 2500,
    shadowMode: false,
    blockMalicious: true,
  };
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "BENIGN",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "benign",
  }), false);
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "BENIGN",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }), false);
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "benign",
  }), true);
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "MALICIOUS",
    score: 0.1,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }), false);
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }), true);
  assert.equal(t.shouldBlockToolCall({ ...config, shadowMode: true }, {
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }), false);
});

test("plugin: before_tool_call uses config captured before classifier await", async () => {
  const config = {
    apiKey: "k",
    apiUrl: "u",
    blockMalicious: true,
    shadowMode: false,
  };
  const env = registerPlugin({ config });
  let release;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  globalThis.__silmarilFirewallClassify = async () => pending;

  await withSilencedConsole(async () => {
    const call = hook(env, "before_tool_call")({ toolName: "exec", params: { command: "true" } }, {});
    config.shadowMode = true;
    release({
      prediction: "MALICIOUS",
      score: 0.99,
      threshold: 0.5,
      primaryOutcome: "control_abuse",
    });
    assert.deepEqual(await call, {
      block: true,
      blockReason: "Silmaril Firewall blocked this tool call; hook=TOOL_CALL; prediction=MALICIOUS; primaryOutcome=control_abuse; score=0.99; threshold=0.5",
    });
  });
});

test("plugin: stable runtime config reuses one Firewall client", async () => {
  const config = { apiKey: "k", apiUrl: "u", timeoutMs: 777 };
  const env = registerPlugin({ config });
  await withSilencedConsole(async () => {
    await hook(env, "before_prompt_build")({ prompt: "first" }, {});
    await hook(env, "before_tool_call")({ toolName: "exec", params: { command: "true" } }, {});
    hook(env, "tool_result_persist")({ message: { content: "tool output" } }, {});
    await hook(env, "message_sending")({ to: "user", content: "assistant output" }, {});
    await sleep(0);
  });

  assert.equal(globalThis.__silmarilFirewallInstances.length, 1);
  assert.deepEqual(globalThis.__silmarilFirewallInstances[0].options, {
    apiKey: "k",
    apiUrl: "u",
    timeoutMs: 777,
    shadowMode: true,
  });
});

test("plugin: runtime config changes create a new Firewall client", async () => {
  const config = { apiKey: "k", apiUrl: "u1", timeoutMs: 777, blockMalicious: false };
  const env = registerPlugin({ config });
  await withSilencedConsole(async () => {
    await hook(env, "before_prompt_build")({ prompt: "first" }, {});
    config.apiUrl = "u2";
    await hook(env, "before_tool_call")({ toolName: "exec", params: { command: "true" } }, {});
    config.blockMalicious = true;
    await hook(env, "message_sending")({ to: "user", content: "third" }, {});
  });

  assert.equal(globalThis.__silmarilFirewallInstances.length, 3);
  assert.deepEqual(
    globalThis.__silmarilFirewallInstances.map((entry) => entry.options.apiUrl),
    ["u1", "u2", "u2"],
  );
});

test("plugin: tool_result_persist stays pass-through and returns immediately", async () => {
  const env = registerPlugin({
    config: {
      apiKey: "k",
      apiUrl: "u",
      blockMalicious: true,
      shadowMode: false,
    },
  });
  let release;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  globalThis.__silmarilFirewallClassify = async () => pending.then(() => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }));
  await withSilencedConsole(async () => {
    const result = hook(env, "tool_result_persist")({ message: { content: "tool output" } }, {});
    assert.equal(result, undefined);
    assert.equal(globalThis.__silmarilFirewallCalls.length, 1);
    assert.equal(globalThis.__silmarilFirewallCalls[0].text, "tool output");
    assertClassifyOptions(globalThis.__silmarilFirewallCalls[0].options, {
      hook: "TOOL_RESPONSE",
      toolName: undefined,
      eventType: "tool_result_persist",
    });
    release();
    await sleep(0);
  });
});

test("plugin: classifier errors are logged and fail open", async () => {
  const env = registerPlugin({
    config: {
      apiKey: "k",
      apiUrl: "u",
      blockMalicious: true,
      shadowMode: false,
    },
  });
  globalThis.__silmarilFirewallClassify = async () => {
    throw new Error("classifier unavailable for raw classified prompt");
  };
  await withConsoleCapture(async ({ errors }) => {
    const promptResult = await hook(env, "before_prompt_build")({ prompt: "risk", runId: "run-error" }, {});
    const toolResult = await hook(env, "before_tool_call")({ params: { a: 1 } }, {});
    hook(env, "tool_result_persist")({ message: { content: "tool result" } }, {});
    const messageResult = await hook(env, "message_sending")({ to: "user", content: "assistant result" }, {});
    await sleep(0);
    assert.equal(promptResult, undefined);
    assert.equal(toolResult, undefined);
    assert.equal(messageResult, undefined);
    assert.ok(errors.some((line) => line.includes("before_prompt_build error:")));
    assert.ok(errors.some((line) => line.includes("before_tool_call error:")));
    assert.ok(errors.some((line) => line.includes("tool_result_persist error:")));
    assert.ok(errors.some((line) => line.includes("message_sending error:")));
    assert.equal(errors.some((line) => line.includes("raw classified prompt")), false);
  });
});

test("logging: error diagnostics keep safe details and redact unknown messages", () => {
  const networkError = Object.assign(
    new Error("connect ECONNREFUSED 127.0.0.1:443"),
    { code: "ECONNREFUSED" },
  );
  assert.deepEqual(t.safeErrorFields(networkError), {
    errorType: "Error",
    errorCode: "ECONNREFUSED",
    errorMessage: "connect ECONNREFUSED 127.0.0.1:443",
  });
  const statusError = Object.assign(new Error("Response status 401"), { status: 401 });
  assert.deepEqual(t.safeErrorFields(statusError), {
    errorType: "Error",
    status: 401,
    errorMessage: "response_status_401",
  });
  assert.deepEqual(t.safeErrorFields(new Error("classifier saw raw classified prompt")), {
    errorType: "Error",
  });
});

test("source invariant: runtime has no result cache, wrappers, or prompt mutation", async () => {
  const source = await readFile(path.join(repoRoot, "index.ts"), "utf8");
  for (const forbidden of [
    "RiskRecord",
    "riskBy",
    "risk cache",
    "before_message_write",
    "SILMARIL_FIREWALL_SHADOW_MODE",
    "toolResultMaxInFlight",
    "appendSystemContext",
    "prependSystemContext",
    "prependContext",
    "Silmaril's Firewall found this to be suspicious",
    "Silmaril found a risk of prompt injection",
    "warning prepended",
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden source marker present: ${forbidden}`);
  }
});

let failed = 0;
const started = performance.now();
for (const { name, fn } of tests) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`not ok - ${name}`);
    console.error(err);
  }
}

await rm(outDir, { recursive: true, force: true });

const elapsed = (performance.now() - started).toFixed(1);
if (failed > 0) {
  console.error(`${failed}/${tests.length} unit tests failed in ${elapsed}ms`);
  process.exit(1);
}

console.log(`${tests.length} unit tests passed in ${elapsed}ms`);
