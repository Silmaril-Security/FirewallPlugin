import assert from "node:assert/strict";
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
              TOOL_RESPONSE: "TOOL_RESPONSE"
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

test("safeStringify handles circular references, BigInt, undefined, and throwing toJSON", () => {
  const circular = { a: 1, big: 2n };
  circular.self = circular;
  assert.equal(t.safeStringify(circular), '{"a":1,"big":"2","self":"[Circular]"}');
  assert.equal(t.safeStringify(undefined), "");
  assert.equal(t.safeStringify({ toJSON() { throw new Error("boom"); } }), "[object Object]");
});

test("plugin: registers only startup and classifier hooks", () => {
  const env = registerPlugin({ config: { apiKey: "k", apiUrl: "u", timeoutMs: 777 } });
  assert.deepEqual([...env.hooks.keys()].sort(), [
    "before_prompt_build",
    "before_tool_call",
    "gateway_start",
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

test("plugin: optional enforcement blocks only before_tool_call when not shadowing", async () => {
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
    const result = await hook(env, "before_tool_call")({
      toolName: "exec",
      params: { command: "rm -rf /tmp/example" },
    }, {});
    assert.deepEqual(result, {
      block: true,
      blockReason: "Silmaril Firewall blocked this tool call; hook=TOOL_CALL; primaryOutcome=control_abuse; score=0.99; threshold=0.5",
    });
    assert.ok(logs.some((line) => line.includes("[firewall] before_tool_call blocked:")));
    assert.equal(logs.some((line) => line.includes("rm -rf")), false);
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
    assert.equal(result, undefined);
  });
});

test("decision: benign outcomes do not block even above threshold", () => {
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
      blockReason: "Silmaril Firewall blocked this tool call; hook=TOOL_CALL; primaryOutcome=control_abuse; score=0.99; threshold=0.5",
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
    await hook(env, "before_prompt_build")({ prompt: "third" }, {});
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
    await sleep(0);
    assert.equal(promptResult, undefined);
    assert.equal(toolResult, undefined);
    assert.ok(errors.some((line) => line.includes("before_prompt_build error:")));
    assert.ok(errors.some((line) => line.includes("before_tool_call error:")));
    assert.ok(errors.some((line) => line.includes("tool_result_persist error:")));
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
