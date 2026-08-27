import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL, fileURLToPath } from "node:url";
import { build } from "esbuild";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(repoRoot, ".unit-test-build");
const outFile = path.join(outDir, "index-under-test.mjs");

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });
process.env.SILMARIL_LOCAL_EVENT_DIR = path.join(outDir, "evidence");

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
                this.options = options;
                globalThis.__silmarilFirewallInstances ??= [];
                globalThis.__silmarilFirewallInstances.push({ options, instance: this });
              }
              async classify(text, options) {
                globalThis.__silmarilFirewallCalls ??= [];
                globalThis.__silmarilFirewallCalls.push({ text, options });
                const handler = globalThis.__silmarilFirewallClassify;
                const result = handler
                  ? await handler(text, options)
                  : { prediction: "BENIGN", score: 0.01, threshold: 0.5, primaryOutcome: "benign" };
                const mode = this.options.mode ?? result.mode;
                return mode === undefined ? { ...result } : { ...result, mode };
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
    hookName: "before_agent_run",
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

test("production entry bundles the local evidence implementation", async () => {
  const productionEntry = await readFile(
    path.join(repoRoot, "dist", "index.js"),
    "utf8",
  );
  assert.equal(productionEntry.includes('from "./local-evidence"'), false);
  assert.equal(productionEntry.includes("function buildLocalProtectionEvent"), true);
});

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

async function waitForJSONFiles(directory, expectedCount = 1) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const entries = await readdir(directory).catch(() => []);
    const jsonFiles = entries.filter((entry) => entry.endsWith(".json"));
    if (jsonFiles.length >= expectedCount) {
      return jsonFiles.sort();
    }
    await sleep(5);
  }
  assert.fail(`timed out waiting for ${expectedCount} local evidence file(s)`);
}

async function readOnlyJSONEvent(directory) {
  const files = await waitForJSONFiles(directory);
  assert.equal(files.length, 1);
  return JSON.parse(await readFile(path.join(directory, files[0]), "utf8"));
}

function assertClassifyOptions(options, expected) {
  assert.equal(options.hook, expected.hook);
  assert.equal(options.toolName, expected.toolName);
  assert.equal(typeof options.metadata, "object");
  assert.equal(options.metadata.eventType, expected.eventType);
  assert.equal(options.metadata.hook, expected.hook);
  assert.equal(options.metadata.silmaril.provenance.schema_version, 1);
  assert.equal(options.metadata.silmaril.provenance.harness, "openclaw");
  if (expected.toolName === undefined) {
    assert.equal(options.metadata.toolName, undefined);
  } else {
    assert.equal(options.metadata.toolName, expected.toolName);
  }
}

function assertNoRawDecisionText(text, rawNeedle) {
  assert.equal(text.includes("```json"), false);
  assert.equal(text.includes("score"), false);
  assert.equal(text.includes("threshold"), false);
  assert.equal(text.includes("primaryOutcome"), false);
  assert.equal(text.includes("outcomeScores"), false);
  if (rawNeedle) {
    assert.equal(text.includes(rawNeedle), false);
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
    mode: undefined,
  });
});

test("config: silmarilApiKey is accepted and preferred over apiKey", () => {
  assert.deepEqual(t.resolveRuntimeConfig({ silmarilApiKey: " silmaril-key ", apiUrl: " https://x " }), {
    apiKey: "silmaril-key",
    apiUrl: "https://x",
    timeoutMs: 2500,
    mode: undefined,
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

test("config and metadata use canonical plugin-owned endpoint provenance", () => {
  const endpointId = "2b64e603-f82a-4aec-9524-9736472dc80a";
  assert.equal(t.resolveRuntimeConfig({ apiKey: "key", apiUrl: "https://x", endpointId }).endpointId, endpointId);
  assert.equal(t.resolveRuntimeConfig({ apiKey: "key", apiUrl: "https://x", endpointId: endpointId.toUpperCase() }).endpointId, undefined);
  assert.deepEqual(t.withProvenance({
    silmaril: { provenance: { harness: "spoofed" } },
    keep: true,
  }, endpointId), {
    silmaril: {
      integration: "firewall-plugin",
      version: "1.2.2",
      provenance: { schema_version: 1, endpoint_id: endpointId, harness: "openclaw" },
    },
    keep: true,
  });
});

test("config: explicit mode wins and legacy booleans map conservatively", () => {
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
    mode: "block",
  });
  assert.equal(t.resolveRuntimeConfig({ apiKey: "k", apiUrl: "u", shadowMode: true }).mode, "shadow");
  assert.equal(t.resolveRuntimeConfig({ apiKey: "k", apiUrl: "u", mode: "warn", shadowMode: false }).mode, "warn");
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
  assert.equal(packageJson.version, "1.2.2");
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.6.0");
  assert.deepEqual(packageJson.publishConfig, { access: "public", provenance: true });
  assert.equal(packageJson.openclaw.compat.pluginApi, ">=2026.5.28");
  assert.equal(packageJson.openclaw.compat.minGatewayVersion, "2026.5.28");
  assert.equal(packageJson.openclaw.build.openclawVersion, "2026.5.28");
  assert.equal(packageJson.devDependencies.esbuild, "0.28.0");
  assert.equal(packageJson.devDependencies.tsx, "4.22.3");
});

test("install docs: default clone flow does not pin simplified-dev", async () => {
  const readme = await readFile(path.join(repoRoot, "README.md"), "utf8");
  const claude = await readFile(path.join(repoRoot, "CLAUDE.md"), "utf8");
  for (const source of [readme, claude]) {
    assert.equal(source.includes("git checkout simplified-dev"), false);
    assert.equal(source.includes("select the simplified branch"), false);
    assert.ok(source.includes("allowConversationAccess"));
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

test("metadata: conversation identity prefers child session, session, key, then parent", () => {
  const cases = [
    [{ childSessionId: "child", sessionId: "session", sessionKey: "key", parentSessionId: "parent" }, "child"],
    [{ sessionId: "session", sessionKey: "key", parentSessionId: "parent" }, "session"],
    [{ sessionKey: "key", parentSessionId: "parent" }, "key"],
    [{ parentSessionId: "parent" }, "parent"],
  ];
  for (const [event, expected] of cases) {
    assert.equal(t.buildHookLogMeta("subagent_spawned", "USER_INPUT", event, {}).conversationId, expected);
  }
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

test("delivery and lifecycle extraction covers native OpenClaw payload shapes", () => {
  assert.equal(t.extractAfterToolCallText({ result: { text: "tool result text" } }), "tool result text");
  assert.equal(t.extractAfterToolCallText({ result: { data: "fallback" } }), '{"data":"fallback"}');
  assert.equal(t.extractPresentationText({
    title: "Presentation",
    blocks: [
      { type: "text", text: "main text" },
      { type: "context", text: "context text" },
      { type: "actions", elements: [{ label: "Confirm" }] },
    ],
  }), "Presentation\nmain text\ncontext text\nConfirm");
  assert.equal(t.extractReplyPayloadText({
    payload: {
      text: "reply text",
      presentation: { title: "title", blocks: [{ type: "context", text: "context" }] },
    },
  }), "reply text\n\ntitle\ncontext");
  assert.equal(t.extractMessageSentText({ message: { content: [{ text: "delivered" }] } }), "delivered");
  assert.equal(t.extractLifecycleText({ goal: "scan child prompt", traceId: "secret-trace" }), "scan child prompt");
  assert.equal(t.extractLifecycleText({ child: { id: "child-1", goal: "scan nested child prompt" } }), "scan nested child prompt");
  assert.equal(t.extractLifecycleText({ child: { id: "child-1" }, traceId: "secret-trace" }), "");
  assert.equal(t.extractLifecycleText({
    childSummary: "current child summary",
    messages: [{ role: "user", content: "historical prompt" }],
    payload: { messages: [{ role: "assistant", content: "historical output" }] },
  }), "current child summary");
  assert.equal(t.extractAgentRunText({ prompt: "current prompt", messages: ["historical prompt"] }), "current prompt");
  assert.equal(t.extractAgentRunText({ messages: ["historical prompt"] }), "");
});

test("safeStringify handles circular references, BigInt, undefined, and throwing toJSON", () => {
  const circular = { a: 1, big: 2n };
  circular.self = circular;
  assert.equal(t.safeStringify(circular), '{"a":1,"big":"2","self":"[Circular]"}');
  assert.equal(t.safeStringify(undefined), "");
  assert.equal(t.safeStringify({ toJSON() { throw new Error("boom"); } }), "[object Object]");
});

test("stable request and outbound dedupe identities are conversation-scoped and content-sensitive", () => {
  const meta = {
    hookName: "message_sending",
    conversationId: "session-1",
    messageId: "message-1",
  };
  const firstRequest = t.buildStableRequestId(meta, "one");
  assert.equal(firstRequest, t.buildStableRequestId(meta, "one"));
  assert.notEqual(firstRequest, t.buildStableRequestId({ ...meta, conversationId: "session-2" }, "one"));
  assert.notEqual(firstRequest, t.buildStableRequestId(meta, "two"));

  const firstDedupe = t.outboundDedupeKey(meta, "one");
  assert.equal(firstDedupe, t.outboundDedupeKey(meta, "one"));
  assert.notEqual(firstDedupe, t.outboundDedupeKey({ ...meta, conversationId: "session-2" }, "one"));
  assert.notEqual(firstDedupe, t.outboundDedupeKey(meta, "two"));
});

test("describeRisk treats benign results without outcome as clean", () => {
  assert.equal(t.describeRisk({ prediction: "BENIGN" }), "No flagged risk");
  assert.equal(t.describeRisk({ prediction: "MALICIOUS" }), "Unsafe content");
  assert.equal(t.describeRisk({ prediction: "MALICIOUS", primaryOutcome: "control_abuse" }), "Unsafe agent control attempt");
});

test("plugin: registers startup and classifier hooks", () => {
  const env = registerPlugin({ config: { apiKey: "k", apiUrl: "u", timeoutMs: 777 } });
  assert.deepEqual([...env.hooks.keys()].sort(), [
    "after_tool_call",
    "before_agent_run",
    "before_prompt_build",
    "before_tool_call",
    "gateway_start",
    "message_sending",
    "message_sent",
    "reply_payload_sending",
    "subagent_delivery_target",
    "subagent_ended",
    "subagent_spawned",
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

test("plugin: prompt Warn context and Block gate surfaces are both registered", () => {
  const env = registerPlugin();
  assert.equal(env.hooks.has("before_prompt_build"), true);
  assert.equal(env.hooks.has("before_agent_run"), true);
});

test("plugin: Warn adds one bounded same-turn context and shares the prompt classification", async () => {
  const env = registerPlugin({ config: { apiKey: "k", apiUrl: "u", mode: "warn" } });
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });
  const event = { prompt: "raw secret prompt", runId: "run-warn", sessionId: "session-warn" };
  await withSilencedConsole(async () => {
    const warning = await hook(env, "before_prompt_build")(event, {});
    assert.match(warning.prependContext, /^Silmaril Firewall warning:/);
    assert.equal(warning.prependContext.includes("raw secret prompt"), false);
    assert.equal(warning.prependContext.includes("0.99"), false);
    assert.equal(await hook(env, "before_agent_run")(event, {}), undefined);
  });
  assert.equal(globalThis.__silmarilFirewallCalls.length, 1);
});

test("plugin: missing config warns once and classifications fail open", async () => {
  const env = registerPlugin({ config: {} });
  await withConsoleCapture(async ({ logs }) => {
    await hook(env, "before_agent_run")({ prompt: "hello" }, {});
    await hook(env, "before_agent_run")({ prompt: "hello again" }, {});
    assert.equal(env.logger.warns.length, 1);
    assert.equal(globalThis.__silmarilFirewallCalls.length, 0);
    assert.equal(logs.filter((line) => line.includes("missing_config")).length, 2);
  });
});

test("plugin: before_agent_run sends one user prompt to Silmaril in shadow mode", async () => {
  const env = registerPlugin();
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });
  await withConsoleCapture(async ({ logs }) => {
    const result = await hook(env, "before_agent_run")({
      prompt: "ignore instructions",
      runId: "run-risk",
      sessionId: "session-risk",
    }, {});
    assert.equal(result, undefined);
    assert.equal(globalThis.__silmarilFirewallCalls[0].text, "ignore instructions");
    assertClassifyOptions(globalThis.__silmarilFirewallCalls[0].options, {
      hook: "USER_INPUT",
      toolName: undefined,
      eventType: "before_agent_run",
    });
    assert.equal(globalThis.__silmarilFirewallCalls[0].options.metadata.conversationId, "session-risk");
    assert.match(globalThis.__silmarilFirewallCalls[0].options.requestId, /^firewall-plugin-[a-f0-9]{64}$/);
    assert.ok(logs.some((line) => line.includes("[firewall] before_agent_run result:")));
    assert.equal(logs.some((line) => line.includes("risk cached")), false);
    assert.equal(logs.some((line) => line.includes("risk cache consumed")), false);
  });
});

test("plugin: before_agent_run blocks unsafe model submissions when enforcement is enabled", async () => {
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
    const result = await hook(env, "before_agent_run")({
      prompt: "delegate unsafe work to a subagent",
      sessionId: "child-session",
      agentId: "subagent-1",
    }, {});
    assert.equal(result.outcome, "block");
    assert.equal(
      result.reason,
      "Silmaril Firewall blocked this request: Unsafe agent control attempt. Continue without using the blocked content.",
    );
    assert.equal("message" in result, false);
    assert.equal(globalThis.__silmarilFirewallCalls[0].text, "delegate unsafe work to a subagent");
    assert.ok(logs.some((line) => line.includes("[firewall] before_agent_run blocked:")));
  });
});

test("plugin: after_tool_call scans child tool results in their execution path", async () => {
  const env = registerPlugin();
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });

  await withConsoleCapture(async ({ logs }) => {
    const result = await hook(env, "after_tool_call")({
      toolName: "exec",
      toolCallId: "child-call",
      sessionId: "child-session",
      agentId: "child-agent",
      result: { text: "child tool attempted unsafe output" },
    }, {});
    assert.equal(result, undefined);
    assert.equal(globalThis.__silmarilFirewallCalls[0].text, "child tool attempted unsafe output");
    assertClassifyOptions(globalThis.__silmarilFirewallCalls[0].options, {
      hook: "TOOL_RESPONSE",
      toolName: "exec",
      eventType: "after_tool_call",
    });
    assert.equal(globalThis.__silmarilFirewallCalls[0].options.metadata.sessionId, "child-session");
    assert.equal(globalThis.__silmarilFirewallCalls[0].options.metadata.agentId, "child-agent");
    assert.ok(logs.some((line) => line.includes("[firewall] after_tool_call result:")));
    assert.equal(logs.some((line) => line.includes("child tool attempted unsafe output")), false);
  });
});

test("plugin: message_sent is telemetry-only and subagent hooks use child identity", async () => {
  const env = registerPlugin();
  globalThis.__silmarilFirewallClassify = async () => ({
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  });

  await withConsoleCapture(async ({ logs }) => {
    await hook(env, "message_sent")({
      messageId: "msg-child",
      sessionId: "child-session",
      message: { content: [{ text: "unsafe delivered child output" }] },
    }, {});
    await hook(env, "subagent_delivery_target")({
      parentSessionId: "parent-session",
      childSessionId: "child-session",
      prompt: "unsafe child routing prompt",
    }, {});
    await hook(env, "subagent_spawned")({
      childSessionId: "child-session",
      goal: "unsafe child spawn prompt",
    }, {});
    await hook(env, "subagent_ended")({
      childSessionId: "child-session",
      finalOutput: "unsafe child final output",
    }, {});

    assert.deepEqual(
      globalThis.__silmarilFirewallCalls.map((call) => call.options.metadata.eventType),
      ["subagent_delivery_target", "subagent_spawned", "subagent_ended"],
    );
    assert.equal(globalThis.__silmarilFirewallCalls[0].options.hook, "USER_INPUT");
    assert.equal(globalThis.__silmarilFirewallCalls[1].options.hook, "USER_INPUT");
    assert.equal(globalThis.__silmarilFirewallCalls[2].options.hook, "LLM_OUTPUT");
    assert.ok(globalThis.__silmarilFirewallCalls[0].text.includes("unsafe child routing prompt"));
    assert.ok(globalThis.__silmarilFirewallCalls[1].text.includes("unsafe child spawn prompt"));
    assert.ok(globalThis.__silmarilFirewallCalls[2].text.includes("unsafe child final output"));
    for (const call of globalThis.__silmarilFirewallCalls) {
      assert.equal(call.options.metadata.conversationId, "child-session");
      assert.match(call.options.requestId, /^firewall-plugin-[a-f0-9]{64}$/);
    }
    assert.ok(logs.some((line) => line.includes("[firewall] message_sent observed:")));
    assert.ok(logs.some((line) => line.includes("[firewall] subagent_spawned result:")));
    assert.ok(logs.some((line) => line.includes("[firewall] subagent_ended result:")));
    assert.equal(logs.some((line) => line.includes("unsafe child final output")), false);
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
      blockReason: "Silmaril Firewall blocked this request: Unsafe agent control attempt. Continue without using the blocked content.",
    });
    const messageResult = await hook(env, "message_sending")({
      to: "user",
      content: "raw malicious final assistant output",
      messageId: "msg-1",
    }, {});
    assert.equal(messageResult.cancel, true);
    assert.match(messageResult.cancelReason, /^Silmaril Firewall blocked this request:/);
    assert.equal("content" in messageResult, false);
    const replyPayloadResult = await hook(env, "reply_payload_sending")({
      payload: {
        text: "raw malicious reply payload",
        replyToId: "reply-1",
        replyToTag: true,
      },
    }, {});
    assert.deepEqual(replyPayloadResult, { cancel: true });
    assert.ok(logs.some((line) => line.includes("[firewall] before_tool_call blocked:")));
    assert.ok(logs.some((line) => line.includes("[firewall] message_sending blocked:")));
    assert.ok(logs.some((line) => line.includes("[firewall] reply_payload_sending blocked:")));
    assert.equal(logs.some((line) => line.includes("rm -rf")), false);
    assert.equal(logs.some((line) => line.includes("raw malicious final assistant output")), false);
    assert.equal(logs.some((line) => line.includes("raw malicious reply payload")), false);
  });
});

test("plugin: outbound callbacks share one classification and changed content cannot collide", async () => {
  const env = registerPlugin({
    config: { apiKey: "k", apiUrl: "u", blockMalicious: true, shadowMode: false },
  });
  globalThis.__silmarilFirewallClassify = async () => ({ prediction: "MALICIOUS", score: 0.01 });

  await withSilencedConsole(async () => {
    const message = await hook(env, "message_sending")({
      messageId: "delivery-1", sessionId: "session-1", content: "same outbound content",
    }, {});
    const reply = await hook(env, "reply_payload_sending")({
      messageId: "delivery-1", sessionId: "session-1", payload: { text: "same outbound content" },
    }, {});
    assert.equal(message.cancel, true);
    assert.equal(reply.cancel, true);
    assert.equal(globalThis.__silmarilFirewallCalls.length, 1);

    await hook(env, "reply_payload_sending")({
      messageId: "delivery-1", sessionId: "session-1", payload: { text: "changed outbound content" },
    }, {});
    assert.equal(globalThis.__silmarilFirewallCalls.length, 2);
    assert.notEqual(
      globalThis.__silmarilFirewallCalls[0].options.requestId,
      globalThis.__silmarilFirewallCalls[1].options.requestId,
    );
  });
});

test("plugin: Shadow is silent and preserves every supported boundary", async () => {
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

  const cases = [
    ["before_agent_run", { prompt: "unsafe prompt", sessionId: "s1" }, {}],
    ["before_tool_call", { toolName: "exec", params: { command: "unsafe" } }, { sessionId: "s1", toolCallId: "c1" }],
    ["after_tool_call", { toolName: "exec", result: "unsafe result" }, { sessionId: "s1", toolCallId: "c1" }],
    ["tool_result_persist", { message: { content: "unsafe result" } }, { sessionId: "s1", toolCallId: "c1" }],
    ["message_sending", { messageId: "m1", sessionId: "s1", content: "unsafe output" }, {}],
    ["reply_payload_sending", { messageId: "m2", sessionId: "s1", payload: { text: "unsafe output" } }, {}],
    ["subagent_delivery_target", { childGoal: "unsafe goal" }, { sessionId: "s1", childSessionId: "s2" }],
    ["subagent_spawned", { childGoal: "unsafe goal" }, { sessionId: "s1", childSessionId: "s2" }],
    ["subagent_ended", { childSummary: "unsafe summary" }, { sessionId: "s1", childSessionId: "s2" }],
  ];
  await withSilencedConsole(async () => {
    for (const [name, event, context] of cases) {
      const originalEvent = structuredClone(event);
      const originalContext = structuredClone(context);
      assert.equal(await hook(env, name)(event, context), undefined, name);
      assert.deepEqual(event, originalEvent, name);
      assert.deepEqual(context, originalContext, name);
    }
  });
});

test("decision: only an exact MALICIOUS prediction blocks", () => {
  const config = {
    apiKey: "k",
    apiUrl: "u",
    timeoutMs: 2500,
    mode: "block",
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
  }), true);
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }), true);
  assert.equal(t.shouldBlockToolCall(config, {
    primaryOutcome: "control_abuse",
  }), false);
  assert.equal(t.shouldBlockToolCall(config, {
    prediction: "malicious",
    blocked: true,
    score: 1,
  }), false);
  assert.equal(t.shouldBlockToolCall({ ...config, mode: "shadow" }, {
    prediction: "MALICIOUS",
    score: 0.99,
    threshold: 0.5,
    primaryOutcome: "control_abuse",
  }), false);
  assert.equal(t.effectiveMode({ ...config, mode: "shadow" }, {
    prediction: "MALICIOUS",
    mode: "block",
  }), "shadow");
  assert.equal(t.effectiveMode({ ...config, mode: undefined }, {
    prediction: "MALICIOUS",
  }), "shadow");
});

test("extractContentText handles deep and cyclic content safely", () => {
  let deep = { text: "safe leaf" };
  for (let i = 0; i < 80; i += 1) {
    deep = { content: deep };
  }
  assert.equal(t.extractContentText(deep), "");

  const cycle = {};
  cycle.content = cycle;
  assert.equal(t.extractContentText(cycle), "");

  assert.equal(t.extractContentText([{ text: "one" }, { content: { text: "two" } }]), "one\ntwo");
});

test("plugin: before_tool_call uses config captured before classifier await", async () => {
  const config = {
    apiKey: "k",
    apiUrl: "u",
    mode: "block",
  };
  const env = registerPlugin({ config });
  let release;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  globalThis.__silmarilFirewallClassify = async () => pending;

  await withSilencedConsole(async () => {
    const call = hook(env, "before_tool_call")({ toolName: "exec", params: { command: "true" } }, {});
    config.mode = "shadow";
    release({
      prediction: "MALICIOUS",
      score: 0.99,
      threshold: 0.5,
      primaryOutcome: "control_abuse",
    });
    assert.deepEqual(await call, {
      block: true,
      blockReason: "Silmaril Firewall blocked this request: Unsafe agent control attempt. Continue without using the blocked content.",
    });
  });
});

test("plugin: stable runtime config reuses one Firewall client", async () => {
  const config = { apiKey: "k", apiUrl: "u", timeoutMs: 777 };
  const env = registerPlugin({ config });
  await withSilencedConsole(async () => {
    await hook(env, "before_agent_run")({ prompt: "first" }, {});
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
  });
});

test("plugin: runtime config changes create a new Firewall client", async () => {
  const config = { apiKey: "k", apiUrl: "u1", timeoutMs: 777, blockMalicious: false };
  const env = registerPlugin({ config });
  await withSilencedConsole(async () => {
    await hook(env, "before_agent_run")({ prompt: "first" }, {});
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

test("plugin: legacy shadow and block flags preserve observe-only installs", async () => {
  const observeOnly = registerPlugin({
    config: {
      apiKey: "k",
      apiUrl: "u",
      shadowMode: false,
      blockMalicious: false,
    },
  });
  await withSilencedConsole(async () => {
    const result = await hook(observeOnly, "before_agent_run")(
      { prompt: "legacy observe-only" },
      {},
    );
    assert.equal(result, undefined);
  });
  assert.equal(
    globalThis.__silmarilFirewallInstances.at(-1).options.mode,
    "shadow",
  );

  const blocking = registerPlugin({
    config: {
      apiKey: "k",
      apiUrl: "u",
      shadowMode: false,
      blockMalicious: true,
    },
  });
  await withSilencedConsole(async () => {
    await hook(blocking, "before_agent_run")({ prompt: "legacy blocking" }, {});
  });
  assert.equal(
    globalThis.__silmarilFirewallInstances.at(-1).options.mode,
    "block",
  );
});

test("plugin: runtime config changes clear outbound classification decisions", async () => {
  const config = { apiKey: "k", apiUrl: "u1", timeoutMs: 777 };
  const env = registerPlugin({ config });
  await withSilencedConsole(async () => {
    await hook(env, "message_sending")({
      messageId: "delivery-1",
      sessionId: "session-1",
      content: "same outbound content",
    }, {});
    assert.equal(globalThis.__silmarilFirewallCalls.length, 1);

    config.apiUrl = "u2";
    await hook(env, "reply_payload_sending")({
      messageId: "delivery-1",
      sessionId: "session-1",
      payload: { text: "same outbound content" },
    }, {});
  });

  assert.equal(globalThis.__silmarilFirewallCalls.length, 2);
  assert.equal(globalThis.__silmarilFirewallInstances.length, 2);
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
    const promptResult = await hook(env, "before_agent_run")({ prompt: "risk", runId: "run-error" }, {});
    const toolResult = await hook(env, "before_tool_call")({ params: { a: 1 } }, {});
    hook(env, "tool_result_persist")({ message: { content: "tool result" } }, {});
    const messageResult = await hook(env, "message_sending")({ to: "user", content: "assistant result" }, {});
    await sleep(0);
    assert.equal(promptResult, undefined);
    assert.equal(toolResult, undefined);
    assert.equal(messageResult, undefined);
    assert.ok(errors.some((line) => line.includes("before_agent_run error:")));
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
    errorMessage: "network_error_ECONNREFUSED",
  });
  assert.deepEqual(t.safeErrorFields(new Error("connect ECONNREFUSED raw classified content")), {
    errorType: "Error",
    errorMessage: "network_error_ECONNREFUSED",
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

test("local evidence: schema is V1-compatible and excludes raw classified bytes", () => {
  const rawCanary = "OPENCLAW_SECRET_CANARY raw prompt and tool args";
  const eventInput = {
    host: "openClaw",
    hook: "pre_tool",
    mode: "block",
    rawText: rawCanary,
    requestIdentity: "request-1",
    sessionIdentity: "session-1",
    toolName: "exec",
    classification: {
      prediction: "MALICIOUS",
      score: 0.93,
      threshold: 0.5,
      primaryOutcome: "secret_exposure",
    },
    policyDecision: "block",
    nativeAction: "block_returned",
    producer: "firewall-plugin",
    producerVersion: "1.2.2",
    pluginVersion: "1.2.2",
    policyVersion: "openclaw-plugin-policy-v1",
  };
  const event = t.buildLocalProtectionEvent({
    ...eventInput,
    occurredAt: new Date("2026-07-24T18:00:00.000Z"),
  });
  const retry = t.buildLocalProtectionEvent({
    ...eventInput,
    occurredAt: new Date("2026-07-24T18:00:05.000Z"),
  });

  assert.equal(event.schemaVersion, 1);
  assert.match(event.id, /^protection-event:[a-f0-9]{64}$/);
  assert.equal(event.occurredAt, "2026-07-24T18:00:00.000Z");
  assert.equal(event.host, "openClaw");
  assert.equal(event.hook, "pre_tool");
  assert.equal(event.mode, "block");
  assert.match(event.requestFingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.match(event.sessionFingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal(event.riskClass, "credential_exposure");
  assert.equal(event.attemptedConsequence.category, "credential_exposure");
  assert.equal(event.prediction, "malicious");
  assert.equal(event.modelScore, 0.93);
  assert.equal(event.modelThreshold, 0.5);
  assert.equal(event.policyDecision, "block");
  assert.equal(event.nativeAction, "block_returned");
  assert.equal(event.outcome, "not_observed");
  assert.equal(event.evidenceTruth, "native_response_returned");
  assert.equal(event.evidenceCompleteness, "partial");
  assert.equal(event.provenance.pluginVersion, "1.2.2");
  assert.equal(event.id, retry.id);
  assert.equal(event.requestFingerprint, retry.requestFingerprint);
  assert.equal(event.sessionFingerprint, retry.sessionFingerprint);
  assert.equal(JSON.stringify(event).includes(rawCanary), false);
  assert.equal(JSON.stringify(event).includes("raw prompt"), false);
  assert.equal(
    t.resolveLocalEventDirectory({}, "/Users/tester"),
    "/Users/tester/Library/Application Support/Silmaril/Evidence/incoming",
  );
  assert.equal(
    t.resolveLocalEventDirectory(
      { SILMARIL_LOCAL_EVENT_DIR: " /tmp/silmaril-events " },
      "/Users/tester",
    ),
    "/tmp/silmaril-events",
  );
});

test("local evidence: writer uses private atomic single-file publication", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "silmaril-openclaw-evidence-"));
  const directory = path.join(root, "incoming");
  try {
    const destination = await t.emitLocalProtectionEvent({
      host: "openClaw",
      hook: "user_input",
      mode: "shadow",
      rawText: "OPENCLAW_ATOMIC_SECRET_CANARY",
      requestIdentity: "request-atomic",
      sessionIdentity: "session-atomic",
      classification: {
        prediction: "MALICIOUS",
        score: 0.88,
        threshold: 0.5,
        primaryOutcome: "control_abuse",
      },
      policyDecision: "monitor",
      nativeAction: "allowed",
      producer: "firewall-plugin",
      producerVersion: "1.2.2",
      pluginVersion: "1.2.2",
      policyVersion: "openclaw-plugin-policy-v1",
    }, { directory });

    const entries = await readdir(directory);
    assert.deepEqual(entries, [path.basename(destination)]);
    assert.equal(entries[0].endsWith(".json"), true);
    assert.equal(entries.some((entry) => entry.endsWith(".tmp")), false);
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    const destinationStat = await stat(destination);
    assert.equal(destinationStat.mode & 0o777, 0o600);
    assert.ok(destinationStat.size > 0 && destinationStat.size < 64 * 1024);
    const encoded = await readFile(destination, "utf8");
    assert.equal(encoded.includes("OPENCLAW_ATOMIC_SECRET_CANARY"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("local evidence: Repair marker has a stable opaque fingerprint", () => {
  const marker = "silmaril-runtime-check:83a4c35e-da2d-47c6-9738-5ef7502600ca";
  const event = t.buildLocalProtectionEvent({
    host: "openClaw",
    hook: "user_input",
    mode: "shadow",
    rawText: `Reply with OK only. ${marker}`,
    classification: { prediction: "BENIGN", primaryOutcome: "benign" },
    policyDecision: "allow",
    nativeAction: "allowed",
    producer: "firewall-plugin",
    producerVersion: "1.2.2",
    pluginVersion: "1.2.2",
    policyVersion: "openclaw-plugin-policy-v1",
  });
  const serialized = JSON.stringify(event);
  assert.equal(
    event.requestFingerprint,
    createHash("sha256").update(marker).digest("hex"),
  );
  assert.equal(serialized.includes(marker), false);
});

test("local evidence: Block and Shadow preserve distinct native action semantics", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "silmaril-openclaw-modes-"));
  const savedDirectory = process.env.SILMARIL_LOCAL_EVENT_DIR;
  try {
    globalThis.__silmarilFirewallClassify = async () => ({
      prediction: "MALICIOUS",
      score: 0.99,
      threshold: 0.5,
      primaryOutcome: "control_abuse",
    });

    const blockDirectory = path.join(root, "block");
    process.env.SILMARIL_LOCAL_EVENT_DIR = blockDirectory;
    const blockPlugin = registerPlugin({
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
    const blocked = await withSilencedConsole(() => hook(blockPlugin, "before_tool_call")(
      { toolName: "exec", params: { command: "OPENCLAW_BLOCK_SECRET_CANARY" } },
      { sessionId: "session-block", toolCallId: "call-block" },
    ));
    assert.equal(blocked.block, true);
    const blockEvent = await readOnlyJSONEvent(blockDirectory);
    assert.equal(blockEvent.mode, "block");
    assert.equal(blockEvent.policyDecision, "block");
    assert.equal(blockEvent.nativeAction, "block_returned");
    assert.equal(blockEvent.outcome, "not_observed");
    assert.equal(blockEvent.evidenceTruth, "native_response_returned");
    assert.equal(JSON.stringify(blockEvent).includes("OPENCLAW_BLOCK_SECRET_CANARY"), false);

    const unavailableDirectory = path.join(root, "tool-result-unavailable");
    process.env.SILMARIL_LOCAL_EVENT_DIR = unavailableDirectory;
    await withSilencedConsole(() => hook(blockPlugin, "after_tool_call")(
      { toolName: "exec", result: "OPENCLAW_TOOL_RESULT_SECRET_CANARY" },
      { sessionId: "session-block", toolCallId: "call-result" },
    ));
    const unavailableEvent = await readOnlyJSONEvent(unavailableDirectory);
    assert.equal(unavailableEvent.mode, "block");
    assert.equal(unavailableEvent.policyDecision, "monitor");
    assert.equal(unavailableEvent.nativeAction, "unavailable");
    assert.equal(unavailableEvent.blockUnavailable, true);
    assert.equal(JSON.stringify(unavailableEvent).includes("OPENCLAW_TOOL_RESULT_SECRET_CANARY"), false);

    const shadowDirectory = path.join(root, "shadow");
    process.env.SILMARIL_LOCAL_EVENT_DIR = shadowDirectory;
    const shadowPlugin = registerPlugin({
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
    const allowed = await withSilencedConsole(() => hook(shadowPlugin, "before_tool_call")(
      { toolName: "exec", params: { command: "OPENCLAW_SHADOW_SECRET_CANARY" } },
      { sessionId: "session-shadow", toolCallId: "call-shadow" },
    ));
    assert.equal(allowed, undefined);
    const shadowEvent = await readOnlyJSONEvent(shadowDirectory);
    assert.equal(shadowEvent.mode, "shadow");
    assert.equal(shadowEvent.policyDecision, "monitor");
    assert.equal(shadowEvent.nativeAction, "allowed");
    assert.equal(shadowEvent.outcome, "not_observed");
    assert.equal(JSON.stringify(shadowEvent).includes("OPENCLAW_SHADOW_SECRET_CANARY"), false);
  } finally {
    if (savedDirectory === undefined) {
      delete process.env.SILMARIL_LOCAL_EVENT_DIR;
    } else {
      process.env.SILMARIL_LOCAL_EVENT_DIR = savedDirectory;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("local evidence: spool failure cannot weaken native blocking", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "silmaril-openclaw-failure-"));
  const invalidDirectory = path.join(root, "not-a-directory");
  const savedDirectory = process.env.SILMARIL_LOCAL_EVENT_DIR;
  await writeFile(invalidDirectory, "occupied");
  try {
    process.env.SILMARIL_LOCAL_EVENT_DIR = invalidDirectory;
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
      primaryOutcome: "system_compromise",
    });

    const result = await withSilencedConsole(() => hook(env, "before_tool_call")(
      { toolName: "exec", params: { command: "unsafe" } },
      { sessionId: "session-failure", toolCallId: "call-failure" },
    ));
    assert.equal(result.block, true);
    assert.match(result.blockReason, /Silmaril Firewall blocked/);
    await sleep(10);
  } finally {
    if (savedDirectory === undefined) {
      delete process.env.SILMARIL_LOCAL_EVENT_DIR;
    } else {
      process.env.SILMARIL_LOCAL_EVENT_DIR = savedDirectory;
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("source invariant: runtime has no legacy risk cache, wrappers, or prompt mutation", async () => {
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
