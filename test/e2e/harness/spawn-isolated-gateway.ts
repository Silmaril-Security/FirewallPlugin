import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { installApiInterceptor, type ApiInterceptor } from "./api-interceptor";
import { auditCanarySinks } from "./audit-sinks";
import { delay, ensureDir, getFreePort, readNdjson, waitFor } from "./common";
import { startFakeS3, type FakeS3 } from "./fake-s3";
import { startFixtureServer, type FixtureServer } from "./fixture-server";
import { startMockClassifier, TEST_SILMARIL_API_KEY, type MockClassifier } from "./mock-classifier";
import { startMockFpWebhook, type MockFpWebhook } from "./mock-fp-webhook";
import { startMockTelegram, type MockTelegram } from "./mock-telegram";
import { assertNoExternalFetch } from "./no-egress-test";

export type OpenClawAgentResult = {
  sessionId: string;
  agentId: string;
  runId?: string;
  status?: string;
  text: string;
  rawVisibleText: string;
  stdout: string;
  stderr: string;
  parsed: unknown;
};

export type IsolatedGateway = {
  name: string;
  port: number;
  rootDir: string;
  homeDir: string;
  stateDir: string;
  configPath: string;
  openclawRepo: string;
  child: ChildProcessWithoutNullStreams;
  stdout: string[];
  stderr: string[];
  mockClassifier: MockClassifier;
  fixtureServer: FixtureServer;
  fpWebhook: MockFpWebhook;
  fakeS3: FakeS3;
  mockTelegram?: MockTelegram;
  apiInterceptor: ApiInterceptor;
  env: NodeJS.ProcessEnv;
  openclawAgent(prompt: string, options?: OpenClawAgentOptions): Promise<OpenClawAgentResult>;
  readSinks(canaries: readonly string[]): Promise<Awaited<ReturnType<typeof auditCanarySinks>>>;
  restart(): Promise<IsolatedGateway>;
  kill(): Promise<void>;
};

export type OpenClawAgentOptions = {
  agentId?: "main" | "alt" | string;
  sessionId?: string;
  timeoutSeconds?: number;
};

export type SpawnIsolatedGatewayOptions = {
  name?: string;
  openclawRepo?: string;
  homeDir?: string;
  model?: string;
  enableTelegram?: boolean;
  keepHomeDirOnKill?: boolean;
  runNoEgressSmoke?: boolean;
};

const DEFAULT_MODEL = "anthropic/claude-haiku-4-5";
const GATEWAY_START_TIMEOUT_MS = 300_000;
const GATEWAY_STOP_TIMEOUT_MS = 2_000;

export async function spawnIsolatedGateway(
  options: SpawnIsolatedGatewayOptions = {},
): Promise<IsolatedGateway> {
  const name = options.name ?? `firewall-${randomUUID().slice(0, 8)}`;
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), `silmaril-${name}-`));
  const homeDir = options.homeDir ?? path.join(rootDir, "home");
  const stateDir = path.join(homeDir, ".openclaw", "state");
  // OpenClaw 2026.4.x reads its config from $OPENCLAW_STATE_DIR/openclaw.json
  // (not $HOME/.openclaw/openclaw.json). Setting OPENCLAW_CONFIG_PATH to
  // override that path makes the gateway hang silently after "starting...",
  // so we land the config where OpenClaw will read it natively.
  const configPath = path.join(stateDir, "openclaw.json");
  await ensureDir(path.dirname(configPath));
  await ensureDir(stateDir);

  const openclawRepo = resolveOpenClawRepo(options.openclawRepo);
  await assertOpenClawRepoReady(openclawRepo);
  const pluginRoot = path.resolve(process.cwd());
  const port = await getFreePort();

  const fixtureServer = await startFixtureServer();
  const fakeS3 = await startFakeS3({ rootDir });
  const mockClassifier = await startMockClassifier({ rootDir, apiKey: TEST_SILMARIL_API_KEY });
  const classifierConfig = resolveClassifierConfig(mockClassifier);
  const fpWebhook = await startMockFpWebhook({ rootDir });
  const mockTelegram = options.enableTelegram ? await startMockTelegram({ rootDir }) : undefined;

  const fpReviewLog = path.join(rootDir, "fp-review-uploads.ndjson");
  const uploadLeaseLog = path.join(rootDir, "upload-lease.ndjson");
  const apiInterceptor = installApiInterceptor({
    fakeS3Url: fakeS3.uploadUrl,
    fpReviewLog,
    uploadLeaseLog,
  });
  if (options.runNoEgressSmoke !== false) {
    await assertNoExternalFetch();
  }

  await writeGatewayConfig({
    configPath,
    stateDir,
    pluginRoot,
    port,
    model: options.model ?? process.env.OPENCLAW_E2E_MODEL ?? DEFAULT_MODEL,
    classifierApiKey: classifierConfig.apiKey,
    classifierUrl: classifierConfig.apiUrl,
    fpWebhookUrl: fpWebhook.webhookUrl,
    fpReviewFile: path.join(rootDir, "fp-review.ndjson"),
    mockTelegram,
  });

  const stdout: string[] = [];
  const stderr: string[] = [];
  const env = buildGatewayEnv({
    homeDir,
    stateDir,
    configPath,
    fakeS3Url: fakeS3.uploadUrl,
    fpReviewLog,
    uploadLeaseLog,
    enableTelegram: !!mockTelegram,
  });

  const child = spawnGatewayProcess(openclawRepo, port, env, stdout, stderr);

  try {
    await waitForPortOpen(child, stdout, stderr, port, GATEWAY_START_TIMEOUT_MS);
  } catch (err) {
    console.error(`\n=== gateway startup failed on port ${port} ===`);
    console.error(`--- stdout ---\n${stdout.join("")}`);
    console.error(`--- stderr ---\n${stderr.join("")}`);
    console.error(`--- exit code ---\n${child.exitCode}\n`);
    await stopChild(child);
    throw err;
  }

  let currentChild = child;
  let currentStdout = stdout;
  let currentStderr = stderr;

  const gateway: IsolatedGateway = {
    name,
    port,
    rootDir,
    homeDir,
    stateDir,
    configPath,
    openclawRepo,
    child: currentChild,
    stdout: currentStdout,
    stderr: currentStderr,
    mockClassifier,
    fixtureServer,
    fpWebhook,
    fakeS3,
    mockTelegram,
    apiInterceptor,
    env,
    openclawAgent: (prompt, agentOptions) =>
      runOpenClawAgent(openclawRepo, env, rootDir, prompt, agentOptions),
    readSinks: (canaries) => auditCanarySinks({ rootDir, homeDir, canaries }),
    restart: async () => {
      await stopChild(currentChild);
      const nextStdout: string[] = [];
      const nextStderr: string[] = [];
      const nextChild = spawnGatewayProcess(openclawRepo, port, env, nextStdout, nextStderr);
      await waitForPortOpen(nextChild, nextStdout, nextStderr, port, GATEWAY_START_TIMEOUT_MS);
      currentChild = nextChild;
      currentStdout = nextStdout;
      currentStderr = nextStderr;
      gateway.child = currentChild;
      gateway.stdout = currentStdout;
      gateway.stderr = currentStderr;
      return gateway;
    },
    kill: async () => {
      await stopChild(currentChild);
      await apiInterceptor.restore();
      await mockClassifier.close();
      await fixtureServer.close();
      await fpWebhook.close();
      await fakeS3.close();
      await mockTelegram?.close();
      await fs.writeFile(path.join(rootDir, "gateway.stdout.log"), currentStdout.join(""), "utf8");
      await fs.writeFile(path.join(rootDir, "gateway.stderr.log"), currentStderr.join(""), "utf8");
      if (!options.keepHomeDirOnKill) {
        await fs.rm(homeDir, { recursive: true, force: true });
      }
    },
  };

  return gateway;
}

export async function readClassifierCaptures(gateway: IsolatedGateway): Promise<unknown[]> {
  return readNdjson(gateway.mockClassifier.captureFile);
}

export async function readTelegramCaptures(gateway: IsolatedGateway): Promise<unknown[]> {
  return gateway.mockTelegram ? readNdjson(gateway.mockTelegram.captureFile) : [];
}

function resolveOpenClawRepo(explicit?: string): string {
  const candidate =
    explicit ??
    process.env.OPENCLAW_E2E_REPO ??
    path.resolve(process.cwd(), "..", "openclaw-clean");
  return path.resolve(candidate);
}

async function assertOpenClawRepoReady(openclawRepo: string): Promise<void> {
  const entry = path.join(openclawRepo, "dist", "index.js");
  try {
    await fs.access(entry);
  } catch {
    throw new Error(
      `OpenClaw E2E repo is not built or not found at ${openclawRepo}. Set OPENCLAW_E2E_REPO or build the sibling openclaw-clean repo first.`,
    );
  }
}

async function writeGatewayConfig(params: {
  configPath: string;
  stateDir: string;
  pluginRoot: string;
  port: number;
  model: string;
  classifierApiKey: string;
  classifierUrl: string;
  fpWebhookUrl: string;
  fpReviewFile: string;
  mockTelegram?: MockTelegram;
}): Promise<void> {
  const workspace = path.join(path.dirname(params.configPath), "workspace");
  const config = {
    agents: {
      defaults: {
        workspace,
        model: { primary: params.model },
        models: {
          [params.model]: {},
          "anthropic/claude-sonnet-4-6": {},
          "anthropic/claude-haiku-4-5": {},
        },
        compaction: { mode: "safeguard" },
        skipBootstrap: true,
      },
      list: [
        { id: "main" },
        {
          id: "alt",
          name: "alt",
          workspace: path.join(workspace, "alt"),
          agentDir: path.join(params.stateDir, "agents", "alt", "agent"),
        },
      ],
    },
    gateway: {
      mode: "local",
      auth: { mode: "none", token: "" },
      port: params.port,
      bind: "loopback",
      controlUi: { enabled: false },
      tailscale: { mode: "off", resetOnExit: false },
    },
    hooks: { enabled: true, token: `firewall-e2e-hooks-${randomUUID()}`, path: "/hooks" },
    session: { dmScope: "per-channel-peer" },
    tools: {
      profile: "coding",
      alsoAllow: [
        "firewall_report_false_positive",
        "web_fetch",
        "bash",
        "browser",
        "web_search",
        "github_issue_read",
      ],
      web: {
        fetch: {
          enabled: false,
          maxChars: 20000,
          maxResponseBytes: 10_000_000,
          timeoutSeconds: 30,
          maxRedirects: 3,
        },
      },
    },
    channels: {
      telegram: params.mockTelegram
        ? {
            enabled: true,
            botToken: params.mockTelegram.token,
            apiRoot: params.mockTelegram.apiRoot,
            actions: { poll: true, sendMessage: true },
          }
        : { enabled: false },
    },
    plugins: {
      entries: {
        google: { enabled: false },
        "firewall-plugin": {
          enabled: true,
          config: {
            apiKey: params.classifierApiKey,
            silmarilApiKey: params.classifierApiKey,
            userEmail: "firewall-e2e@example.invalid",
            apiUrl: params.classifierUrl,
            falsePositiveReportUrl: params.fpWebhookUrl,
            falsePositiveReviewFile: params.fpReviewFile,
            enableWebFetchWrapper: true,
            webFetch: {
              dangerouslyAllowPrivateNetwork: true,
            },
            llmFalsePositiveReviewThreshold: 0.6,
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
          },
        },
      },
      load: { paths: [params.pluginRoot] },
      installs: {
        "firewall-plugin": {
          source: "path",
          sourcePath: params.pluginRoot,
          installPath: params.pluginRoot,
          version: "1.0.0",
          installedAt: new Date().toISOString(),
        },
      },
    },
  };
  await ensureDir(path.dirname(params.configPath));
  await fs.writeFile(params.configPath, JSON.stringify(config, null, 2), "utf8");
}

function resolveClassifierConfig(mockClassifier: MockClassifier): { apiKey: string; apiUrl: string } {
  const liveApiKey = process.env.FIREWALL_E2E_CLASSIFIER_API_KEY;
  const liveApiUrl = process.env.FIREWALL_E2E_CLASSIFIER_URL;
  if (liveApiKey && liveApiUrl) {
    return { apiKey: liveApiKey, apiUrl: liveApiUrl };
  }
  return { apiKey: TEST_SILMARIL_API_KEY, apiUrl: mockClassifier.classifyUrl };
}

function buildGatewayEnv(params: {
  homeDir: string;
  stateDir: string;
  configPath: string;
  fakeS3Url: string;
  fpReviewLog: string;
  uploadLeaseLog: string;
  enableTelegram: boolean;
}): NodeJS.ProcessEnv {
  const preload = path.resolve(process.cwd(), "test", "e2e", "harness", "api-interceptor-preload.mjs");
  const nodeOptions = [process.env.NODE_OPTIONS, `--import ${pathToFileURL(preload).href}`]
    .filter(Boolean)
    .join(" ");
  return {
    ...process.env,
    HOME: params.homeDir,
    USERPROFILE: params.homeDir,
    // OPENCLAW_CONFIG_PATH intentionally not set: in OpenClaw 2026.4.x setting
    // it makes the gateway hang silently after "starting...". The harness
    // writes its config to $OPENCLAW_STATE_DIR/openclaw.json instead, which
    // OpenClaw picks up natively.
    OPENCLAW_STATE_DIR: params.stateDir,
    OPENCLAW_GATEWAY_TOKEN: "",
    OPENCLAW_GATEWAY_PASSWORD: "",
    OPENCLAW_SKIP_GMAIL_WATCHER: "1",
    OPENCLAW_SKIP_CRON: "1",
    OPENCLAW_SKIP_BROWSER_CONTROL_SERVER: "1",
    OPENCLAW_SKIP_CANVAS_HOST: "1",
    // OPENCLAW_TEST_MINIMAL_GATEWAY intentionally unset: under 2026.4.x it
    // skips plugin loading entirely, so the firewall plugin would never
    // register and the scenarios under test would all see 0 plugins.
    OPENCLAW_SKIP_CHANNELS: params.enableTelegram ? "0" : "1",
    FIREWALL_E2E_FAKE_S3_URL: params.fakeS3Url,
    FIREWALL_E2E_FP_REVIEW_UPLOADS: params.fpReviewLog,
    FIREWALL_E2E_UPLOAD_LEASE_LOG: params.uploadLeaseLog,
    NODE_OPTIONS: nodeOptions,
    VITEST: "1",
  };
}

async function runPluginInstall(
  openclawRepo: string,
  env: NodeJS.ProcessEnv,
  pluginRoot: string,
): Promise<void> {
  const entry = path.join(openclawRepo, "dist", "index.js");
  const startedAt = Date.now();
  console.error(`[harness] plugins install start (pluginRoot=${pluginRoot})`);
  // The api-interceptor-preload .mjs leaves an undici dispatcher attached that
  // keeps the install command's event loop alive long after its work finishes,
  // so the install hangs until SIGKILL. The install doesn't need any of the
  // mocks (it's offline metadata work), so strip NODE_OPTIONS for this child.
  const installEnv: NodeJS.ProcessEnv = { ...env };
  delete installEnv.NODE_OPTIONS;
  delete installEnv.VITEST;
  delete installEnv.VITEST_POOL_ID;
  delete installEnv.VITEST_WORKER_ID;
  console.error(`[harness] install env scrubbed`);
  const stdoutStream = require("node:fs").openSync(`/tmp/install-${Date.now()}.out`, "w");
  const child = spawn(
    process.execPath,
    [entry, "plugins", "install", "-l", pluginRoot, "--dangerously-force-unsafe-install"],
    { cwd: openclawRepo, env: installEnv, stdio: ["ignore", stdoutStream, stdoutStream], windowsHide: true, detached: false },
  );
  const stdout: string[] = [];
  const stderr: string[] = [];
  const installTimeoutMs = 120_000;
  const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    const t = setTimeout(() => {
      console.error(`[harness] plugins install timeout after ${installTimeoutMs}ms; killing`);
      child.kill("SIGKILL");
    }, installTimeoutMs);
    child.once("exit", (code, signal) => {
      clearTimeout(t);
      resolve({ code, signal });
    });
  });
  console.error(`[harness] plugins install done (code=${exit.code} ${Date.now() - startedAt}ms)`);
  if (exit.code !== 0) {
    throw new Error(
      `openclaw plugins install exited code=${exit.code} signal=${exit.signal}\n--- stdout ---\n${stdout.join("")}\n--- stderr ---\n${stderr.join("")}`,
    );
  }
}

function spawnGatewayProcess(
  openclawRepo: string,
  port: number,
  env: NodeJS.ProcessEnv,
  stdout: string[],
  stderr: string[],
): ChildProcessWithoutNullStreams {
  const entry = path.join(openclawRepo, "dist", "index.js");
  const child = spawn(
    process.execPath,
    [entry, "gateway", "--port", String(port), "--bind", "loopback", "--allow-unconfigured"],
    {
      cwd: openclawRepo,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  const tailPath = process.env.FIREWALL_E2E_GATEWAY_TAIL;
  child.stdout.on("data", (chunk) => {
    const s = String(chunk);
    stdout.push(s);
    if (tailPath) require("node:fs").appendFileSync(tailPath, s);
  });
  child.stderr.on("data", (chunk) => {
    const s = String(chunk);
    stderr.push(s);
    if (tailPath) require("node:fs").appendFileSync(tailPath, `[stderr] ${s}`);
  });
  return child;
}

async function runOpenClawAgent(
  openclawRepo: string,
  env: NodeJS.ProcessEnv,
  rootDir: string,
  prompt: string,
  options: OpenClawAgentOptions = {},
): Promise<OpenClawAgentResult> {
  const agentId = options.agentId ?? "main";
  const sessionId = options.sessionId ?? `firewall-e2e-${agentId}-${randomUUID()}`;
  const timeoutSeconds = options.timeoutSeconds ?? 300;
  const entry = path.join(openclawRepo, "dist", "index.js");
  const args = [
    entry,
    "agent",
    "--agent",
    agentId,
    "--session-id",
    sessionId,
    "--message",
    prompt,
    "--json",
    "--timeout",
    String(timeoutSeconds),
  ];
  const started = Date.now();
  const stdout: string[] = [];
  const stderr: string[] = [];

  const child = spawn(process.execPath, args, {
    cwd: openclawRepo,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => stdout.push(String(chunk)));
  child.stderr.on("data", (chunk) => stderr.push(String(chunk)));

  const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  const stdoutText = stdout.join("");
  const stderrText = stderr.join("");
  const logBase = path.join(rootDir, `agent-${agentId}-${sessionId}-${started}`);
  await fs.writeFile(`${logBase}.stdout.log`, stdoutText, "utf8");
  await fs.writeFile(`${logBase}.stderr.log`, stderrText, "utf8");

  if (exit.code !== 0) {
    throw new Error(
      `openclaw agent exited with code=${exit.code} signal=${exit.signal}\n--- stdout ---\n${stdoutText}\n--- stderr ---\n${stderrText}`,
    );
  }

  const parsed = parseTrailingJson(stdoutText);
  const text = extractAgentText(parsed);
  return {
    sessionId,
    agentId,
    runId: isObject(parsed) && typeof parsed.runId === "string" ? parsed.runId : undefined,
    status: isObject(parsed) && typeof parsed.status === "string" ? parsed.status : undefined,
    text,
    rawVisibleText: extractVisibleText(parsed) ?? text,
    stdout: stdoutText,
    stderr: stderrText,
    parsed,
  };
}

async function waitForPortOpen(
  proc: ChildProcessWithoutNullStreams,
  stdout: string[],
  stderr: string[],
  port: number,
  timeoutMs: number,
): Promise<void> {
  await waitFor(
    async () => {
      if (proc.exitCode !== null) {
        throw new Error(
          `gateway exited before listening (code=${proc.exitCode}, signal=${proc.signalCode})\n--- stdout ---\n${stdout.join("")}\n--- stderr ---\n${stderr.join("")}`,
        );
      }
      return canConnect(port);
    },
    { timeoutMs, intervalMs: 25, message: `timeout waiting for gateway on port ${port}` },
  );
}

async function canConnect(port: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function stopChild(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode === null && !child.killed) {
    try {
      child.kill("SIGTERM");
    } catch {
      // ignore
    }
  }
  const exited = await Promise.race([
    new Promise<boolean>((resolve) => {
      if (child.exitCode !== null) return resolve(true);
      child.once("exit", () => resolve(true));
    }),
    delay(GATEWAY_STOP_TIMEOUT_MS).then(() => false),
  ]);
  if (!exited && child.exitCode === null && !child.killed) {
    try {
      child.kill("SIGKILL");
    } catch {
      // ignore
    }
  }
}

function parseTrailingJson(stdout: string): unknown {
  const trimmed = stdout.trim();
  const start = trimmed.lastIndexOf("\n{");
  const candidate = start >= 0 ? trimmed.slice(start + 1) : trimmed;
  try {
    return JSON.parse(candidate);
  } catch {
    const match = /(\{\s*"runId"[\s\S]*\})\s*$/.exec(trimmed);
    if (match?.[1]) return JSON.parse(match[1]);
    throw new Error(`could not parse OpenClaw JSON output:\n${stdout}`);
  }
}

function extractAgentText(parsed: unknown): string {
  if (!isObject(parsed)) return "";
  const payloads = (parsed as { result?: { payloads?: Array<{ text?: unknown }> } }).result?.payloads;
  if (Array.isArray(payloads)) {
    return payloads.map((payload) => (typeof payload.text === "string" ? payload.text : "")).join("\n").trim();
  }
  return extractVisibleText(parsed) ?? "";
}

function extractVisibleText(parsed: unknown): string | undefined {
  if (!isObject(parsed)) return undefined;
  const visible = (parsed as { result?: { meta?: { finalAssistantVisibleText?: unknown } } }).result?.meta
    ?.finalAssistantVisibleText;
  return typeof visible === "string" ? visible : undefined;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object";
}
