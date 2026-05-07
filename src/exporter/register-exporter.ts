import { appendFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { registerHookTraceHandlers, writeHookTraceEvent } from "./hook-trace";
import {
  ensureQueueDirectories,
  enqueueEvent,
  prepareEvent,
  purgeLegacyState,
  recoverStaleBatches,
} from "./simple-queue";
import {
  FIXED_API_KEY_PATH_ID,
  STALE_BATCH_MS,
  type ExporterLogger,
  type ExporterPaths,
  type ExporterRuntime,
  type FirewallExportEventInput,
  type FirewallExporter,
} from "./types";
import { Uploader } from "./uploader";

type PluginApi = {
  logger?: {
    info?: (message: string) => void;
    warn?: (message: string) => void;
    error?: (message: string) => void;
  };
  on?: (eventName: string, handler: (...args: unknown[]) => Promise<void> | void) => void;
};

type ExporterOptions = {
  apiKey: string;
  apiUrl: string;
};

export function createFirewallExporter(api: PluginApi, options: ExporterOptions): FirewallExporter {
  const logger = new FileBackedExporterLogger(api);
  let runtime: ExporterRuntime | undefined;
  let runtimePromise: Promise<ExporterRuntime> | undefined;
  let uploader: Uploader | undefined;
  let stopPromise: Promise<void> | undefined;
  let startPromise: Promise<void> | undefined;

  async function ensureRuntime(ctx?: unknown): Promise<ExporterRuntime> {
    if (runtime) return runtime;
    if (runtimePromise) return runtimePromise;

    runtimePromise = (async () => {
      const paths = resolveExporterPaths(ctx, api);
      logger.setLogPath(paths.logPath);
      await ensureQueueDirectories(paths);
      await purgeLegacyState(paths, logger);
      const built: ExporterRuntime = {
        apiKey: options.apiKey,
        apiKeyPathId: FIXED_API_KEY_PATH_ID,
        host: safeHost(os.hostname()),
        paths,
        logger,
      };
      runtime = built;
      return built;
    })().catch((err) => {
      runtimePromise = undefined;
      throw err;
    });

    return runtimePromise;
  }

  async function startUploader(ctx?: unknown): Promise<void> {
    if (uploader) return;
    if (startPromise) return startPromise;

    startPromise = (async () => {
      const rt = await ensureRuntime(ctx);
      if (uploader) return;

      await recoverStaleBatches(rt.paths, logger, STALE_BATCH_MS);
      uploader = new Uploader(rt);
      uploader.start();
      logger.info(`exporter started at ${rt.paths.exportDir}`);
      void uploader.kick().catch((err) => {
        logger.warn("initial upload attempt failed; batches will retry later", err);
      });
    })();

    try {
      await startPromise;
    } finally {
      startPromise = undefined;
    }
  }

  const exporter: FirewallExporter = {
    async startFromGateway(ctx?: unknown): Promise<void> {
      try {
        await startUploader(ctx);
      } catch (err) {
        logger.warn("exporter startup failed; events still durable on disk", err);
      }
    },

    async stop(): Promise<void> {
      if (stopPromise) return stopPromise;
      const currentUploader = uploader;
      uploader = undefined;
      stopPromise = (async () => {
        if (currentUploader) {
          await currentUploader.stop();
        }
        logger.info("exporter stopped");
      })();
      return stopPromise;
    },

    async writeEvent(input: FirewallExportEventInput): Promise<void> {
      try {
        const rt = await ensureRuntime();
        const event = prepareEvent(input, rt);
        await enqueueEvent(rt.paths, event);
      } catch (err) {
        logger.warn("exporter event dropped: enqueue failed", err);
      }
      // Lazy-start fallback: when OpenClaw lazy-loads the plugin AFTER
      // gateway_start has already fired, our gateway_start listener never
      // runs. Kicking startUploader from writeEvent ensures the uploader
      // eventually comes up. Disk durability is already complete above, so
      // a startup failure here doesn't lose events. Single-flight via the
      // startPromise guard inside startUploader.
      if (!uploader) {
        void startUploader().catch((err) => {
          logger.warn("lazy uploader start failed; events remain on disk", err);
        });
      }
    },
  };

  registerHookTraceHandlers(api, exporter, logger);

  api.on?.("gateway_start", (event, ctx) => {
    void (async () => {
      try {
        await startUploader(ctx);
      } catch (err) {
        logger.warn("exporter failed to start in background", err);
      }
      await writeHookTraceEvent(exporter, "gateway_start", event, ctx, logger);
    })();
  });

  api.on?.("gateway_stop", async (event, ctx) => {
    await writeHookTraceEvent(exporter, "gateway_stop", event, ctx, logger);
    await exporter.stop();
  });

  return exporter;
}

function resolveExporterPaths(ctx: unknown, api: PluginApi): ExporterPaths {
  const stateDir =
    process.env.OPENCLAW_STATE_DIR ??
    getNestedString(ctx, ["stateDir"]) ??
    getNestedString(ctx, ["openclawStateDir"]) ??
    getNestedString(ctx, ["paths", "stateDir"]) ??
    getNestedString(ctx, ["state", "dir"]) ??
    getNestedString(api, ["stateDir"]) ??
    path.join(os.homedir(), ".openclaw");

  const exportDir = path.join(stateDir, "firewall-plugin", "export");
  return {
    stateDir,
    exportDir,
    pendingDir: path.join(exportDir, "pending"),
    inflightDir: path.join(exportDir, "inflight"),
    tmpDir: path.join(exportDir, "tmp"),
    logsDir: path.join(exportDir, "logs"),
    leasePath: path.join(exportDir, "upload-lease.json"),
    logPath: path.join(exportDir, "logs", "exporter.log"),
  };
}

function getNestedString(value: unknown, pathParts: string[]): string | undefined {
  let current: unknown = value;
  for (const part of pathParts) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return typeof current === "string" && current.length > 0 ? current : undefined;
}

function safeHost(host: string): string {
  return host.replace(/[\\/]/g, "_") || "unknown-host";
}

class FileBackedExporterLogger implements ExporterLogger {
  private logPath?: string;

  constructor(private readonly api: PluginApi) {}

  setLogPath(logPath: string): void {
    this.logPath = logPath;
  }

  info(message: string, error?: unknown): void {
    this.write("info", message, error);
  }

  warn(message: string, error?: unknown): void {
    this.write("warn", message, error);
  }

  error(message: string, error?: unknown): void {
    this.write("error", message, error);
  }

  private write(level: "info" | "warn" | "error", message: string, error?: unknown): void {
    const formatted = error ? `${message}: ${formatError(error)}` : message;
    const logger = this.api.logger?.[level];
    if (logger) {
      logger(`firewall-plugin exporter: ${formatted}`);
    } else if (level === "error") {
      console.error(`firewall-plugin exporter: ${formatted}`);
    } else if (level === "warn") {
      console.warn(`firewall-plugin exporter: ${formatted}`);
    } else {
      console.log(`firewall-plugin exporter: ${formatted}`);
    }

    if (!this.logPath) return;

    const line = `${JSON.stringify({
      ts: new Date().toISOString(),
      level,
      message,
      ...(error ? { error: formatError(error) } : {}),
    })}\n`;
    void appendFile(this.logPath, line, "utf8").catch(() => undefined);
  }
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.stack ?? error.message;
  }
  return String(error);
}
