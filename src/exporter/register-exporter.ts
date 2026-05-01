import { appendFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  CheckpointStore,
  EventWriter,
  apiKeyToPathId,
  ensureExporterDirectories,
} from "./event-writer";
import {
  type ExporterLogger,
  type ExporterPaths,
  type ExporterRuntime,
  type FirewallExportEventInput,
  type FirewallExporter,
} from "./types";
import { SegmentUploader } from "./uploader";

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
  let checkpointStore: CheckpointStore | undefined;
  let writer: EventWriter | undefined;
  let uploader: SegmentUploader | undefined;
  let startPromise: Promise<void> | undefined;
  let stopPromise: Promise<void> | undefined;

  const exporter: FirewallExporter = {
    async start(ctx?: unknown): Promise<void> {
      if (startPromise) return startPromise;

      startPromise = (async () => {
        const paths = resolveExporterPaths(ctx, api);
        logger.setLogPath(paths.logPath);
        await ensureExporterDirectories(paths);

        runtime = {
          apiKey: options.apiKey,
          apiUrl: options.apiUrl,
          apiKeyPathId: apiKeyToPathId(options.apiKey),
          host: safeHost(os.hostname()),
          paths,
          logger,
        };

        checkpointStore = new CheckpointStore(paths.checkpointPath, paths.spoolDir, logger);
        await checkpointStore.loadOrInitialize();

        writer = new EventWriter(runtime, checkpointStore);
        await writer.recoverTmpSegments();

        uploader = new SegmentUploader(runtime, checkpointStore, writer);
        try {
          await uploader.uploadReadyChunks();
        } catch (err) {
          logger.warn("initial pending upload attempt failed; chunks will retry later", err);
        }

        writer.startAccepting();
        uploader.startPeriodicLoop();
        logger.info(`exporter started at ${paths.exportDir}`);
      })();

      return startPromise;
    },

    async stop(): Promise<void> {
      if (stopPromise) return stopPromise;

      stopPromise = (async () => {
        writer?.stopAccepting();
        await writer?.flushActive();
        await uploader?.stop();
        await checkpointStore?.persist();
        logger.info("exporter stopped");
      })();

      return stopPromise;
    },

    async writeEvent(event: FirewallExportEventInput): Promise<void> {
      if (!writer) {
        logger.warn("exporter event ignored because gateway_start has not completed");
        return;
      }

      await writer.writeEvent(event);
    },
  };

  api.on?.("gateway_start", async (_event, ctx) => {
    await exporter.start(ctx);
  });

  api.on?.("gateway_stop", async () => {
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
    exportDir,
    spoolDir: path.join(exportDir, "spool"),
    logsDir: path.join(exportDir, "logs"),
    checkpointPath: path.join(exportDir, "checkpoint.json"),
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
