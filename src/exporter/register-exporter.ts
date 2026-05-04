import { appendFile, open, readFile, rm } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  CheckpointStore,
  EventWriter,
  ensureExporterDirectories,
} from "./event-writer";
import { DurableEventInbox, EventSequencer } from "./event-inbox";
import { FileTelemetryCollector } from "./file-collector";
import { registerHookTraceHandlers, writeHookTraceEvent } from "./hook-trace";
import {
  FIXED_API_KEY_PATH_ID,
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
  userEmail?: string;
};

type ExporterLock = {
  fileHandle: FileHandle;
  lockPath: string;
};

export function createFirewallExporter(api: PluginApi, options: ExporterOptions): FirewallExporter {
  const logger = new FileBackedExporterLogger(api);
  let runtime: ExporterRuntime | undefined;
  let checkpointStore: CheckpointStore | undefined;
  let writer: EventWriter | undefined;
  let uploader: SegmentUploader | undefined;
  let inbox: DurableEventInbox | undefined;
  let sequencer: EventSequencer | undefined;
  let fileCollector: FileTelemetryCollector | undefined;
  let exporterLock: ExporterLock | undefined;
  let startPromise: Promise<void> | undefined;
  let stopPromise: Promise<void> | undefined;
  let wroteLockOwnedWarning = false;

  const exporter: FirewallExporter = {
    async startFromGateway(ctx?: unknown): Promise<void> {
      if (startPromise) return startPromise;

      startPromise = (async () => {
        const paths = resolveExporterPaths(ctx, api);
        logger.setLogPath(paths.logPath);
        await ensureExporterDirectories(paths);
        inbox = new DurableEventInbox(paths, logger);

        const lock = await acquireExporterLock(paths.lockPath, logger);
        if (!lock) {
          if (!wroteLockOwnedWarning) {
            logger.warn(`exporter not started because another process owns ${paths.lockPath}`);
            wroteLockOwnedWarning = true;
          }
          startPromise = undefined;
          return;
        }
        exporterLock = lock;
        wroteLockOwnedWarning = false;

        runtime = {
          apiKey: options.apiKey,
          apiKeyPathId: FIXED_API_KEY_PATH_ID,
          userEmail: options.userEmail,
          host: safeHost(os.hostname()),
          paths,
          logger,
        };

        checkpointStore = new CheckpointStore(paths.checkpointPath, paths.spoolDir, logger);
        await checkpointStore.loadOrInitialize();

        writer = new EventWriter(runtime, checkpointStore);
        await writer.recoverTmpSegments();

        uploader = new SegmentUploader(runtime, checkpointStore, writer);
        writer.startAccepting();
        fileCollector = new FileTelemetryCollector(runtime, inbox, paths.collectorCheckpointPath);
        sequencer = new EventSequencer(runtime, inbox, writer, paths.sequencerCheckpointPath, {
          beforeDrain: () => fileCollector?.kick() ?? Promise.resolve(),
        });
        fileCollector.startPeriodicLoop();
        sequencer.startPeriodicLoop();
        uploader.startPeriodicLoop();
        void fileCollector.kick().catch((err) => {
          logger.warn("initial file telemetry collector scan failed; files will retry later", err);
        });
        void sequencer.kick().catch((err) => {
          logger.warn("initial event sequencer drain failed; events will retry later", err);
        });
        void uploader.kick().catch((err) => {
          logger.warn("initial pending upload attempt failed; chunks will retry later", err);
        });
        logger.info(`exporter started at ${paths.exportDir}`);
      })().catch((err) => {
        startPromise = undefined;
        const lock = exporterLock;
        exporterLock = undefined;
        if (lock) {
          void releaseExporterLock(lock).catch((releaseErr) => {
            logger.warn("failed to release exporter lock after start failure", releaseErr);
          });
        }
        throw err;
      });

      return startPromise;
    },

    async stop(): Promise<void> {
      if (stopPromise) return stopPromise;

      stopPromise = (async () => {
        await startPromise?.catch(() => undefined);
        await fileCollector?.stop();
        await sequencer?.stop();
        writer?.stopAccepting();
        await writer?.flushActive();
        await uploader?.stop();
        await checkpointStore?.persist();
        const lock = exporterLock;
        exporterLock = undefined;
        if (lock) {
          await releaseExporterLock(lock);
        }
        logger.info("exporter stopped");
      })();

      return stopPromise;
    },

    async writeEvent(event: FirewallExportEventInput): Promise<void> {
      const targetInbox = await ensureInbox();
      try {
        await targetInbox.enqueue(event);
      } catch (err) {
        logger.warn("exporter event ignored because inbox write failed", err);
        return;
      }

      if (!sequencer) {
        try {
          await exporter.startFromGateway();
        } catch (err) {
          logger.warn("exporter event queued but lazy start failed", err);
        }
      }

      void sequencer?.kick().catch((err) => {
        logger.warn("event sequencer drain failed after enqueue", err);
      });
    },
  };

  async function ensureInbox(): Promise<DurableEventInbox> {
    if (inbox) return inbox;

    const paths = resolveExporterPaths(undefined, api);
    logger.setLogPath(paths.logPath);
    await ensureExporterDirectories(paths);
    inbox = new DurableEventInbox(paths, logger);
    return inbox;
  }

  registerHookTraceHandlers(api, exporter, logger);

  api.on?.("gateway_start", (event, ctx) => {
    void exporter
      .startFromGateway(ctx)
      .then(() => writeHookTraceEvent(exporter, "gateway_start", event, ctx, logger))
      .catch((err) => {
        logger.warn("exporter failed to start in background", err);
      });
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
    spoolDir: path.join(exportDir, "spool"),
    logsDir: path.join(exportDir, "logs"),
    checkpointPath: path.join(exportDir, "checkpoint.json"),
    collectorCheckpointPath: path.join(exportDir, "collector-checkpoint.json"),
    sequencerCheckpointPath: path.join(exportDir, "sequencer-checkpoint.json"),
    inboxDir: path.join(exportDir, "inbox"),
    inboxTmpDir: path.join(exportDir, "inbox", "tmp"),
    inboxReadyDir: path.join(exportDir, "inbox", "ready"),
    lockPath: path.join(exportDir, "exporter.lock"),
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

async function acquireExporterLock(lockPath: string, logger: ExporterLogger): Promise<ExporterLock | undefined> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fileHandle = await open(lockPath, "wx");
      await fileHandle.writeFile(
        `${JSON.stringify({
          version: 1,
          pid: process.pid,
          host: os.hostname(),
          startedAt: new Date().toISOString(),
        })}\n`,
        "utf8",
      );
      return { fileHandle, lockPath };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code !== "EEXIST") {
        logger.warn(`failed to acquire exporter lock at ${lockPath}`, err);
        return undefined;
      }

      const existing = await readExistingLock(lockPath);
      if (!existing?.pid) {
        logger.warn(`exporter lock exists but cannot be verified at ${lockPath}`);
        return undefined;
      }

      if (isProcessAlive(existing.pid)) {
        return undefined;
      }

      logger.warn(`removing stale exporter lock at ${lockPath}`);
      await rm(lockPath, { force: true }).catch((rmErr) => {
        logger.warn(`failed to remove stale exporter lock at ${lockPath}`, rmErr);
      });
    }
  }

  return undefined;
}

async function releaseExporterLock(lock: ExporterLock): Promise<void> {
  await lock.fileHandle.close().catch(() => undefined);
  await rm(lock.lockPath, { force: true });
}

async function readExistingLock(lockPath: string): Promise<{ pid?: number } | undefined> {
  try {
    const parsed = JSON.parse(stripJsonBom(await readFile(lockPath, "utf8"))) as { pid?: unknown };
    return Number.isSafeInteger(parsed.pid) && parsed.pid > 0 ? { pid: parsed.pid } : undefined;
  } catch {
    return undefined;
  }
}

function isProcessAlive(pid: number): boolean {
  if (pid === process.pid) return true;

  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function stripJsonBom(raw: string): string {
  return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
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
