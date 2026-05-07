import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import * as fspNs from "node:fs/promises";
import path from "node:path";

// Mutable indirection for filesystem ops so tests can intercept (e.g. simulate
// transient EBUSY from antivirus on Windows). Production code uses these
// directly; tests use mock.method on this object.
export const fsp = {
  mkdir: fspNs.mkdir,
  readdir: fspNs.readdir,
  readFile: fspNs.readFile,
  rename: fspNs.rename,
  rm: fspNs.rm,
  rmdir: fspNs.rmdir,
  stat: fspNs.stat,
  writeFile: fspNs.writeFile,
};
import {
  BATCH_MAX_BYTES,
  BATCH_MAX_EVENTS,
} from "./types";
import type {
  ExporterLogger,
  ExporterPaths,
  ExporterRuntime,
  FirewallExportEvent,
  FirewallExportEventInput,
} from "./types";

const FILESYSTEM_RENAME_GUARD_CODES = new Set(["EBUSY", "EPERM", "EACCES"]);

const LEGACY_PATHS = [
  "spool",
  "inbox",
  "checkpoint.json",
  "sequencer-checkpoint.json",
  "collector-checkpoint.json",
  "exporter.lock",
] as const;

export type PendingFile = {
  fileName: string;
  pendingPath: string;
};

export type ClaimedEvent = {
  pendingFileName: string;
  inflightPath: string;
  event: FirewallExportEvent;
};

export type ClaimedBatch = {
  batchId: string;
  inflightDir: string;
  events: ClaimedEvent[];
};

export type ClaimBatchOptions = {
  maxEvents?: number;
  maxBytes?: number;
  logger?: ExporterLogger;
};

export async function ensureQueueDirectories(paths: ExporterPaths): Promise<void> {
  await fsp.mkdir(paths.exportDir, { recursive: true });
  await fsp.mkdir(paths.pendingDir, { recursive: true });
  await fsp.mkdir(paths.inflightDir, { recursive: true });
  await fsp.mkdir(paths.tmpDir, { recursive: true });
  await fsp.mkdir(paths.logsDir, { recursive: true });
}

export async function purgeLegacyState(paths: ExporterPaths, logger: ExporterLogger): Promise<void> {
  for (const entry of LEGACY_PATHS) {
    const target = path.join(paths.exportDir, entry);
    try {
      await fsp.rm(target, { recursive: true, force: true });
    } catch (err) {
      logger.warn(`failed to remove legacy exporter path ${target}`, err);
    }
  }
}

export function prepareEvent(
  input: FirewallExportEventInput,
  runtime: Pick<ExporterRuntime, "apiKeyPathId" | "host">,
  now: Date = new Date(),
): FirewallExportEvent {
  const ts = isValidTimestamp(input.ts) ? new Date(Date.parse(input.ts)).toISOString() : validDate(now).toISOString();
  const eventId =
    input.eventId && input.eventId.length > 0
      ? input.eventId
      : `runtime-hook:${input.source}:${ts}:${process.pid}:${randomUUID()}`;

  return {
    schemaVersion: 1,
    ts,
    eventId,
    apiKeyPathId: runtime.apiKeyPathId,
    host: runtime.host,
    source: input.source,
    ...(input.hookName ? { hookName: input.hookName } : {}),
    ...(input.toolName ? { toolName: input.toolName } : {}),
    payload: toJsonSafe(input.payload),
    ...(input.firewallResult !== undefined ? { firewallResult: toJsonSafe(input.firewallResult) } : {}),
  };
}

export async function enqueueEvent(paths: ExporterPaths, event: FirewallExportEvent): Promise<void> {
  const tmpName = `${randomUUID()}.json`;
  const tmpPath = path.join(paths.tmpDir, tmpName);
  const fileName = `${sanitizeIsoForFilename(event.ts)}-${process.pid}-${randomUUID()}.json`;
  const pendingPath = path.join(paths.pendingDir, fileName);

  await fsp.writeFile(tmpPath, `${JSON.stringify(event)}\n`, { encoding: "utf8", flag: "wx" });
  try {
    await fsp.rename(tmpPath, pendingPath);
  } catch (err) {
    await fsp.rm(tmpPath, { force: true }).catch(() => undefined);
    throw err;
  }
}

export async function recoverStaleBatches(
  paths: ExporterPaths,
  logger: ExporterLogger,
  maxAgeMs: number,
): Promise<void> {
  const cutoffMs = Date.now() - maxAgeMs;

  const entries = await fsp.readdir(paths.inflightDir).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return [] as string[];
    throw err;
  });

  for (const entry of entries) {
    const dirPath = path.join(paths.inflightDir, entry);
    let info;
    try {
      info = await fsp.stat(dirPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      logger.warn(`failed to inspect inflight batch ${dirPath}`, err);
      continue;
    }

    if (!info.isDirectory()) continue;
    if (info.mtimeMs > cutoffMs) continue;

    const files = await fsp.readdir(dirPath).catch((err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") return [] as string[];
      throw err;
    });

    for (const fileName of files) {
      const from = path.join(dirPath, fileName);
      const to = path.join(paths.pendingDir, fileName);
      try {
        await fsp.rename(from, to);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if (code === "ENOENT") continue;
        logger.warn(`failed to recover stale event ${from}`, err);
      }
    }

    await fsp.rmdir(dirPath).catch((err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT" || err.code === "ENOTEMPTY") return;
      logger.warn(`failed to remove stale inflight directory ${dirPath}`, err);
    });
  }
}

export async function claimBatch(
  paths: ExporterPaths,
  options: ClaimBatchOptions = {},
): Promise<ClaimedBatch | undefined> {
  const maxEvents = options.maxEvents ?? BATCH_MAX_EVENTS;
  const maxBytes = options.maxBytes ?? BATCH_MAX_BYTES;

  const candidates = await fsp.readdir(paths.pendingDir).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return [] as string[];
    throw err;
  });

  const sorted = candidates.filter((name) => name.endsWith(".json")).sort();
  if (sorted.length === 0) return undefined;

  const batchId = randomUUID();
  const inflightDir = path.join(paths.inflightDir, `${process.pid}-${batchId}`);
  await fsp.mkdir(inflightDir, { recursive: true });

  const events: ClaimedEvent[] = [];
  let totalBytes = 0;
  let claimedAny = false;

  for (const fileName of sorted) {
    if (events.length >= maxEvents) break;

    const from = path.join(paths.pendingDir, fileName);
    const to = path.join(inflightDir, fileName);

    try {
      await fsp.rename(from, to);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT" || FILESYSTEM_RENAME_GUARD_CODES.has(code ?? "")) {
        continue;
      }
      throw err;
    }

    let raw: string;
    try {
      raw = await fsp.readFile(to, "utf8");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT") continue;
      throw err;
    }

    let event: FirewallExportEvent;
    try {
      event = JSON.parse(stripJsonBom(raw)) as FirewallExportEvent;
    } catch (err) {
      options.logger?.warn(`dropping unparseable exporter event ${fileName}`, err);
      await fsp.rm(to, { force: true }).catch(() => undefined);
      continue;
    }

    events.push({
      pendingFileName: fileName,
      inflightPath: to,
      event,
    });
    claimedAny = true;
    totalBytes += Buffer.byteLength(raw, "utf8");
    if (totalBytes >= maxBytes) break;
  }

  if (!claimedAny) {
    await fsp.rmdir(inflightDir).catch(() => undefined);
    return undefined;
  }

  return { batchId, inflightDir, events };
}

export async function commitBatch(batch: ClaimedBatch): Promise<void> {
  for (const claimed of batch.events) {
    await fsp.rm(claimed.inflightPath, { force: true });
  }
  await fsp.rmdir(batch.inflightDir).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return;
    throw err;
  });
}

export async function releaseBatch(batch: ClaimedBatch, paths: ExporterPaths): Promise<void> {
  for (const claimed of batch.events) {
    const back = path.join(paths.pendingDir, claimed.pendingFileName);
    try {
      await fsp.rename(claimed.inflightPath, back);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT") continue;
      // Best-effort: if rename fails the file stays in inflight and the next
      // stale-batch sweep will recover it.
    }
  }
  await fsp.rmdir(batch.inflightDir).catch(() => undefined);
}

export async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  await fsp.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await fsp.rename(tempPath, filePath);
}

export function buildJsonl(events: ReadonlyArray<{ event: FirewallExportEvent }>): Buffer {
  const lines = events.map((claimed) => `${JSON.stringify(claimed.event)}\n`).join("");
  return Buffer.from(lines, "utf8");
}

export function isValidTimestamp(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !Number.isNaN(Date.parse(value));
}

export function toJsonSafe(value: unknown): unknown {
  return makeJsonSafe(value, new WeakSet<object>());
}

function sanitizeIsoForFilename(iso: string): string {
  return iso.replace(/:/g, "-");
}

function stripJsonBom(raw: string): string {
  return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
}

function validDate(date: Date): Date {
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function makeJsonSafe(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null) return null;

  const valueType = typeof value;
  if (valueType === "string" || valueType === "boolean") return value;
  if (valueType === "number") return Number.isFinite(value) ? value : String(value);
  if (valueType === "bigint") return (value as bigint).toString();
  if (valueType === "undefined") return undefined;
  if (valueType === "symbol") return String(value);
  if (valueType === "function") {
    const fn = value as Function;
    return `[Function${fn.name ? `: ${fn.name}` : ""}]`;
  }

  if (value instanceof Date) return value.toISOString();

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
  }

  if (Buffer.isBuffer(value)) {
    return {
      type: "Buffer",
      byteLength: value.byteLength,
      base64: value.toString("base64"),
    };
  }

  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return {
      type: view.constructor.name,
      byteLength: view.byteLength,
      base64: Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString("base64"),
    };
  }

  if (value instanceof ArrayBuffer) {
    return {
      type: "ArrayBuffer",
      byteLength: value.byteLength,
      base64: Buffer.from(value).toString("base64"),
    };
  }

  if (typeof value !== "object") return String(value);

  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (Array.isArray(value)) {
    const result = value.map((item) => makeJsonSafe(item, seen));
    seen.delete(value);
    return result;
  }

  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    try {
      const safeValue = makeJsonSafe((value as Record<string, unknown>)[key], seen);
      if (safeValue !== undefined) {
        result[key] = safeValue;
      }
    } catch (err) {
      result[key] = `[Unserializable: ${formatError(err)}]`;
    }
  }

  seen.delete(value);
  return result;
}

function formatError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
