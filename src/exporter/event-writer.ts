import { Buffer } from "node:buffer";
import {
  appendFile,
  mkdir,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import {
  EXPORT_BUCKET,
  MAX_SPOOL_BYTES,
  RECENT_UPLOAD_LIMIT,
  SEGMENT_SIZE_LIMIT_BYTES,
  SEGMENT_TIME_LIMIT_MS,
  SEQUENCE_WIDTH,
} from "./types";
import type {
  Checkpoint,
  ExporterLogger,
  ExporterPaths,
  ExporterRuntime,
  FirewallExportEvent,
  FirewallExportEventInput,
} from "./types";

type ActiveSegment = {
  seqStart: number;
  seqEnd: number;
  startedAtMs: number;
  bytes: number;
  events: number;
  tmpPath: string;
};

export type ReadyChunkFile = {
  fileName: string;
  filePath: string;
  seqStart: number;
  seqEnd: number;
  chunkId: string;
};

export type JsonlSegmentMeta = {
  eventCount: number;
  firstSeq?: number;
  lastSeq?: number;
  firstTs?: string;
};

export function apiKeyToPathId(apiKey: string): string {
  return Buffer.from(apiKey).toString("base64url");
}

export function padSeq(seq: number): string {
  return Math.trunc(seq).toString().padStart(SEQUENCE_WIDTH, "0");
}

export function chunkId(seqStart: number, seqEnd: number): string {
  return `chunk-${padSeq(seqStart)}-${padSeq(seqEnd)}`;
}

export function chunkFileName(seqStart: number, seqEnd: number): string {
  return `${chunkId(seqStart, seqEnd)}.jsonl.ready`;
}

export function parseReadyChunkFileName(fileName: string): Omit<ReadyChunkFile, "filePath"> | undefined {
  const match = /^chunk-(\d{12})-(\d{12})\.jsonl\.ready$/.exec(fileName);
  if (!match) return undefined;

  const seqStart = Number.parseInt(match[1], 10);
  const seqEnd = Number.parseInt(match[2], 10);
  if (!Number.isSafeInteger(seqStart) || !Number.isSafeInteger(seqEnd) || seqEnd < seqStart) {
    return undefined;
  }

  return {
    fileName,
    seqStart,
    seqEnd,
    chunkId: chunkId(seqStart, seqEnd),
  };
}

export async function ensureExporterDirectories(paths: ExporterPaths): Promise<void> {
  await mkdir(paths.exportDir, { recursive: true });
  await mkdir(paths.spoolDir, { recursive: true });
  await mkdir(paths.logsDir, { recursive: true });
}

export function initialCheckpoint(nextSeq = 1): Checkpoint {
  return {
    version: 1,
    nextSeq,
    uploadedThroughSeq: 0,
    recentUploads: [],
  };
}

export async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}-${Math.random()
    .toString(36)
    .slice(2)}`;
  await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(tempPath, filePath);
}

export async function readJsonlSegmentMeta(filePath: string): Promise<JsonlSegmentMeta> {
  const text = await readFile(filePath, "utf8");
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  const meta: JsonlSegmentMeta = { eventCount: 0 };

  for (const line of lines) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch (err) {
      throw new Error(`invalid JSONL segment ${filePath}: ${formatError(err)}`);
    }

    if (!parsed || typeof parsed !== "object") {
      throw new Error(`invalid JSONL segment ${filePath}: line is not an object`);
    }

    const event = parsed as Partial<FirewallExportEvent>;
    if (!Number.isSafeInteger(event.seq)) {
      throw new Error(`invalid JSONL segment ${filePath}: missing numeric seq`);
    }

    if (typeof event.ts !== "string") {
      throw new Error(`invalid JSONL segment ${filePath}: missing ts`);
    }

    if (meta.eventCount === 0) {
      meta.firstSeq = event.seq;
      meta.firstTs = event.ts;
    }

    if (meta.lastSeq !== undefined && event.seq <= meta.lastSeq) {
      throw new Error(`invalid JSONL segment ${filePath}: seq is not monotonic`);
    }

    meta.lastSeq = event.seq;
    meta.eventCount += 1;
  }

  return meta;
}

export async function listReadyChunks(spoolDir: string): Promise<ReadyChunkFile[]> {
  const entries = await readdir(spoolDir).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return [];
    throw err;
  });

  return entries
    .map((fileName) => {
      const parsed = parseReadyChunkFileName(fileName);
      if (!parsed) return undefined;
      return {
        ...parsed,
        filePath: path.join(spoolDir, fileName),
      };
    })
    .filter((entry): entry is ReadyChunkFile => Boolean(entry))
    .sort((a, b) => a.seqStart - b.seqStart || a.seqEnd - b.seqEnd);
}

export class CheckpointStore {
  private checkpoint: Checkpoint = initialCheckpoint();
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly checkpointPath: string,
    private readonly spoolDir: string,
    private readonly logger: ExporterLogger,
  ) {}

  getSnapshot(): Checkpoint {
    return cloneCheckpoint(this.checkpoint);
  }

  async loadOrInitialize(): Promise<Checkpoint> {
    let checkpoint: Checkpoint | undefined;

    try {
      const raw = await readFile(this.checkpointPath, "utf8");
      checkpoint = normalizeCheckpoint(JSON.parse(raw));
      if (!checkpoint) {
        throw new Error("checkpoint has invalid shape");
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT") {
        checkpoint = initialCheckpoint();
      } else {
        this.logger.warn("checkpoint is corrupt; moving it aside and rebuilding nextSeq", err);
        await moveCorruptCheckpoint(this.checkpointPath, this.logger);
        const highestSeq = await findHighestSeqInSpool(this.spoolDir, this.logger);
        checkpoint = initialCheckpoint(highestSeq + 1);
      }
    }

    const highestSeq = await findHighestSeqInSpool(this.spoolDir, this.logger);
    if (checkpoint.nextSeq <= highestSeq) {
      checkpoint.nextSeq = highestSeq + 1;
    }

    this.checkpoint = normalizeCheckpoint(checkpoint) ?? initialCheckpoint();
    await writeJsonAtomic(this.checkpointPath, this.checkpoint);
    return this.getSnapshot();
  }

  update(mutator: (checkpoint: Checkpoint) => Checkpoint | void): Promise<Checkpoint> {
    const run = this.queue.then(async () => {
      const draft = cloneCheckpoint(this.checkpoint);
      const result = mutator(draft) ?? draft;
      const normalized = normalizeCheckpoint(result);
      if (!normalized) {
        throw new Error("checkpoint update produced invalid checkpoint");
      }

      this.checkpoint = normalized;
      await writeJsonAtomic(this.checkpointPath, this.checkpoint);
      return this.getSnapshot();
    });

    this.queue = run.then(
      () => undefined,
      () => undefined,
    );

    return run;
  }

  async persist(): Promise<void> {
    await this.update((checkpoint) => checkpoint);
  }
}

export class EventWriter {
  private active?: ActiveSegment;
  private accepting = false;
  private nextSeq = 1;
  private queue: Promise<void> = Promise.resolve();
  private rotationTimer?: ReturnType<typeof setTimeout>;
  private spoolFullWarningActive = false;
  private wroteBeforeStartWarning = false;

  constructor(
    private readonly runtime: ExporterRuntime,
    private readonly checkpointStore: CheckpointStore,
  ) {}

  startAccepting(): void {
    this.nextSeq = this.checkpointStore.getSnapshot().nextSeq;
    this.accepting = true;
  }

  stopAccepting(): void {
    this.accepting = false;
  }

  async writeEvent(input: FirewallExportEventInput): Promise<void> {
    await this.enqueue(async () => {
      if (!this.accepting) {
        if (!this.wroteBeforeStartWarning) {
          this.runtime.logger.warn("exporter event ignored because writer is not started");
          this.wroteBeforeStartWarning = true;
        }
        return;
      }

      const spoolBytes = await directorySize(this.runtime.paths.spoolDir);
      if (spoolBytes > MAX_SPOOL_BYTES) {
        if (!this.spoolFullWarningActive) {
          this.runtime.logger.warn(
            `local exporter spool exceeds ${MAX_SPOOL_BYTES} bytes; exporter events will be dropped until it drains`,
          );
          this.spoolFullWarningActive = true;
        }
        return;
      }

      if (this.spoolFullWarningActive) {
        this.runtime.logger.info("local exporter spool is below the limit; exporter events accepted again");
        this.spoolFullWarningActive = false;
      }

      const seq = this.nextSeq;
      const event: FirewallExportEvent = {
        schemaVersion: 1,
        seq,
        ts: new Date().toISOString(),
        apiKeyPathId: this.runtime.apiKeyPathId,
        host: this.runtime.host,
        source: input.source,
        ...(input.toolName ? { toolName: input.toolName } : {}),
        payload: input.payload,
        ...(input.firewallResult !== undefined ? { firewallResult: input.firewallResult } : {}),
      };

      const line = `${JSON.stringify(event)}\n`;
      const lineBytes = Buffer.byteLength(line);

      if (!this.active) {
        await this.openActiveSegment(seq);
      }

      await appendFile(this.active!.tmpPath, line, "utf8");
      this.active!.seqEnd = seq;
      this.active!.bytes += lineBytes;
      this.active!.events += 1;
      this.nextSeq = seq + 1;

      await this.checkpointStore.update((checkpoint) => {
        checkpoint.nextSeq = Math.max(checkpoint.nextSeq, this.nextSeq);
      });

      if (
        this.active!.bytes >= SEGMENT_SIZE_LIMIT_BYTES ||
        Date.now() - this.active!.startedAtMs >= SEGMENT_TIME_LIMIT_MS
      ) {
        await this.rotateActiveSegment();
      }
    });
  }

  async flushExpired(): Promise<void> {
    await this.enqueue(async () => {
      if (!this.active) return;
      if (Date.now() - this.active.startedAtMs < SEGMENT_TIME_LIMIT_MS) return;
      await this.rotateActiveSegment();
    });
  }

  async flushActive(): Promise<void> {
    await this.enqueue(async () => {
      if (!this.active) return;
      await this.rotateActiveSegment();
    });
  }

  async recoverTmpSegments(): Promise<void> {
    await this.enqueue(async () => {
      const entries = await readdir(this.runtime.paths.spoolDir).catch((err: NodeJS.ErrnoException) => {
        if (err.code === "ENOENT") return [];
        throw err;
      });

      const tmpFiles = entries
        .filter((fileName) => /^active-\d{12}\.jsonl\.tmp$/.test(fileName))
        .sort();

      for (const fileName of tmpFiles) {
        const tmpPath = path.join(this.runtime.paths.spoolDir, fileName);
        let meta: JsonlSegmentMeta;
        try {
          meta = await readJsonlSegmentMeta(tmpPath);
        } catch (err) {
          this.runtime.logger.warn(`leaving invalid active segment in place: ${fileName}`, err);
          continue;
        }

        if (meta.eventCount === 0) {
          await rm(tmpPath, { force: true });
          continue;
        }

        const seqStart = meta.firstSeq!;
        const seqEnd = meta.lastSeq!;
        const readyPath = path.join(this.runtime.paths.spoolDir, chunkFileName(seqStart, seqEnd));
        if (await exists(readyPath)) {
          this.runtime.logger.warn(`cannot recover ${fileName}; ready segment already exists`);
          continue;
        }

        await rename(tmpPath, readyPath);
      }
    });
  }

  private async openActiveSegment(seqStart: number): Promise<void> {
    const tmpPath = path.join(this.runtime.paths.spoolDir, `active-${padSeq(seqStart)}.jsonl.tmp`);
    if (await exists(tmpPath)) {
      throw new Error(`active segment already exists: ${tmpPath}`);
    }

    await writeFile(tmpPath, "", { flag: "wx" });
    this.active = {
      seqStart,
      seqEnd: seqStart - 1,
      startedAtMs: Date.now(),
      bytes: 0,
      events: 0,
      tmpPath,
    };
    this.scheduleRotationTimer();
  }

  private async rotateActiveSegment(): Promise<void> {
    if (!this.active) return;

    const active = this.active;
    this.active = undefined;
    this.clearRotationTimer();

    if (active.events === 0) {
      await rm(active.tmpPath, { force: true });
      return;
    }

    const meta = await readJsonlSegmentMeta(active.tmpPath);
    if (
      meta.eventCount !== active.events ||
      meta.firstSeq !== active.seqStart ||
      meta.lastSeq !== active.seqEnd
    ) {
      this.runtime.logger.warn(`leaving invalid active segment in place: ${path.basename(active.tmpPath)}`);
      return;
    }

    const readyPath = path.join(this.runtime.paths.spoolDir, chunkFileName(active.seqStart, active.seqEnd));
    if (await exists(readyPath)) {
      throw new Error(`ready segment already exists: ${readyPath}`);
    }

    await rename(active.tmpPath, readyPath);
  }

  private scheduleRotationTimer(): void {
    this.clearRotationTimer();
    this.rotationTimer = setTimeout(() => {
      void this.flushExpired().catch((err) => {
        this.runtime.logger.warn("time-based segment rotation failed", err);
      });
    }, SEGMENT_TIME_LIMIT_MS);
    this.rotationTimer.unref?.();
  }

  private clearRotationTimer(): void {
    if (this.rotationTimer) {
      clearTimeout(this.rotationTimer);
      this.rotationTimer = undefined;
    }
  }

  private enqueue(task: () => Promise<void>): Promise<void> {
    const run = this.queue.then(task);
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

function normalizeCheckpoint(value: unknown): Checkpoint | undefined {
  if (!value || typeof value !== "object") return undefined;

  const checkpoint = value as Partial<Checkpoint>;
  if (checkpoint.version !== 1) return undefined;

  const uploadedThroughSeq = normalizeSeq(checkpoint.uploadedThroughSeq, 0);
  const nextSeq = Math.max(normalizeSeq(checkpoint.nextSeq, 1), uploadedThroughSeq + 1);
  const recentUploads = Array.isArray(checkpoint.recentUploads) ? checkpoint.recentUploads : [];

  return {
    version: 1,
    nextSeq,
    uploadedThroughSeq,
    recentUploads: recentUploads
      .filter((upload) => {
        if (!upload || typeof upload !== "object") return false;
        const candidate = upload as Partial<Checkpoint["recentUploads"][number]>;
        return (
          typeof candidate.chunkId === "string" &&
          Number.isSafeInteger(candidate.seqStart) &&
          Number.isSafeInteger(candidate.seqEnd) &&
          candidate.seqEnd! >= candidate.seqStart! &&
          candidate.s3Bucket === EXPORT_BUCKET &&
          typeof candidate.s3Key === "string" &&
          typeof candidate.uploadedAt === "string"
        );
      })
      .slice(-RECENT_UPLOAD_LIMIT),
  };
}

function normalizeSeq(value: unknown, fallback: number): number {
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.max(fallback, value as number);
}

function cloneCheckpoint(checkpoint: Checkpoint): Checkpoint {
  return JSON.parse(JSON.stringify(checkpoint)) as Checkpoint;
}

async function moveCorruptCheckpoint(checkpointPath: string, logger: ExporterLogger): Promise<void> {
  if (!(await exists(checkpointPath))) return;

  const timestamp = new Date().toISOString().replace(/[:]/g, "-");
  const corruptPath = `${checkpointPath}.corrupt.${timestamp}`;
  try {
    await rename(checkpointPath, corruptPath);
  } catch (err) {
    logger.warn(`failed to move corrupt checkpoint to ${corruptPath}`, err);
  }
}

async function findHighestSeqInSpool(spoolDir: string, logger: ExporterLogger): Promise<number> {
  const entries = await readdir(spoolDir).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return [];
    throw err;
  });

  let highestSeq = 0;
  for (const fileName of entries) {
    const ready = parseReadyChunkFileName(fileName);
    if (ready) {
      highestSeq = Math.max(highestSeq, ready.seqEnd);
    }

    if (!fileName.endsWith(".jsonl.ready") && !fileName.endsWith(".jsonl.tmp")) {
      continue;
    }

    try {
      const meta = await readJsonlSegmentMeta(path.join(spoolDir, fileName));
      highestSeq = Math.max(highestSeq, meta.lastSeq ?? 0);
    } catch (err) {
      logger.warn(`could not inspect spool segment while rebuilding checkpoint: ${fileName}`, err);
    }
  }

  return highestSeq;
}

async function directorySize(dir: string): Promise<number> {
  const entries = await readdir(dir, { withFileTypes: true }).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return [];
    throw err;
  });

  let total = 0;
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      total += await directorySize(fullPath);
    } else if (entry.isFile()) {
      total += (await stat(fullPath)).size;
    }
  }

  return total;
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw err;
  }
}

function formatError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
