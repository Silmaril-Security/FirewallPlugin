import { createHash } from "node:crypto";
import type { Dirent, Stats } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { inflateRawSync } from "node:zlib";
import { writeJsonAtomic } from "./event-writer";
import {
  FILE_COLLECTOR_LOOP_INTERVAL_MS,
  FILE_COLLECTOR_MAX_LINES_PER_FILE,
  FILE_COLLECTOR_RECENT_EVENT_LIMIT,
} from "./types";
import type { ExporterRuntime, FirewallExportEventInput } from "./types";

type CollectorSource = "agent_session" | "gateway_log";

type CollectorFileCursor = {
  source: CollectorSource;
  signature: string;
  offset: number;
  lineNumber: number;
  lastLineHash?: string;
  lastSeenAt: string;
};

type BrowserArtifactCursor = {
  signature: string;
  emittedAt: string;
};

type CollectorCheckpoint = {
  version: 1;
  files: Record<string, CollectorFileCursor>;
  browserArtifacts: Record<string, BrowserArtifactCursor>;
  recentEventIds: string[];
};

type CompletedLine = {
  line: string;
  lineNumber: number;
  byteOffset: number;
  lineHash: string;
};

type PendingEvent = FirewallExportEventInput & {
  eventId: string;
  ts: string;
};

type EventSink = {
  enqueue(input: FirewallExportEventInput): Promise<unknown>;
};

type ZipEntry = {
  fileName: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
};

const BROWSER_REQUEST_LIMIT = 200;
const ZIP_ENTRY_DETAIL_LIMIT = 500;

export class FileTelemetryCollector {
  private timer?: ReturnType<typeof setInterval>;
  private inFlight?: Promise<void>;
  private stopped = false;
  private checkpoint?: CollectorCheckpoint;
  private loadedCheckpointWasMissing = false;

  constructor(
    private readonly runtime: ExporterRuntime,
    private readonly eventSink: EventSink,
    private readonly checkpointPath: string,
  ) {}

  startPeriodicLoop(): void {
    if (this.timer) return;

    this.stopped = false;
    this.timer = setInterval(() => {
      void this.kick().catch((err) => {
        this.runtime.logger.warn("file telemetry collector scan failed", err);
      });
    }, FILE_COLLECTOR_LOOP_INTERVAL_MS);
    this.timer.unref?.();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    if (this.inFlight) {
      await this.inFlight.catch((err) => {
        this.runtime.logger.warn("file telemetry collector scan failed while stopping", err);
      });
    }

    if (this.checkpoint) {
      await writeJsonAtomic(this.checkpointPath, this.checkpoint);
    }
  }

  async kick(): Promise<void> {
    if (this.inFlight) return this.inFlight;

    this.inFlight = this.runOnce().finally(() => {
      this.inFlight = undefined;
    });

    return this.inFlight;
  }

  private async runOnce(): Promise<void> {
    const checkpoint = await this.loadCheckpoint();
    const draft = cloneCheckpoint(checkpoint);
    const pending: PendingEvent[] = [];

    await this.collectAgentSessionEvents(draft, pending);
    await this.collectGatewayLogEvents(draft, pending);
    await this.collectBrowserTelemetryEvents(draft, pending);

    pending.sort((a, b) => {
      const tsCompare = Date.parse(a.ts) - Date.parse(b.ts);
      if (tsCompare !== 0) return tsCompare;
      return a.eventId.localeCompare(b.eventId);
    });

    const recent = new Set(draft.recentEventIds);
    for (const event of pending) {
      if (this.stopped) return;
      if (recent.has(event.eventId)) continue;

      await this.eventSink.enqueue(event);
      recent.add(event.eventId);
      draft.recentEventIds.push(event.eventId);
      draft.recentEventIds = draft.recentEventIds.slice(-FILE_COLLECTOR_RECENT_EVENT_LIMIT);
    }

    this.checkpoint = normalizeCollectorCheckpoint(draft);
    await writeJsonAtomic(this.checkpointPath, this.checkpoint);
    this.loadedCheckpointWasMissing = false;
  }

  private async collectAgentSessionEvents(
    checkpoint: CollectorCheckpoint,
    pending: PendingEvent[],
  ): Promise<void> {
    const agentsDir = path.join(this.runtime.paths.stateDir, "agents");
    const agentEntries = await readDirSafe(agentsDir);

    for (const agentEntry of agentEntries) {
      if (!agentEntry.isDirectory()) continue;

      const agentId = agentEntry.name;
      const sessionsDir = path.join(agentsDir, agentId, "sessions");
      const sessionEntries = await readDirSafe(sessionsDir);
      for (const sessionEntry of sessionEntries) {
        if (!sessionEntry.isFile()) continue;
        if (!sessionEntry.name.endsWith(".jsonl")) continue;

        const filePath = path.join(sessionsDir, sessionEntry.name);
        const sessionId = path.basename(sessionEntry.name, ".jsonl");
        const lines = await this.readCompletedLines(checkpoint, filePath, "agent_session");

        for (const line of lines) {
          const parsed = parseJsonObject(line.line);
          if (!parsed) continue;

          const ts = normalizeTimestamp(parsed.timestamp);
          if (!ts) continue;

          const rowId = typeof parsed.id === "string" && parsed.id.length > 0 ? parsed.id : line.lineHash;
          const eventId = `agent-session:${agentId}:${sessionId}:${rowId}`;
          pending.push({
            source: "agent_session_event",
            eventId,
            ts,
            payload: normalizeAgentSessionPayload({
              sourceFile: filePath,
              agentId,
              sessionId,
              line,
              row: parsed,
            }),
          });
        }
      }
    }
  }

  private async collectGatewayLogEvents(
    checkpoint: CollectorCheckpoint,
    pending: PendingEvent[],
  ): Promise<void> {
    const logFiles = await discoverGatewayLogFiles(this.runtime.paths.stateDir);

    for (const filePath of logFiles) {
      const lines = await this.readCompletedLines(checkpoint, filePath, "gateway_log");
      for (const line of lines) {
        const parsed = parseJsonObject(line.line);
        if (!parsed) continue;

        const ts = normalizeTimestamp(parsed.time);
        if (!ts) continue;

        const eventId = `gateway-log:${path.basename(filePath)}:${line.lineNumber}:${line.lineHash}`;
        pending.push({
          source: "gateway_log_event",
          eventId,
          ts,
          payload: normalizeGatewayLogPayload(filePath, line, parsed),
        });
      }
    }
  }

  private async collectBrowserTelemetryEvents(
    checkpoint: CollectorCheckpoint,
    pending: PendingEvent[],
  ): Promise<void> {
    const artifactFiles = await discoverBrowserArtifacts();

    for (const filePath of artifactFiles) {
      const fileStat = await stat(filePath).catch(() => undefined);
      if (!fileStat?.isFile()) continue;

      const signature = artifactSignature(fileStat);
      const key = normalizePathKey(filePath);
      if (checkpoint.browserArtifacts[key]?.signature === signature) continue;
      if (this.loadedCheckpointWasMissing) {
        checkpoint.browserArtifacts[key] = {
          signature,
          emittedAt: new Date().toISOString(),
        };
        continue;
      }

      const modifiedAt = new Date(fileStat.mtimeMs).toISOString();
      const artifactName = path.basename(filePath);
      const eventId = `browser-artifact:${artifactName}:${signature}:${hashText(key)}`;
      const payload = await normalizeBrowserArtifactPayload(filePath, artifactName, fileStat.size, modifiedAt);

      pending.push({
        source: "browser_telemetry_event",
        eventId,
        ts: modifiedAt,
        payload,
      });

      checkpoint.browserArtifacts[key] = {
        signature,
        emittedAt: new Date().toISOString(),
      };
    }
  }

  private async readCompletedLines(
    checkpoint: CollectorCheckpoint,
    filePath: string,
    source: CollectorSource,
  ): Promise<CompletedLine[]> {
    const fileStat = await stat(filePath).catch(() => undefined);
    if (!fileStat?.isFile()) return [];

    const key = normalizePathKey(filePath);
    const signature = cursorSignature(fileStat);
    let cursor = checkpoint.files[key];
    if (!cursor && this.loadedCheckpointWasMissing) {
      cursor = await initialCursorAtEnd(filePath, fileStat, source);
      checkpoint.files[key] = cursor;
      return [];
    }
    if (!cursor || cursor.source !== source || cursor.signature !== signature || fileStat.size < cursor.offset) {
      cursor = {
        source,
        signature,
        offset: 0,
        lineNumber: 0,
        lastSeenAt: new Date().toISOString(),
      };
    }

    if (fileStat.size <= cursor.offset) {
      cursor.lastSeenAt = new Date().toISOString();
      checkpoint.files[key] = cursor;
      return [];
    }

    const buffer = await readFile(filePath);
    const start = Math.min(cursor.offset, buffer.length);
    const slice = buffer.subarray(start);
    const completeLength = lastCompletedLineLength(slice);
    if (completeLength <= 0) {
      cursor.lastSeenAt = new Date().toISOString();
      checkpoint.files[key] = cursor;
      return [];
    }

    const completedText = slice.subarray(0, completeLength).toString("utf8");
    const parts = completedText.split("\n");
    const lines: CompletedLine[] = [];
    let consumed = 0;

    for (let index = 0; index < parts.length - 1; index += 1) {
      if (lines.length >= FILE_COLLECTOR_MAX_LINES_PER_FILE) break;

      const rawPart = parts[index];
      const lineBytes = Buffer.byteLength(`${rawPart}\n`, "utf8");
      const line = rawPart.endsWith("\r") ? rawPart.slice(0, -1) : rawPart;
      consumed += lineBytes;
      cursor.lineNumber += 1;
      cursor.offset = start + consumed;
      cursor.lastLineHash = hashText(line);

      if (line.length === 0) continue;

      lines.push({
        line,
        lineNumber: cursor.lineNumber,
        byteOffset: cursor.offset - lineBytes,
        lineHash: cursor.lastLineHash,
      });
    }

    cursor.lastSeenAt = new Date().toISOString();
    checkpoint.files[key] = cursor;
    return lines;
  }

  private async loadCheckpoint(): Promise<CollectorCheckpoint> {
    if (this.checkpoint) return this.checkpoint;

    try {
      const raw = await readFile(this.checkpointPath, "utf8");
      this.checkpoint = normalizeCollectorCheckpoint(JSON.parse(stripJsonBom(raw)));
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") {
        this.runtime.logger.warn("ignoring invalid collector checkpoint", err);
      } else {
        this.loadedCheckpointWasMissing = true;
      }
      this.checkpoint = initialCollectorCheckpoint();
    }

    return this.checkpoint;
  }
}

async function initialCursorAtEnd(
  filePath: string,
  fileStat: Stats,
  source: CollectorSource,
): Promise<CollectorFileCursor> {
  const buffer = await readFile(filePath).catch(() => Buffer.alloc(0));
  const completeLength = lastCompletedLineLength(buffer);
  const completed = completeLength > 0 ? buffer.subarray(0, completeLength).toString("utf8") : "";

  return {
    source,
    signature: cursorSignature(fileStat),
    offset: fileStat.size,
    lineNumber: completed.length > 0 ? completed.split("\n").length - 1 : 0,
    lastSeenAt: new Date().toISOString(),
  };
}

function normalizeAgentSessionPayload(input: {
  sourceFile: string;
  agentId: string;
  sessionId: string;
  line: CompletedLine;
  row: Record<string, unknown>;
}): Record<string, unknown> {
  const message = objectValue(input.row.message);
  const content = Array.isArray(message?.content) ? message.content : [];
  const toolCalls = content
    .filter((part): part is Record<string, unknown> => {
      return Boolean(part && typeof part === "object" && (part as Record<string, unknown>).type === "toolCall");
    })
    .map((part) => ({
      id: part.id,
      name: part.name,
      arguments: part.arguments,
    }));

  return {
    sourceFile: input.sourceFile,
    agentId: input.agentId,
    sessionId: input.sessionId,
    lineNumber: input.line.lineNumber,
    byteOffset: input.line.byteOffset,
    rowType: input.row.type,
    rowId: input.row.id,
    parentId: input.row.parentId,
    timestamp: input.row.timestamp,
    provider: input.row.provider ?? message?.provider,
    model: input.row.modelId ?? message?.model,
    messageRole: message?.role,
    messageContent: message?.content,
    toolCalls,
    toolResult:
      message?.role === "toolResult"
        ? {
            toolCallId: message.toolCallId,
            toolName: message.toolName,
            details: message.details,
            isError: message.isError,
          }
        : undefined,
    usage: message?.usage,
    raw: input.row,
  };
}

function normalizeGatewayLogPayload(
  sourceFile: string,
  line: CompletedLine,
  row: Record<string, unknown>,
): Record<string, unknown> {
  const messageParts = Object.keys(row)
    .filter((key) => /^\d+$/.test(key))
    .sort((a, b) => Number(a) - Number(b))
    .map((key) => row[key]);

  const message = messageParts.map(formatMessagePart).join(" ");
  return {
    sourceFile,
    lineNumber: line.lineNumber,
    byteOffset: line.byteOffset,
    time: row.time,
    level: row.level ?? objectValue(row._meta)?.logLevelName,
    message,
    messageParts,
    subsystem: extractSubsystem(messageParts),
    meta: row._meta,
    raw: row,
  };
}

async function normalizeBrowserArtifactPayload(
  filePath: string,
  artifactName: string,
  byteLength: number,
  modifiedAt: string,
): Promise<Record<string, unknown>> {
  if (artifactName.toLowerCase().endsWith(".zip")) {
    const parsed = await parseTraceZip(filePath);
    return {
      artifactType: "browser_trace",
      artifactPath: filePath,
      artifactName,
      byteLength,
      modifiedAt,
      entries: parsed.entries.slice(0, ZIP_ENTRY_DETAIL_LIMIT),
      entryCount: parsed.entries.length,
      networkRequests: parsed.networkRequests,
      parseWarnings: parsed.parseWarnings,
    };
  }

  const raw = await readFile(filePath, "utf8").catch(() => "");
  return {
    artifactType: inferBrowserArtifactType(artifactName),
    artifactPath: filePath,
    artifactName,
    byteLength,
    modifiedAt,
    data: parseJsonObject(raw) ?? raw,
  };
}

async function parseTraceZip(filePath: string): Promise<{
  entries: Array<Record<string, unknown>>;
  networkRequests: Array<Record<string, unknown>>;
  parseWarnings: string[];
}> {
  const warnings: string[] = [];
  const buffer = await readFile(filePath);
  const entries = parseZipCentralDirectory(buffer);
  const networkRequests: Array<Record<string, unknown>> = [];
  const networkEntry = entries.find((entry) => entry.fileName.endsWith("trace.network"));

  if (networkEntry) {
    try {
      const networkText = readZipEntry(buffer, networkEntry).toString("utf8");
      for (const line of networkText.split(/\r?\n/)) {
        if (networkRequests.length >= BROWSER_REQUEST_LIMIT) break;
        const parsed = parseJsonObject(line);
        const summary = parsed ? summarizeNetworkRecord(parsed) : undefined;
        if (summary) networkRequests.push(summary);
      }
    } catch (err) {
      warnings.push(`failed to parse trace.network: ${formatError(err)}`);
    }
  }

  return {
    entries: entries.map((entry) => ({
      fileName: entry.fileName,
      compressionMethod: entry.compressionMethod,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
    })),
    networkRequests,
    parseWarnings: warnings,
  };
}

function parseZipCentralDirectory(buffer: Buffer): ZipEntry[] {
  const eocdOffset = findEndOfCentralDirectory(buffer);
  if (eocdOffset < 0) return [];

  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  let offset = buffer.readUInt32LE(eocdOffset + 16);
  const entries: ZipEntry[] = [];

  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) break;

    const compressionMethod = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const fileName = buffer.subarray(offset + 46, offset + 46 + fileNameLength).toString("utf8");

    entries.push({
      fileName,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
    });

    offset += 46 + fileNameLength + extraLength + commentLength;
  }

  return entries;
}

function readZipEntry(buffer: Buffer, entry: ZipEntry): Buffer {
  const offset = entry.localHeaderOffset;
  if (offset + 30 > buffer.length || buffer.readUInt32LE(offset) !== 0x04034b50) {
    throw new Error(`invalid local zip header for ${entry.fileName}`);
  }

  const fileNameLength = buffer.readUInt16LE(offset + 26);
  const extraLength = buffer.readUInt16LE(offset + 28);
  const dataStart = offset + 30 + fileNameLength + extraLength;
  const compressed = buffer.subarray(dataStart, dataStart + entry.compressedSize);

  if (entry.compressionMethod === 0) return compressed;
  if (entry.compressionMethod === 8) return inflateRawSync(compressed);
  throw new Error(`unsupported zip compression method ${entry.compressionMethod} for ${entry.fileName}`);
}

function findEndOfCentralDirectory(buffer: Buffer): number {
  const minOffset = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= minOffset; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  return -1;
}

function summarizeNetworkRecord(record: Record<string, unknown>): Record<string, unknown> | undefined {
  const candidate = objectValue(record.snapshot) ?? objectValue(record.request) ?? record;
  const request = objectValue(candidate.request) ?? candidate;
  const response = objectValue(candidate.response);
  const url = stringValue(request.url) ?? stringValue(candidate.url);
  if (!url) return undefined;

  return {
    type: record.type,
    method: stringValue(request.method),
    url,
    status: numberValue(response?.status) ?? numberValue(candidate.status),
    statusText: stringValue(response?.statusText),
    resourceType: stringValue(candidate.resourceType),
    serverAddr: candidate.serverAddr,
    timing: candidate.timing,
    requestHeaders: request.headers,
    responseHeaders: response?.headers,
  };
}

async function discoverGatewayLogFiles(stateDir: string): Promise<string[]> {
  const candidates = new Set<string>();
  addEnvPath(candidates, "OPENCLAW_GATEWAY_LOG");
  addEnvPath(candidates, "OPENCLAW_LOG_PATH");
  addEnvPath(candidates, "OPENCLAW_LOG_FILE");

  for (const dir of [path.join(os.tmpdir(), "openclaw"), path.join(stateDir, "logs")]) {
    const entries = await readDirSafe(dir);
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (/^openclaw-\d{4}-\d{2}-\d{2}\.log$/.test(entry.name) || /^gateway.*\.log$/i.test(entry.name)) {
        candidates.add(path.join(dir, entry.name));
      }
    }
  }

  return filterExistingFiles([...candidates]);
}

async function discoverBrowserArtifacts(): Promise<string[]> {
  const candidates = new Set<string>();
  const tempOpenClawDir = path.join(os.tmpdir(), "openclaw");
  const entries = await readDirSafe(tempOpenClawDir);

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (/^browser-trace-.*\.zip$/i.test(entry.name) || /^browser-(requests|snapshot).*\.json$/i.test(entry.name)) {
      candidates.add(path.join(tempOpenClawDir, entry.name));
    }
  }

  return filterExistingFiles([...candidates]);
}

async function filterExistingFiles(paths: string[]): Promise<string[]> {
  const existing: string[] = [];
  for (const filePath of paths) {
    const fileStat = await stat(filePath).catch(() => undefined);
    if (fileStat?.isFile()) existing.push(filePath);
  }
  return existing.sort();
}

function addEnvPath(paths: Set<string>, envName: string): void {
  const value = process.env[envName];
  if (value) paths.add(value);
}

async function readDirSafe(dir: string): Promise<Dirent[]> {
  return readdir(dir, { withFileTypes: true }).catch((err: NodeJS.ErrnoException) => {
    if (err.code === "ENOENT") return [];
    throw err;
  });
}

function initialCollectorCheckpoint(): CollectorCheckpoint {
  return {
    version: 1,
    files: {},
    browserArtifacts: {},
    recentEventIds: [],
  };
}

function normalizeCollectorCheckpoint(value: unknown): CollectorCheckpoint {
  if (!value || typeof value !== "object") return initialCollectorCheckpoint();
  const candidate = value as Partial<CollectorCheckpoint>;
  const files: Record<string, CollectorFileCursor> = {};
  const browserArtifacts: Record<string, BrowserArtifactCursor> = {};

  if (candidate.files && typeof candidate.files === "object" && !Array.isArray(candidate.files)) {
    for (const [key, cursor] of Object.entries(candidate.files)) {
      if (!cursor || typeof cursor !== "object") continue;
      const fileCursor = cursor as Partial<CollectorFileCursor>;
      if (fileCursor.source !== "agent_session" && fileCursor.source !== "gateway_log") continue;
      if (typeof fileCursor.signature !== "string") continue;
      if (!Number.isSafeInteger(fileCursor.offset) || fileCursor.offset < 0) continue;
      if (!Number.isSafeInteger(fileCursor.lineNumber) || fileCursor.lineNumber < 0) continue;
      files[key] = {
        source: fileCursor.source,
        signature: fileCursor.signature,
        offset: fileCursor.offset,
        lineNumber: fileCursor.lineNumber,
        ...(typeof fileCursor.lastLineHash === "string" ? { lastLineHash: fileCursor.lastLineHash } : {}),
        lastSeenAt:
          typeof fileCursor.lastSeenAt === "string" && !Number.isNaN(Date.parse(fileCursor.lastSeenAt))
            ? fileCursor.lastSeenAt
            : new Date().toISOString(),
      };
    }
  }

  if (
    candidate.browserArtifacts &&
    typeof candidate.browserArtifacts === "object" &&
    !Array.isArray(candidate.browserArtifacts)
  ) {
    for (const [key, artifact] of Object.entries(candidate.browserArtifacts)) {
      if (!artifact || typeof artifact !== "object") continue;
      const browserArtifact = artifact as Partial<BrowserArtifactCursor>;
      if (typeof browserArtifact.signature !== "string") continue;
      browserArtifacts[key] = {
        signature: browserArtifact.signature,
        emittedAt:
          typeof browserArtifact.emittedAt === "string" && !Number.isNaN(Date.parse(browserArtifact.emittedAt))
            ? browserArtifact.emittedAt
            : new Date().toISOString(),
      };
    }
  }

  const recentEventIds = Array.isArray(candidate.recentEventIds)
    ? candidate.recentEventIds.filter((id): id is string => typeof id === "string")
    : [];

  return {
    version: 1,
    files,
    browserArtifacts,
    recentEventIds: recentEventIds.slice(-FILE_COLLECTOR_RECENT_EVENT_LIMIT),
  };
}

function cloneCheckpoint(checkpoint: CollectorCheckpoint): CollectorCheckpoint {
  return JSON.parse(JSON.stringify(checkpoint)) as CollectorCheckpoint;
}

function parseJsonObject(text: string): Record<string, unknown> | undefined {
  const trimmed = stripJsonBom(text).trim();
  if (!trimmed) return undefined;

  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function normalizeTimestamp(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const timestampMs = Date.parse(value);
  if (Number.isNaN(timestampMs)) return undefined;
  return new Date(timestampMs).toISOString();
}

function cursorSignature(fileStat: Stats): string {
  return `${fileStat.dev}:${fileStat.ino}:${Math.trunc(fileStat.birthtimeMs)}`;
}

function artifactSignature(fileStat: Stats): string {
  return `${fileStat.size}:${Math.trunc(fileStat.mtimeMs)}`;
}

function normalizePathKey(filePath: string): string {
  const resolved = path.resolve(filePath);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function lastCompletedLineLength(buffer: Buffer): number {
  for (let index = buffer.length - 1; index >= 0; index -= 1) {
    if (buffer[index] === 10) return index + 1;
  }
  return 0;
}

function hashText(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

function stripJsonBom(raw: string): string {
  return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function formatMessagePart(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function extractSubsystem(messageParts: unknown[]): string | undefined {
  for (const part of messageParts) {
    const obj = objectValue(part);
    if (typeof obj?.subsystem === "string") return obj.subsystem;
    if (typeof obj?.module === "string") return obj.module;
  }
  return undefined;
}

function inferBrowserArtifactType(fileName: string): string {
  if (/requests/i.test(fileName)) return "browser_requests";
  if (/snapshot/i.test(fileName)) return "browser_snapshot";
  return "browser_artifact";
}

function formatError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
