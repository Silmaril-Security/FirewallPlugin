import { randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  EVENT_REORDER_WINDOW_MS,
  EVENT_SEQUENCER_LOOP_INTERVAL_MS,
  EVENT_SEQUENCER_RECENT_EVENT_LIMIT,
} from "./types";
import { isValidTimestamp, toJsonSafe, writeJsonAtomic } from "./event-writer";
import type { EventWriter } from "./event-writer";
import type {
  ExportSource,
  ExporterLogger,
  ExporterPaths,
  ExporterRuntime,
  FirewallExportEventInput,
} from "./types";

type SequencerCheckpoint = {
  version: 1;
  recentEventIds: string[];
};

export type QueuedExportEvent = {
  version: 1;
  eventId: string;
  createdAt: string;
  sourceTs: string;
  sourcePriority: number;
  event: FirewallExportEventInput & {
    eventId: string;
    ts: string;
  };
};

export type ReadyInboxEvent = {
  fileName: string;
  filePath: string;
  queued: QueuedExportEvent;
};

type EventSequencerOptions = {
  loopIntervalMs?: number;
  reorderWindowMs?: number;
  beforeDrain?: () => Promise<void>;
};

export class DurableEventInbox {
  constructor(
    private readonly paths: Pick<ExporterPaths, "inboxTmpDir" | "inboxReadyDir">,
    private readonly logger: ExporterLogger,
  ) {}

  async enqueue(input: FirewallExportEventInput): Promise<QueuedExportEvent> {
    await this.ensureDirectories();

    const queued = prepareQueuedEvent(input);
    const uniqueName = `${Date.now()}-${process.pid}-${queued.sourcePriority}-${queued.eventId.replace(
      /[^A-Za-z0-9_.-]/g,
      "_",
    )}-${randomUUID()}.json`;
    const tmpPath = path.join(this.paths.inboxTmpDir, `${uniqueName}.tmp`);
    const readyPath = path.join(this.paths.inboxReadyDir, uniqueName);

    await writeFile(tmpPath, `${JSON.stringify(queued)}\n`, { encoding: "utf8", flag: "wx" });
    await rename(tmpPath, readyPath);
    return queued;
  }

  async listReady(): Promise<ReadyInboxEvent[]> {
    await this.ensureDirectories();

    const entries = await readdir(this.paths.inboxReadyDir).catch((err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") return [];
      throw err;
    });

    const ready: ReadyInboxEvent[] = [];
    for (const fileName of entries.sort()) {
      if (!fileName.endsWith(".json")) continue;

      const filePath = path.join(this.paths.inboxReadyDir, fileName);
      let parsed: unknown;
      try {
        parsed = JSON.parse(stripJsonBom(await readFile(filePath, "utf8")));
      } catch (err) {
        this.logger.warn(`leaving invalid exporter inbox file in place: ${fileName}`, err);
        continue;
      }

      const queued = normalizeQueuedEvent(parsed);
      if (!queued) {
        this.logger.warn(`leaving invalid exporter inbox file in place: ${fileName}`);
        continue;
      }

      ready.push({
        fileName,
        filePath,
        queued,
      });
    }

    return ready;
  }

  async remove(file: Pick<ReadyInboxEvent, "filePath">): Promise<void> {
    await rm(file.filePath, { force: true });
  }

  private async ensureDirectories(): Promise<void> {
    await mkdir(this.paths.inboxTmpDir, { recursive: true });
    await mkdir(this.paths.inboxReadyDir, { recursive: true });
  }
}

export class EventSequencer {
  private timer?: ReturnType<typeof setInterval>;
  private inFlight?: Promise<void>;
  private stopped = false;
  private checkpoint?: SequencerCheckpoint;

  private readonly loopIntervalMs: number;
  private readonly reorderWindowMs: number;
  private readonly beforeDrain?: () => Promise<void>;

  constructor(
    private readonly runtime: ExporterRuntime,
    private readonly inbox: DurableEventInbox,
    private readonly writer: EventWriter,
    private readonly checkpointPath: string,
    options: EventSequencerOptions = {},
  ) {
    this.loopIntervalMs = options.loopIntervalMs ?? EVENT_SEQUENCER_LOOP_INTERVAL_MS;
    this.reorderWindowMs = options.reorderWindowMs ?? EVENT_REORDER_WINDOW_MS;
    this.beforeDrain = options.beforeDrain;
  }

  startPeriodicLoop(): void {
    if (this.timer) return;

    this.stopped = false;
    this.timer = setInterval(() => {
      void this.kick().catch((err) => {
        this.runtime.logger.warn("event sequencer drain failed", err);
      });
    }, this.loopIntervalMs);
    this.timer.unref?.();
  }

  async kick(options: { flushAll?: boolean } = {}): Promise<void> {
    if (this.inFlight) return this.inFlight;

    this.inFlight = this.runOnce(Boolean(options.flushAll)).finally(() => {
      this.inFlight = undefined;
    });

    return this.inFlight;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }

    if (this.inFlight) {
      await this.inFlight.catch((err) => {
        this.runtime.logger.warn("event sequencer drain failed while stopping", err);
      });
    }

    await this.kick({ flushAll: true });
    if (this.checkpoint) {
      await writeJsonAtomic(this.checkpointPath, this.checkpoint);
    }
  }

  private async runOnce(flushAll: boolean): Promise<void> {
    const checkpoint = await this.loadCheckpoint();
    if (!flushAll && this.beforeDrain) {
      await this.beforeDrain();
    }

    const recent = new Set(checkpoint.recentEventIds);
    const cutoffMs = Date.now() - this.reorderWindowMs;
    const ready = await this.inbox.listReady();

    const eligible = ready
      .filter((file) => {
        if (flushAll) return true;
        return Date.parse(file.queued.sourceTs) <= cutoffMs;
      })
      .sort(compareReadyInboxEvents);

    for (const file of eligible) {
      if (!flushAll && this.stopped) return;

      const { eventId } = file.queued;
      if (recent.has(eventId)) {
        await this.inbox.remove(file);
        continue;
      }

      await this.writer.writeEvent(file.queued.event);
      recent.add(eventId);
      checkpoint.recentEventIds.push(eventId);
      checkpoint.recentEventIds = checkpoint.recentEventIds.slice(-EVENT_SEQUENCER_RECENT_EVENT_LIMIT);
      this.checkpoint = normalizeSequencerCheckpoint(checkpoint);
      await writeJsonAtomic(this.checkpointPath, this.checkpoint);
      await this.inbox.remove(file);
    }
  }

  private async loadCheckpoint(): Promise<SequencerCheckpoint> {
    if (this.checkpoint) return this.checkpoint;

    try {
      const raw = await readFile(this.checkpointPath, "utf8");
      this.checkpoint = normalizeSequencerCheckpoint(JSON.parse(stripJsonBom(raw)));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        this.runtime.logger.warn("ignoring invalid event sequencer checkpoint", err);
      }
      this.checkpoint = initialSequencerCheckpoint();
    }

    return this.checkpoint;
  }
}

export function prepareQueuedEvent(input: FirewallExportEventInput, now = new Date()): QueuedExportEvent {
  const createdAt = validDate(now).toISOString();
  const ts = isValidTimestamp(input.ts) ? new Date(Date.parse(input.ts)).toISOString() : createdAt;
  const eventId = input.eventId && input.eventId.length > 0 ? input.eventId : generatedEventId(input.source, createdAt);

  return {
    version: 1,
    eventId,
    createdAt,
    sourceTs: ts,
    sourcePriority: sourcePriority(input.source),
    event: {
      source: input.source,
      ts,
      eventId,
      ...(input.hookName ? { hookName: input.hookName } : {}),
      ...(input.toolName ? { toolName: input.toolName } : {}),
      payload: toJsonSafe(input.payload),
      ...(input.firewallResult !== undefined ? { firewallResult: toJsonSafe(input.firewallResult) } : {}),
    },
  };
}

function compareReadyInboxEvents(a: ReadyInboxEvent, b: ReadyInboxEvent): number {
  const tsCompare = Date.parse(a.queued.sourceTs) - Date.parse(b.queued.sourceTs);
  if (tsCompare !== 0) return tsCompare;

  const priorityCompare = a.queued.sourcePriority - b.queued.sourcePriority;
  if (priorityCompare !== 0) return priorityCompare;

  const eventIdCompare = a.queued.eventId.localeCompare(b.queued.eventId);
  if (eventIdCompare !== 0) return eventIdCompare;

  return a.fileName.localeCompare(b.fileName);
}

function normalizeQueuedEvent(value: unknown): QueuedExportEvent | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Partial<QueuedExportEvent>;
  if (candidate.version !== 1) return undefined;
  if (typeof candidate.eventId !== "string" || candidate.eventId.length === 0) return undefined;
  if (!isValidTimestamp(candidate.createdAt)) return undefined;
  if (!isValidTimestamp(candidate.sourceTs)) return undefined;
  if (!Number.isSafeInteger(candidate.sourcePriority)) return undefined;
  if (!candidate.event || typeof candidate.event !== "object") return undefined;

  const event = candidate.event as Partial<FirewallExportEventInput>;
  if (!isExportSource(event.source)) return undefined;
  if (!isValidTimestamp(event.ts)) return undefined;
  if (typeof event.eventId !== "string" || event.eventId.length === 0) return undefined;
  if (event.eventId !== candidate.eventId) return undefined;

  return {
    version: 1,
    eventId: candidate.eventId,
    createdAt: new Date(Date.parse(candidate.createdAt)).toISOString(),
    sourceTs: new Date(Date.parse(candidate.sourceTs)).toISOString(),
    sourcePriority: candidate.sourcePriority,
    event: {
      source: event.source,
      ts: new Date(Date.parse(event.ts)).toISOString(),
      eventId: event.eventId,
      ...(event.hookName ? { hookName: event.hookName } : {}),
      ...(event.toolName ? { toolName: event.toolName } : {}),
      payload: event.payload,
      ...(event.firewallResult !== undefined ? { firewallResult: event.firewallResult } : {}),
    },
  };
}

function sourcePriority(source: ExportSource): number {
  switch (source) {
    case "user_input":
    case "tool_call":
    case "tool_response":
      return 10;
    case "hook_event":
      return 20;
    case "agent_session_event":
      return 30;
    case "gateway_log_event":
      return 40;
    case "browser_telemetry_event":
      return 50;
  }
}

function isExportSource(value: unknown): value is ExportSource {
  return (
    value === "user_input" ||
    value === "tool_call" ||
    value === "tool_response" ||
    value === "hook_event" ||
    value === "agent_session_event" ||
    value === "gateway_log_event" ||
    value === "browser_telemetry_event"
  );
}

function generatedEventId(source: ExportSource, createdAt: string): string {
  return `runtime-hook:${source}:${createdAt}:${process.pid}:${randomUUID()}`;
}

function validDate(date: Date): Date {
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function initialSequencerCheckpoint(): SequencerCheckpoint {
  return {
    version: 1,
    recentEventIds: [],
  };
}

function normalizeSequencerCheckpoint(value: unknown): SequencerCheckpoint {
  if (!value || typeof value !== "object") return initialSequencerCheckpoint();
  const candidate = value as Partial<SequencerCheckpoint>;
  const recentEventIds = Array.isArray(candidate.recentEventIds)
    ? candidate.recentEventIds.filter((id): id is string => typeof id === "string" && id.length > 0)
    : [];

  return {
    version: 1,
    recentEventIds: recentEventIds.slice(-EVENT_SEQUENCER_RECENT_EVENT_LIMIT),
  };
}

function stripJsonBom(raw: string): string {
  return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
}
