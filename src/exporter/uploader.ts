import { gzip as gzipCallback } from "node:zlib";
import { promisify } from "node:util";
import path from "node:path";
import { readFile, rm } from "node:fs/promises";
import {
  EXPORT_BUCKET,
  EXPORT_ROOT_PREFIX,
  LEASE_REFRESH_THRESHOLD_MS,
  RECENT_UPLOAD_LIMIT,
  UPLOAD_LEASE_URL,
  UPLOAD_LOOP_INTERVAL_MS,
} from "./types";
import type { ExporterRuntime, UploadLease } from "./types";
import {
  CheckpointStore,
  EventWriter,
  chunkId,
  listReadyChunks,
  padSeq,
  readJsonlSegmentMeta,
  writeJsonAtomic,
} from "./event-writer";

const gzip = promisify(gzipCallback);

export class SegmentUploader {
  private timer?: ReturnType<typeof setInterval>;
  private inFlight?: Promise<void>;
  private stopped = false;
  private cachedLease?: UploadLease;
  private leaseFailureCount = 0;
  private nextLeaseAttemptAtMs = 0;

  constructor(
    private readonly runtime: ExporterRuntime,
    private readonly checkpointStore: CheckpointStore,
    private readonly writer: EventWriter,
  ) {}

  startPeriodicLoop(): void {
    if (this.timer) return;

    this.stopped = false;
    this.timer = setInterval(() => {
      void this.kick().catch((err) => {
        this.runtime.logger.warn("periodic upload attempt failed", err);
      });
    }, UPLOAD_LOOP_INTERVAL_MS);
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
        this.runtime.logger.warn("upload attempt failed while stopping", err);
      });
    }
  }

  async kick(): Promise<void> {
    if (this.inFlight) return this.inFlight;

    this.inFlight = this.runOnce().finally(() => {
      this.inFlight = undefined;
    });

    return this.inFlight;
  }

  async runOnce(): Promise<void> {
    await this.writer.flushExpired();
    await this.uploadReadyChunks();
  }

  async uploadReadyChunks(): Promise<void> {
    const readyChunks = await listReadyChunks(this.runtime.paths.spoolDir);
    for (const readyChunk of readyChunks) {
      if (this.stopped) return;
      await this.uploadReadyChunk(readyChunk.filePath, readyChunk.seqStart, readyChunk.seqEnd);
    }
  }

  private async uploadReadyChunk(filePath: string, seqStart: number, seqEnd: number): Promise<void> {
    const segmentMeta = await readJsonlSegmentMeta(filePath);
    if (segmentMeta.eventCount === 0) {
      throw new Error(`ready chunk is empty: ${filePath}`);
    }

    const raw = await readFile(filePath);
    const gzipped = await gzip(raw);
    const generatedS3Key = buildS3Key(this.runtime, seqStart, seqEnd, segmentMeta.firstTs);
    const lease = await this.getUploadLease();
    const uploadKey = resolveS3PostKey(lease, generatedS3Key);

    if (!uploadKey.s3Key.startsWith(lease.keyPrefix)) {
      throw new Error(`S3 key ${uploadKey.s3Key} is outside lease prefix ${lease.keyPrefix}`);
    }

    if (uploadKey.usesExactLeaseKey && uploadKey.s3Key !== generatedS3Key) {
      this.runtime.logger.warn(
        `upload lease pins S3 key ${uploadKey.s3Key}; generated key ${generatedS3Key} cannot be used with this policy`,
      );
    }

    await uploadWithPresignedPost(lease, uploadKey.s3Key, gzipped);

    await this.checkpointStore.update((checkpoint) => {
      checkpoint.uploadedThroughSeq = Math.max(checkpoint.uploadedThroughSeq, seqEnd);
      checkpoint.recentUploads.push({
        chunkId: chunkId(seqStart, seqEnd),
        seqStart,
        seqEnd,
        s3Bucket: EXPORT_BUCKET,
        s3Key: uploadKey.s3Key,
        uploadedAt: new Date().toISOString(),
      });
      checkpoint.recentUploads = checkpoint.recentUploads.slice(-RECENT_UPLOAD_LIMIT);
    });

    if (uploadKey.usesExactLeaseKey) {
      await this.invalidateCachedLease();
    }

    await rm(filePath, { force: true });
  }

  private async invalidateCachedLease(): Promise<void> {
    this.cachedLease = undefined;
    await rm(this.runtime.paths.leasePath, { force: true });
  }

  private async getUploadLease(): Promise<UploadLease> {
    if (isLeaseFresh(this.cachedLease)) {
      return this.cachedLease;
    }

    const cached = await readCachedLease(this.runtime.paths.leasePath, this.runtime.logger);
    if (isLeaseFresh(cached)) {
      this.cachedLease = cached;
      return cached;
    }

    const now = Date.now();
    if (now < this.nextLeaseAttemptAtMs) {
      throw new Error(`upload lease refresh is backing off until ${new Date(this.nextLeaseAttemptAtMs).toISOString()}`);
    }

    try {
      const lease = await requestUploadLease(this.runtime);
      this.cachedLease = lease;
      this.leaseFailureCount = 0;
      this.nextLeaseAttemptAtMs = 0;
      await writeJsonAtomic(this.runtime.paths.leasePath, lease);
      return lease;
    } catch (err) {
      this.leaseFailureCount += 1;
      const delayMs = Math.min(60_000, 1000 * 2 ** Math.min(this.leaseFailureCount - 1, 6));
      this.nextLeaseAttemptAtMs = Date.now() + delayMs;
      throw err;
    }
  }
}

export function buildS3Key(
  runtime: Pick<ExporterRuntime, "apiKeyPathId" | "host">,
  seqStart: number,
  seqEnd: number,
  ts?: string,
): string {
  const date = ts ? new Date(ts) : new Date();
  const iso = Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
  const dt = iso.slice(0, 10);
  const hour = iso.slice(11, 13);

  return `${EXPORT_ROOT_PREFIX}apiKey=${runtime.apiKeyPathId}/host=${runtime.host}/dt=${dt}/hour=${hour}/chunk-${padSeq(
    seqStart,
  )}-${padSeq(seqEnd)}.jsonl.gz`;
}

export function resolveS3PostKey(
  lease: UploadLease,
  generatedS3Key: string,
): { s3Key: string; usesExactLeaseKey: boolean } {
  const exactPolicyKey = getExactPolicyKey(lease.fields.Policy);
  if (exactPolicyKey) {
    return {
      s3Key: exactPolicyKey,
      usesExactLeaseKey: true,
    };
  }

  return {
    s3Key: generatedS3Key,
    usesExactLeaseKey: false,
  };
}

export function resolveUploadLeaseUrl(): string {
  return UPLOAD_LEASE_URL;
}

async function readCachedLease(leasePath: string, logger: ExporterRuntime["logger"]): Promise<UploadLease | undefined> {
  try {
    const raw = await readFile(leasePath, "utf8");
    return normalizeUploadLease(JSON.parse(raw));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code !== "ENOENT") {
      logger.warn("ignoring invalid cached upload lease", err);
    }
    return undefined;
  }
}

async function requestUploadLease(runtime: ExporterRuntime): Promise<UploadLease> {
  const prefix = `${EXPORT_ROOT_PREFIX}apiKey=${runtime.apiKeyPathId}/`;
  const response = await fetch(resolveUploadLeaseUrl(), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${runtime.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      prefix,
      apiKeyPathId: runtime.apiKeyPathId,
      host: runtime.host,
    }),
  });

  if (!response.ok) {
    throw new Error(`upload lease request failed: ${response.status} ${response.statusText} ${await response.text()}`);
  }

  const lease = normalizeUploadLease(await response.json());
  if (!lease) {
    throw new Error("upload lease response has invalid shape");
  }

  if (lease.bucket !== EXPORT_BUCKET) {
    throw new Error(`upload lease returned unexpected bucket: ${lease.bucket}`);
  }

  if (lease.keyPrefix !== prefix) {
    throw new Error(`upload lease returned unexpected keyPrefix: ${lease.keyPrefix}`);
  }

  return lease;
}

async function uploadWithPresignedPost(lease: UploadLease, s3Key: string, gzipped: Buffer): Promise<void> {
  const form = new FormData();
  for (const [key, value] of Object.entries(lease.fields)) {
    if (key === "key") continue;
    form.append(key, value);
  }
  form.append("key", s3Key);
  form.append("file", new Blob([gzipped], { type: "application/gzip" }), path.basename(s3Key));

  const response = await fetch(lease.url, {
    method: "POST",
    body: form,
  });

  if (![200, 201, 204].includes(response.status)) {
    throw new Error(`S3 upload failed: ${response.status} ${response.statusText} ${await response.text()}`);
  }
}

function getExactPolicyKey(policyBase64: string | undefined): string | undefined {
  if (!policyBase64) return undefined;

  try {
    const policy = JSON.parse(Buffer.from(policyBase64, "base64").toString("utf8")) as {
      conditions?: unknown[];
    };
    if (!Array.isArray(policy.conditions)) return undefined;

    for (const condition of policy.conditions) {
      if (
        Array.isArray(condition) &&
        condition[0] === "eq" &&
        condition[1] === "$key" &&
        typeof condition[2] === "string"
      ) {
        return condition[2];
      }

      if (condition && typeof condition === "object" && !Array.isArray(condition)) {
        const key = (condition as Record<string, unknown>).key;
        if (typeof key === "string") return key;
      }
    }
  } catch {
    return undefined;
  }

  return undefined;
}

function isLeaseFresh(lease: UploadLease | undefined): lease is UploadLease {
  if (!lease) return false;
  const expiresAtMs = Date.parse(lease.expiresAt);
  if (Number.isNaN(expiresAtMs)) return false;
  return expiresAtMs - Date.now() > LEASE_REFRESH_THRESHOLD_MS;
}

function normalizeUploadLease(value: unknown): UploadLease | undefined {
  if (!value || typeof value !== "object") return undefined;
  const lease = value as Partial<UploadLease>;
  if (lease.type !== "s3-post") return undefined;
  if (lease.bucket !== EXPORT_BUCKET) return undefined;
  if (typeof lease.url !== "string") return undefined;
  if (!lease.fields || typeof lease.fields !== "object" || Array.isArray(lease.fields)) return undefined;
  if (typeof lease.keyPrefix !== "string") return undefined;
  if (typeof lease.expiresAt !== "string" || Number.isNaN(Date.parse(lease.expiresAt))) return undefined;

  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(lease.fields)) {
    if (typeof value !== "string") return undefined;
    fields[key] = value;
  }

  return {
    type: "s3-post",
    bucket: EXPORT_BUCKET,
    url: lease.url,
    fields,
    keyPrefix: lease.keyPrefix,
    expiresAt: lease.expiresAt,
  };
}
