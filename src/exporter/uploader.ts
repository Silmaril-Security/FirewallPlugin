import { randomUUID } from "node:crypto";
import { gzip as gzipCallback } from "node:zlib";
import { promisify } from "node:util";
import path from "node:path";
import { readFile, rm } from "node:fs/promises";
import {
  EXPORT_BUCKET,
  EXPORT_LOGS_PREFIX,
  LEASE_MAX_AGE_MS,
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
    const s3Key = await this.uploadWithLeaseRetry(gzipped);

    await this.checkpointStore.update((checkpoint) => {
      checkpoint.uploadedThroughSeq = Math.max(checkpoint.uploadedThroughSeq, seqEnd);
      checkpoint.recentUploads.push({
        chunkId: chunkId(seqStart, seqEnd),
        seqStart,
        seqEnd,
        s3Bucket: EXPORT_BUCKET,
        s3Key,
        uploadedAt: new Date().toISOString(),
      });
      checkpoint.recentUploads = checkpoint.recentUploads.slice(-RECENT_UPLOAD_LIMIT);
    });

    await rm(filePath, { force: true });
  }

  private async uploadWithLeaseRetry(gzipped: Buffer): Promise<string> {
    let lastS3Key: string | undefined;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const lease = await this.getUploadLease();
      if (lease.maxObjectBytes !== undefined && gzipped.byteLength > lease.maxObjectBytes) {
        throw new Error(
          `gzipped export segment is ${gzipped.byteLength} bytes; lease maxObjectBytes is ${lease.maxObjectBytes}`,
        );
      }

      const s3Key = buildObjectKey(lease);
      if (!s3Key.startsWith(lease.keyPrefix)) {
        throw new Error(`S3 key ${s3Key} is outside lease prefix ${lease.keyPrefix}`);
      }
      lastS3Key = s3Key;

      try {
        await uploadWithPresignedPost(lease, s3Key, gzipped);
        return s3Key;
      } catch (err) {
        const refreshLease = shouldRefreshLeaseAfterUploadError(err);
        if (refreshLease) {
          await this.invalidateCachedLease();
        }

        if (attempt === 0 && (refreshLease || shouldRetryWithFreshObjectKey(err))) {
          const reason = refreshLease
            ? "S3 upload lease was rejected; refreshed upload lease and retrying"
            : "S3 upload key was rejected; retrying with a fresh object key";
          this.runtime.logger.warn(reason, err);
          continue;
        }

        throw err;
      }
    }

    throw new Error(`S3 upload failed before completion${lastS3Key ? ` for ${lastS3Key}` : ""}`);
  }

  private async invalidateCachedLease(): Promise<void> {
    this.cachedLease = undefined;
    this.leaseFailureCount = 0;
    this.nextLeaseAttemptAtMs = 0;
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

export function isValidLeasePrefix(keyPrefix: string): boolean {
  if (!keyPrefix.startsWith(EXPORT_LOGS_PREFIX) || !keyPrefix.endsWith("/")) {
    return false;
  }

  const suffix = keyPrefix.slice(EXPORT_LOGS_PREFIX.length, -1);
  return suffix.length > 0 && !suffix.includes("/") && !suffix.includes("..");
}

export function buildObjectKey(
  lease: Pick<UploadLease, "keyPrefix">,
  now = new Date(),
  uuid = randomUUID(),
): string {
  const date = Number.isNaN(now.getTime()) ? new Date() : now;
  const yyyy = String(date.getUTCFullYear());
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");

  return `${lease.keyPrefix}${yyyy}/${mm}/${dd}/${hh}/${uuid}.jsonl.gz`;
}

export function resolveUploadLeaseUrl(): string {
  return UPLOAD_LEASE_URL;
}

async function readCachedLease(leasePath: string, logger: ExporterRuntime["logger"]): Promise<UploadLease | undefined> {
  try {
    const raw = await readFile(leasePath, "utf8");
    return normalizeUploadLease(JSON.parse(stripJsonBom(raw)));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code !== "ENOENT") {
      logger.warn("ignoring invalid cached upload lease", err);
    }
    return undefined;
  }
}

async function requestUploadLease(runtime: ExporterRuntime): Promise<UploadLease> {
  const response = await fetch(resolveUploadLeaseUrl(), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${runtime.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      host: runtime.host,
      ...(runtime.userEmail ? { userEmail: runtime.userEmail } : {}),
    }),
  });

  if (!response.ok) {
    throw new Error(`upload lease request failed: ${response.status} ${response.statusText} ${await response.text()}`);
  }

  const lease = normalizeUploadLease(await response.json(), new Date().toISOString());
  if (!lease) {
    throw new Error("upload lease response has invalid shape");
  }

  if (lease.bucket !== EXPORT_BUCKET) {
    throw new Error(`upload lease returned unexpected bucket: ${lease.bucket}`);
  }

  if (hasExactPolicyKey(lease.fields.Policy)) {
    throw new Error("upload lease policy pins an exact S3 key; expected reusable prefix policy");
  }

  if (!isValidLeasePrefix(lease.keyPrefix)) {
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
  form.append("file", new Blob([gzipped], { type: lease.contentType ?? "application/gzip" }), path.basename(s3Key));

  const response = await fetch(lease.url, {
    method: "POST",
    body: form,
  });

  if (![200, 201, 204].includes(response.status)) {
    const body = await response.text();
    throw new S3UploadError(response.status, response.statusText, body);
  }
}

function isLeaseFresh(lease: UploadLease | undefined): lease is UploadLease {
  if (!lease) return false;
  if (!isValidLeasePrefix(lease.keyPrefix)) return false;
  if (hasExactPolicyKey(lease.fields.Policy)) return false;

  const fetchedAtMs = Date.parse(lease.fetchedAt);
  if (Number.isNaN(fetchedAtMs)) return false;
  if (Date.now() - fetchedAtMs >= LEASE_MAX_AGE_MS) return false;

  const expiresAtMs = Date.parse(lease.expiresAt);
  if (Number.isNaN(expiresAtMs)) return false;
  return expiresAtMs - Date.now() > LEASE_REFRESH_THRESHOLD_MS;
}

function normalizeUploadLease(value: unknown, fetchedAtOverride?: string): UploadLease | undefined {
  if (!value || typeof value !== "object") return undefined;
  const lease = value as Partial<UploadLease>;
  if (lease.type !== "s3-post") return undefined;
  if (lease.bucket !== EXPORT_BUCKET) return undefined;
  if (typeof lease.url !== "string") return undefined;
  if (!lease.fields || typeof lease.fields !== "object" || Array.isArray(lease.fields)) return undefined;
  if (typeof lease.keyPrefix !== "string") return undefined;
  if (typeof lease.expiresAt !== "string" || Number.isNaN(Date.parse(lease.expiresAt))) return undefined;

  const fetchedAt = fetchedAtOverride ?? lease.fetchedAt;
  if (typeof fetchedAt !== "string" || Number.isNaN(Date.parse(fetchedAt))) return undefined;

  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(lease.fields)) {
    if (typeof value !== "string") return undefined;
    fields[key] = value;
  }

  const contentType = typeof lease.contentType === "string" ? lease.contentType : fields["Content-Type"];
  if (contentType !== undefined && contentType !== "application/gzip") return undefined;

  const keyTemplate = typeof lease.keyTemplate === "string" ? lease.keyTemplate : undefined;
  const maxObjectBytes =
    Number.isSafeInteger(lease.maxObjectBytes) && lease.maxObjectBytes! > 0 ? lease.maxObjectBytes : undefined;
  const expiresInSeconds =
    Number.isSafeInteger(lease.expiresInSeconds) && lease.expiresInSeconds! > 0
      ? lease.expiresInSeconds
      : undefined;

  return {
    type: "s3-post",
    bucket: EXPORT_BUCKET,
    url: lease.url,
    fields,
    keyPrefix: lease.keyPrefix,
    ...(keyTemplate ? { keyTemplate } : {}),
    ...(contentType ? { contentType } : {}),
    ...(maxObjectBytes ? { maxObjectBytes } : {}),
    ...(expiresInSeconds ? { expiresInSeconds } : {}),
    expiresAt: lease.expiresAt,
    fetchedAt,
  };
}

class S3UploadError extends Error {
  readonly s3Code?: string;

  constructor(
    readonly status: number,
    readonly statusText: string,
    readonly body: string,
  ) {
    super(`S3 upload failed: ${status} ${statusText} ${body}`);
    this.name = "S3UploadError";
    this.s3Code = extractS3ErrorCode(body);
  }
}

function shouldRefreshLeaseAfterUploadError(err: unknown): boolean {
  if (err instanceof S3UploadError) {
    return err.status === 403 || err.s3Code === "ExpiredToken" || err.body.includes("ExpiredToken");
  }

  return err instanceof Error && err.message.includes("ExpiredToken");
}

function shouldRetryWithFreshObjectKey(err: unknown): boolean {
  if (!(err instanceof S3UploadError)) return false;
  return err.status === 409 || err.s3Code === "OperationAborted" || err.body.includes("KeyAlreadyExists");
}

function extractS3ErrorCode(body: string): string | undefined {
  return /<Code>([^<]+)<\/Code>/.exec(body)?.[1];
}

function stripJsonBom(raw: string): string {
  return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
}

function hasExactPolicyKey(policyBase64: string | undefined): boolean {
  if (!policyBase64) return false;

  try {
    const policy = JSON.parse(Buffer.from(policyBase64, "base64").toString("utf8")) as {
      conditions?: unknown[];
    };
    if (!Array.isArray(policy.conditions)) return false;

    return policy.conditions.some((condition) => {
      if (Array.isArray(condition)) {
        return condition[0] === "eq" && condition[1] === "$key" && typeof condition[2] === "string";
      }

      if (condition && typeof condition === "object") {
        return typeof (condition as Record<string, unknown>).key === "string";
      }

      return false;
    });
  } catch {
    return false;
  }
}
