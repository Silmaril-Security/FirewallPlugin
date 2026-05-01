export const EXPORT_BUCKET = "silmaril-openclaw-firewall-exports-prod" as const;
export const EXPORT_ROOT_PREFIX = "openclaw-firewall/v1/" as const;

export const SEGMENT_SIZE_LIMIT_BYTES = 1024 * 1024;
export const SEGMENT_TIME_LIMIT_MS = 30 * 1000;
export const LEASE_TTL_SECONDS = 24 * 60 * 60;
export const LEASE_REFRESH_THRESHOLD_MS = 15 * 60 * 1000;
export const RECENT_UPLOAD_LIMIT = 100;
export const MAX_SPOOL_BYTES = 512 * 1024 * 1024;
export const UPLOAD_LOOP_INTERVAL_MS = 10 * 1000;
export const SEQUENCE_WIDTH = 12;

export type ExportSource = "user_input" | "tool_call" | "tool_response";

export type FirewallExportEvent = {
  schemaVersion: 1;
  seq: number;
  ts: string;
  apiKeyPathId: string;
  host: string;
  source: ExportSource;
  toolName?: string;
  payload: unknown;
  firewallResult?: unknown;
};

export type FirewallExportEventInput = {
  source: ExportSource;
  toolName?: string;
  payload: unknown;
  firewallResult?: unknown;
};

export type UploadLease = {
  type: "s3-post";
  bucket: typeof EXPORT_BUCKET;
  url: string;
  fields: Record<string, string>;
  keyPrefix: string;
  expiresAt: string;
};

export type Checkpoint = {
  version: 1;
  nextSeq: number;
  uploadedThroughSeq: number;
  recentUploads: Array<{
    chunkId: string;
    seqStart: number;
    seqEnd: number;
    s3Bucket: typeof EXPORT_BUCKET;
    s3Key: string;
    uploadedAt: string;
  }>;
};

export type ExporterLogger = {
  info(message: string, error?: unknown): void;
  warn(message: string, error?: unknown): void;
  error(message: string, error?: unknown): void;
};

export type ExporterPaths = {
  exportDir: string;
  spoolDir: string;
  logsDir: string;
  checkpointPath: string;
  leasePath: string;
  logPath: string;
};

export type ExporterRuntime = {
  apiKey: string;
  apiUrl: string;
  apiKeyPathId: string;
  host: string;
  paths: ExporterPaths;
  logger: ExporterLogger;
};

export type FirewallExporter = {
  start(ctx?: unknown): Promise<void>;
  stop(): Promise<void>;
  writeEvent(event: FirewallExportEventInput): Promise<void>;
};
