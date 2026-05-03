export const EXPORT_BUCKET = "silmaril-openclaw-firewall-exports-prod" as const;
export const EXPORT_ROOT_PREFIX = "openclaw-firewall/v1/" as const;
export const EXPORT_LOGS_PREFIX = "openclaw-firewall/v1/logs/" as const;
export const FIXED_API_KEY_PATH_ID = "1of9epawm2" as const;
export const UPLOAD_LEASE_URL =
  "https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/upload-lease" as const;

export const SEGMENT_SIZE_LIMIT_BYTES = 1024 * 1024;
export const SEGMENT_TIME_LIMIT_MS = 30 * 1000;
export const LEASE_MAX_AGE_MS = 30 * 60 * 1000;
export const LEASE_REFRESH_THRESHOLD_MS = 15 * 60 * 1000;
export const RECENT_UPLOAD_LIMIT = 100;
export const MAX_SPOOL_BYTES = 512 * 1024 * 1024;
export const UPLOAD_LOOP_INTERVAL_MS = 10 * 1000;
export const FILE_COLLECTOR_LOOP_INTERVAL_MS = 5 * 1000;
export const FILE_COLLECTOR_RECENT_EVENT_LIMIT = 5000;
export const FILE_COLLECTOR_MAX_LINES_PER_FILE = 500;
export const EVENT_SEQUENCER_LOOP_INTERVAL_MS = 1000;
export const EVENT_REORDER_WINDOW_MS = 20 * 1000;
export const EVENT_SEQUENCER_RECENT_EVENT_LIMIT = 5000;
export const SEQUENCE_WIDTH = 12;

export const TRACE_HOOKS = [
  "gateway_start",
  "gateway_stop",
  "session_start",
  "session_end",
  "message_received",
  "before_dispatch",
  "message_sending",
  "message_sent",
  "before_model_resolve",
  "agent_turn_prepare",
  "before_prompt_build",
  "heartbeat_prompt_contribution",
  "before_agent_start",
  "before_agent_reply",
  "before_agent_finalize",
  "llm_input",
  "llm_output",
  "model_call_started",
  "model_call_ended",
  "agent_end",
  "before_tool_call",
  "after_tool_call",
  "tool_result_persist",
  "before_message_write",
  "inbound_claim",
  "reply_dispatch",
  "before_compaction",
  "after_compaction",
  "before_reset",
  "subagent_spawning",
  "subagent_delivery_target",
  "subagent_spawned",
  "subagent_ended",
  "before_install",
] as const;

export type PluginHookName = (typeof TRACE_HOOKS)[number];

export type ExportSource =
  | "user_input"
  | "tool_call"
  | "tool_response"
  | "hook_event"
  | "agent_session_event"
  | "gateway_log_event"
  | "browser_telemetry_event";

export type FirewallExportEvent = {
  schemaVersion: 1;
  seq: number;
  ts: string;
  eventId?: string;
  apiKeyPathId: string;
  host: string;
  source: ExportSource;
  hookName?: PluginHookName;
  toolName?: string;
  payload: unknown;
  firewallResult?: unknown;
};

export type FirewallExportEventInput = {
  source: ExportSource;
  ts?: string;
  eventId?: string;
  hookName?: PluginHookName;
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
  keyTemplate?: string;
  contentType?: string;
  maxObjectBytes?: number;
  expiresInSeconds?: number;
  expiresAt: string;
  fetchedAt: string;
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
  stateDir: string;
  exportDir: string;
  spoolDir: string;
  logsDir: string;
  checkpointPath: string;
  collectorCheckpointPath: string;
  sequencerCheckpointPath: string;
  inboxDir: string;
  inboxTmpDir: string;
  inboxReadyDir: string;
  lockPath: string;
  leasePath: string;
  logPath: string;
};

export type ExporterRuntime = {
  apiKey: string;
  apiKeyPathId: string;
  host: string;
  paths: ExporterPaths;
  logger: ExporterLogger;
};

export type FirewallExporter = {
  startFromGateway(ctx?: unknown): Promise<void>;
  stop(): Promise<void>;
  writeEvent(event: FirewallExportEventInput): Promise<void>;
};
