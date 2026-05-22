import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";
import { createHash, randomUUID } from "node:crypto";

const SHADOW_MODE_ENV = "SILMARIL_FIREWALL_SHADOW_MODE";
const DEFAULT_CLASSIFY_TIMEOUT_MS = 2500;
const MIN_CLASSIFY_TIMEOUT_MS = 250;
const MAX_CLASSIFY_TIMEOUT_MS = 10000;
const DEFAULT_TOOL_RESULT_MAX_IN_FLIGHT = 8;
const MAX_TOOL_RESULT_MAX_IN_FLIGHT = 64;
const RISK_RECORD_TTL_MS = 5 * 60 * 1000;
const MAX_RISK_RECORDS = 10000;

type RuntimeConfig = {
  apiKey: string;
  apiUrl: string;
  timeoutMs: number;
  toolResultMaxInFlight: number;
};

type RuntimeState = {
  firewall: Firewall;
  config: RuntimeConfig;
};

type HookLogMeta = {
  hookName: string;
  hook: HookLabel;
  toolName?: string;
  toolCallId?: string;
  runId?: string;
  sessionKey?: string;
  sessionId?: string;
  agentId?: string;
  messageId?: string;
  traceId?: string;
  idempotencyKey?: string;
};

type RiskRecord = {
  id: string;
  runId?: string;
  sessionKey?: string;
  sessionId?: string;
  agentId?: string;
  traceId?: string;
  promptHash: string;
  prediction: string;
  score: string;
  createdAtMs: number;
  expiresAtMs: number;
  exactKeys: string[];
  fallbackKey?: string;
};

type RiskMatch = {
  record: RiskRecord;
  matchKind: "exact" | "fallback";
  matchKey: string;
};

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Adds hook-level Silmaril firewall classification to OpenClaw",
  register(api) {
    const shadowMode = readOptionalBoolean(process.env[SHADOW_MODE_ENV]) ?? true;
    const registrationTimeoutMs = readIntegerInRange(
      readRecord(api.pluginConfig)?.timeoutMs,
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS,
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS;
    const hookOptions = { priority: 0, timeoutMs: registrationTimeoutMs };
    let cachedFirewall: Firewall | undefined;
    let cachedFirewallKey: string | undefined;
    let missingConfigWarned = false;
    let toolResultInFlight = 0;
    const riskByExactKey = new Map<string, RiskRecord>();
    const riskQueueByFallbackKey = new Map<string, RiskRecord[]>();

    const getRuntime = (): RuntimeState | undefined => {
      const config = resolveRuntimeConfig(api.pluginConfig);
      if (!config) {
        if (!missingConfigWarned) {
          api.logger.warn("firewall-plugin: apiKey or apiUrl missing - classifications skipped");
          missingConfigWarned = true;
        }
        return undefined;
      }

      missingConfigWarned = false;
      const cacheKey = `${config.apiUrl}\0${config.apiKey}\0${config.timeoutMs}`;
      if (!cachedFirewall || cachedFirewallKey !== cacheKey) {
        cachedFirewall = new Firewall({
          apiKey: config.apiKey,
          apiUrl: config.apiUrl,
          timeoutMs: config.timeoutMs,
        });
        cachedFirewallKey = cacheKey;
      }

      return { firewall: cachedFirewall, config };
    };

    api.on("gateway_start", () => {
      api.logger.info("firewall-plugin: installed");
      if (shadowMode) {
        api.logger.info("firewall-plugin: Silmaril is in shadow mode");
      }
    }, hookOptions);

    api.on("before_prompt_build", async (event, ctx) => {
      const meta = buildHookLogMeta("before_prompt_build", HookLabel.USER_INPUT, event, ctx);
      if (typeof event?.prompt !== "string") {
        logSkipped(meta, "missing_prompt");
        return;
      }

      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }

      try {
        const result = await classifyHookPayload(runtime.firewall, event.prompt, meta);
        if (isRisk(result)) {
          rememberRiskRecord(
            buildRiskRecord({
              prompt: event.prompt,
              result,
              meta,
            }),
            riskByExactKey,
            riskQueueByFallbackKey,
          );
        }
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);

    api.on("before_message_write", (event, ctx) => {
      const eventRecord = readRecord(event);
      const message = eventRecord?.message;
      if (!isAssistantMessageWithText(message)) {
        return;
      }

      const meta = buildHookLogMeta("before_message_write", HookLabel.USER_INPUT, event, ctx);
      const riskMatch = takeRiskRecord(meta, riskByExactKey, riskQueueByFallbackKey);
      if (!riskMatch) {
        return;
      }

      console.log("[firewall] before_message_write risk cache consumed:", JSON.stringify({
        ...logFields(meta),
        riskRecordId: riskMatch.record.id,
        promptHash: riskMatch.record.promptHash,
        prediction: riskMatch.record.prediction,
        score: riskMatch.record.score,
        matchKind: riskMatch.matchKind,
        matchKey: riskMatch.matchKey,
      }));
    }, hookOptions);

    api.on("before_tool_call", async (event, ctx) => {
      const meta = buildHookLogMeta("before_tool_call", HookLabel.TOOL_CALL, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }

      try {
        await classifyHookPayload(runtime.firewall, safeStringify(event?.params ?? {}), meta);
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);

    api.on("tool_result_persist", (event, ctx) => {
      const meta = buildHookLogMeta("tool_result_persist", HookLabel.TOOL_RESPONSE, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }

      try {
        const text = extractToolResultText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        if (toolResultInFlight >= runtime.config.toolResultMaxInFlight) {
          logSkipped(meta, "max_in_flight");
          return;
        }

        toolResultInFlight += 1;
        console.log("[firewall] tool_result_persist classify begin:", JSON.stringify(logFields(meta)));
        void classifyHookPayload(runtime.firewall, text, meta)
          .catch((err) => logError(meta, err))
          .finally(() => {
            toolResultInFlight = Math.max(0, toolResultInFlight - 1);
          });
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);
  },
});

function resolveRuntimeConfig(rawConfig: unknown): RuntimeConfig | undefined {
  const config = readRecord(rawConfig);
  const apiKey = readString(config?.silmarilApiKey) ?? readString(config?.apiKey);
  const apiUrl = readString(config?.apiUrl);
  if (!apiKey || !apiUrl) {
    return undefined;
  }

  return {
    apiKey,
    apiUrl,
    timeoutMs: readIntegerInRange(
      config?.timeoutMs,
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS,
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS,
    toolResultMaxInFlight: readIntegerInRange(
      config?.toolResultMaxInFlight,
      0,
      MAX_TOOL_RESULT_MAX_IN_FLIGHT,
    ) ?? DEFAULT_TOOL_RESULT_MAX_IN_FLIGHT,
  };
}

function readRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readIntegerInRange(value: unknown, min: number, max: number): number | undefined {
  const numberValue = typeof value === "string" && value.trim()
    ? Number(value)
    : value;
  if (typeof numberValue !== "number" || !Number.isFinite(numberValue)) {
    return undefined;
  }
  const integerValue = Math.trunc(numberValue);
  if (integerValue < min || integerValue > max) {
    return undefined;
  }
  return integerValue;
}

function readOptionalBoolean(value: unknown): boolean | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return undefined;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return undefined;
}

async function classifyHookPayload(
  firewall: Firewall,
  text: string,
  meta: HookLogMeta,
): Promise<{ prediction?: unknown; score?: unknown } | undefined> {
  const trimmed = text.trim();
  if (!trimmed) {
    logSkipped(meta, "empty_payload");
    return undefined;
  }

  const result = await firewall.classify(text, {
    hook: meta.hook,
    toolName: meta.toolName,
  });
  console.log("[firewall] " + meta.hookName + " result:", JSON.stringify({
    ...logFields(meta),
    prediction: result.prediction,
    score: result.score,
  }));
  return result;
}

function buildHookLogMeta(hookName: string, hook: HookLabel, event: unknown, ctx: unknown): HookLogMeta {
  const eventRecord = readRecord(event);
  const ctxRecord = readRecord(ctx);
  const messageRecord = readRecord(eventRecord?.message);
  return {
    hookName,
    hook,
    toolName: readString(eventRecord?.toolName) ?? readString(ctxRecord?.toolName) ?? readString(messageRecord?.toolName),
    toolCallId: readString(eventRecord?.toolCallId) ?? readString(ctxRecord?.toolCallId) ?? readString(messageRecord?.toolCallId),
    runId: readString(eventRecord?.runId) ?? readString(ctxRecord?.runId) ?? readString(messageRecord?.runId),
    sessionKey: readString(eventRecord?.sessionKey) ?? readString(ctxRecord?.sessionKey) ?? readString(messageRecord?.sessionKey),
    sessionId: readString(eventRecord?.sessionId) ?? readString(ctxRecord?.sessionId) ?? readString(messageRecord?.sessionId),
    agentId: readString(eventRecord?.agentId) ?? readString(ctxRecord?.agentId) ?? readString(messageRecord?.agentId),
    messageId: readString(eventRecord?.messageId) ?? readString(ctxRecord?.messageId) ?? readString(messageRecord?.id),
    traceId: readString(eventRecord?.traceId) ?? readTraceId(eventRecord?.trace) ?? readString(ctxRecord?.traceId) ?? readTraceId(ctxRecord?.trace),
    idempotencyKey: readString(eventRecord?.idempotencyKey) ?? readString(ctxRecord?.idempotencyKey) ?? readString(messageRecord?.idempotencyKey),
  };
}

function readTraceId(value: unknown): string | undefined {
  const record = readRecord(value);
  return readString(record?.traceId) ?? readString(record?.id);
}

function buildExactRiskKeys(meta: HookLogMeta): string[] {
  const keys = [
    meta.runId ? `run:${meta.runId}` : undefined,
    meta.traceId ? `trace:${meta.traceId}` : undefined,
    meta.idempotencyKey ? `idempotency:${meta.idempotencyKey}` : undefined,
    meta.runId && meta.sessionKey ? `session:${meta.sessionKey}:run:${meta.runId}` : undefined,
    meta.runId && meta.agentId ? `agent:${meta.agentId}:run:${meta.runId}` : undefined,
  ].filter((key): key is string => typeof key === "string" && key.length > 0);
  return [...new Set(keys)];
}

function buildFallbackRiskQueueKey(meta: HookLogMeta): string | undefined {
  if (meta.agentId && meta.sessionKey) return `agent:${meta.agentId}:session:${meta.sessionKey}`;
  if (meta.sessionKey) return `session:${meta.sessionKey}`;
  if (meta.agentId && meta.sessionId) return `agent:${meta.agentId}:sessionId:${meta.sessionId}`;
  if (meta.sessionId) return `sessionId:${meta.sessionId}`;
  return undefined;
}

function buildRiskRecord(params: {
  prompt: string;
  result: { prediction?: unknown; score?: unknown };
  meta: HookLogMeta;
}): RiskRecord {
  const createdAtMs = Date.now();
  const promptHash = createHash("sha256").update(params.prompt).digest("hex").slice(0, 16);
  const exactKeys = buildExactRiskKeys(params.meta);
  const fallbackKey = buildFallbackRiskQueueKey(params.meta);
  return {
    id: [
      params.meta.runId ?? "no-run",
      params.meta.sessionKey ?? "no-session",
      params.meta.sessionId ?? "no-session-id",
      params.meta.agentId ?? "no-agent",
      params.meta.traceId ?? "no-trace",
      promptHash,
      String(createdAtMs),
      randomUUID(),
    ].join(":"),
    runId: params.meta.runId,
    sessionKey: params.meta.sessionKey,
    sessionId: params.meta.sessionId,
    agentId: params.meta.agentId,
    traceId: params.meta.traceId,
    promptHash,
    prediction: String(params.result.prediction ?? "UNKNOWN").toUpperCase(),
    score: formatScore(params.result.score),
    createdAtMs,
    expiresAtMs: createdAtMs + RISK_RECORD_TTL_MS,
    exactKeys,
    fallbackKey,
  };
}

function rememberRiskRecord(
  record: RiskRecord,
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): void {
  pruneRiskRecords(Date.now(), riskByExactKey, riskQueueByFallbackKey);
  if (record.exactKeys.length === 0 && !record.fallbackKey) {
    console.log("[firewall] before_prompt_build risk cache skipped:", JSON.stringify({
      riskRecordId: record.id,
      promptHash: record.promptHash,
      prediction: record.prediction,
      score: record.score,
      reason: "missing_correlation_key",
    }));
    return;
  }

  const replacedRecords = new Set<RiskRecord>();
  for (const key of record.exactKeys) {
    const existing = riskByExactKey.get(key);
    if (existing && existing.id !== record.id && !replacedRecords.has(existing)) {
      replacedRecords.add(existing);
      removeRiskRecord(existing, riskByExactKey, riskQueueByFallbackKey);
    }
    riskByExactKey.set(key, record);
  }
  if (record.fallbackKey) {
    const queue = riskQueueByFallbackKey.get(record.fallbackKey) ?? [];
    queue.push(record);
    riskQueueByFallbackKey.set(record.fallbackKey, queue);
  }
  trimRiskRecords(riskByExactKey, riskQueueByFallbackKey);

  console.log("[firewall] before_prompt_build risk cached:", JSON.stringify({
    runId: record.runId,
    sessionKey: record.sessionKey,
    sessionId: record.sessionId,
    agentId: record.agentId,
    traceId: record.traceId,
    riskRecordId: record.id,
    promptHash: record.promptHash,
    prediction: record.prediction,
    score: record.score,
    exactKeys: record.exactKeys,
    fallbackKey: record.fallbackKey,
  }));
}

function takeRiskRecord(
  meta: HookLogMeta,
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): RiskMatch | undefined {
  const now = Date.now();
  pruneRiskRecords(now, riskByExactKey, riskQueueByFallbackKey);

  for (const key of buildExactRiskKeys(meta)) {
    const record = riskByExactKey.get(key);
    if (record && !isExpiredRiskRecord(record, now)) {
      removeRiskRecord(record, riskByExactKey, riskQueueByFallbackKey);
      return {
        record,
        matchKind: "exact",
        matchKey: key,
      };
    }
  }

  const fallbackKey = buildFallbackRiskQueueKey(meta);
  if (!fallbackKey) {
    return undefined;
  }

  const queue = riskQueueByFallbackKey.get(fallbackKey);
  while (queue?.length) {
    const record = queue.shift();
    if (!record || isExpiredRiskRecord(record, now)) {
      if (record) removeRiskRecord(record, riskByExactKey, riskQueueByFallbackKey);
      continue;
    }
    removeRiskRecord(record, riskByExactKey, riskQueueByFallbackKey);
    return {
      record,
      matchKind: "fallback",
      matchKey: fallbackKey,
    };
  }
  riskQueueByFallbackKey.delete(fallbackKey);
  return undefined;
}

function pruneRiskRecords(
  now: number,
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): void {
  for (const [key, record] of riskByExactKey.entries()) {
    if (isExpiredRiskRecord(record, now)) riskByExactKey.delete(key);
  }
  for (const [fallbackKey, queue] of riskQueueByFallbackKey.entries()) {
    const filtered = queue.filter((record) => !isExpiredRiskRecord(record, now));
    if (filtered.length > 0) riskQueueByFallbackKey.set(fallbackKey, filtered);
    else riskQueueByFallbackKey.delete(fallbackKey);
  }
}

function trimRiskRecords(
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): void {
  while (countRiskRecords(riskByExactKey, riskQueueByFallbackKey) > MAX_RISK_RECORDS) {
    const oldest = findOldestRiskRecord(riskByExactKey, riskQueueByFallbackKey);
    if (!oldest) return;
    removeRiskRecord(oldest, riskByExactKey, riskQueueByFallbackKey);
  }
}

function countRiskRecords(
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): number {
  const ids = new Set<string>();
  for (const record of riskByExactKey.values()) {
    ids.add(record.id);
  }
  for (const queue of riskQueueByFallbackKey.values()) {
    for (const record of queue) {
      ids.add(record.id);
    }
  }
  return ids.size;
}

function findOldestRiskRecord(
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): RiskRecord | undefined {
  let oldest: RiskRecord | undefined;
  const visit = (record: RiskRecord) => {
    if (!oldest || record.createdAtMs < oldest.createdAtMs) {
      oldest = record;
    }
  };
  for (const record of riskByExactKey.values()) {
    visit(record);
  }
  for (const queue of riskQueueByFallbackKey.values()) {
    for (const record of queue) {
      visit(record);
    }
  }
  return oldest;
}

function removeRiskRecord(
  record: RiskRecord,
  riskByExactKey: Map<string, RiskRecord>,
  riskQueueByFallbackKey: Map<string, RiskRecord[]>,
): void {
  for (const key of record.exactKeys) {
    riskByExactKey.delete(key);
  }
  if (!record.fallbackKey) return;
  const queue = riskQueueByFallbackKey.get(record.fallbackKey);
  if (!queue) return;
  const filtered = queue.filter((candidate) => candidate.id !== record.id);
  if (filtered.length > 0) riskQueueByFallbackKey.set(record.fallbackKey, filtered);
  else riskQueueByFallbackKey.delete(record.fallbackKey);
}

function isExpiredRiskRecord(record: RiskRecord, now: number): boolean {
  return record.expiresAtMs < now;
}

function formatScore(score: unknown): string {
  return typeof score === "number" && Number.isFinite(score)
    ? score.toFixed(3)
    : "unknown";
}

function isAssistantMessageWithText(value: unknown): boolean {
  const message = readRecord(value);
  if (readString(message?.role) !== "assistant") return false;
  return findTextContentIndex(message?.content) !== -1;
}

function findTextContentIndex(content: unknown): number {
  if (typeof content === "string") return content.trim().length > 0 ? 0 : -1;
  if (!Array.isArray(content)) return -1;
  return content.findIndex((part) => {
    if (typeof part === "string") return part.trim().length > 0;
    if (!part || typeof part !== "object" || Array.isArray(part)) return false;
    const partRecord = part as Record<string, unknown>;
    return typeof partRecord.text === "string" && partRecord.text.trim().length > 0;
  });
}

function logFields(meta: HookLogMeta): Record<string, string> {
  return Object.fromEntries(
    Object.entries({
      hook: meta.hook,
      toolName: meta.toolName,
      toolCallId: meta.toolCallId,
      runId: meta.runId,
      sessionKey: meta.sessionKey,
      sessionId: meta.sessionId,
      agentId: meta.agentId,
      messageId: meta.messageId,
      traceId: meta.traceId,
      idempotencyKey: meta.idempotencyKey,
    }).filter((entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].length > 0),
  );
}

function logSkipped(meta: HookLogMeta, reason: string): void {
  console.log("[firewall] " + meta.hookName + " skipped:", JSON.stringify({
    ...logFields(meta),
    reason,
  }));
}

function logError(meta: HookLogMeta, err: unknown): void {
  console.error("[firewall] " + meta.hookName + " error:", JSON.stringify({
    ...logFields(meta),
    error: err instanceof Error ? err.message : String(err),
  }));
}

function safeStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(value, (_key, currentValue) => {
      if (typeof currentValue === "bigint") {
        return currentValue.toString();
      }
      if (currentValue && typeof currentValue === "object") {
        if (seen.has(currentValue)) {
          return "[Circular]";
        }
        seen.add(currentValue);
      }
      return currentValue;
    }) ?? "";
  } catch {
    return String(value ?? "");
  }
}

function isRisk(result: { prediction?: unknown } | undefined): boolean {
  return String(result?.prediction ?? "").toUpperCase() === "MALICIOUS";
}

function extractToolResultText(event: { message?: { content?: unknown } } | undefined): string {
  const content = event?.message?.content;
  if (typeof content === "string") {
    return content;
  }
  if (content && typeof content === "object" && !Array.isArray(content)) {
    const text = (content as { text?: unknown }).text;
    return typeof text === "string" ? text : "";
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .map((part) => {
      if (typeof part === "string") {
        return part;
      }
      if (part && typeof part === "object" && typeof (part as { text?: unknown }).text === "string") {
        return (part as { text: string }).text;
      }
      return "";
    })
    .join("\n");
}

export const __testInternals = {
  RISK_RECORD_TTL_MS,
  MAX_RISK_RECORDS,
  resolveRuntimeConfig,
  readRecord,
  readString,
  readIntegerInRange,
  readOptionalBoolean,
  classifyHookPayload,
  buildHookLogMeta,
  readTraceId,
  buildExactRiskKeys,
  buildFallbackRiskQueueKey,
  buildRiskRecord,
  rememberRiskRecord,
  takeRiskRecord,
  pruneRiskRecords,
  trimRiskRecords,
  countRiskRecords,
  findOldestRiskRecord,
  removeRiskRecord,
  isExpiredRiskRecord,
  formatScore,
  isAssistantMessageWithText,
  findTextContentIndex,
  logFields,
  logSkipped,
  logError,
  safeStringify,
  isRisk,
  extractToolResultText,
};
