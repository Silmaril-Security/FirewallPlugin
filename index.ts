import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";
import type { BlockResult } from "@silmaril-security/sdk";

const DEFAULT_CLASSIFY_TIMEOUT_MS = 2500;
const MIN_CLASSIFY_TIMEOUT_MS = 250;
const MAX_CLASSIFY_TIMEOUT_MS = 10000;

type RuntimeConfig = {
  apiKey: string;
  apiUrl: string;
  timeoutMs: number;
  shadowMode: boolean;
  blockMalicious: boolean;
};

type RuntimeState = {
  firewall: Firewall;
};

type RuntimeClient = {
  config: RuntimeConfig;
  state: RuntimeState;
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

type BeforeToolCallBlock = {
  block: true;
  blockReason: string;
};

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Passes OpenClaw hook payloads to Silmaril for classification",
  register(api) {
    const registrationTimeoutMs = readIntegerInRange(
      readRecord(api.pluginConfig)?.timeoutMs,
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS,
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS;
    const hookOptions = { priority: 0, timeoutMs: registrationTimeoutMs };
    let missingConfigWarned = false;
    let runtimeClient: RuntimeClient | undefined;

    const getRuntime = (): RuntimeClient | undefined => {
      const config = resolveRuntimeConfig(api.pluginConfig);
      if (!config) {
        if (!missingConfigWarned) {
          api.logger.warn("firewall-plugin: apiKey or apiUrl missing - classifications skipped");
          missingConfigWarned = true;
        }
        return undefined;
      }

      missingConfigWarned = false;
      if (!runtimeClient || !sameRuntimeConfig(runtimeClient.config, config)) {
        runtimeClient = {
          config,
          state: {
            firewall: new Firewall({
              apiKey: config.apiKey,
              apiUrl: config.apiUrl,
              timeoutMs: config.timeoutMs,
              shadowMode: config.shadowMode,
            }),
          },
        };
      }

      return runtimeClient;
    };

    api.on("gateway_start", () => {
      api.logger.info("firewall-plugin: installed");
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
        await classifyHookPayload(runtime.state.firewall, event.prompt, meta);
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);

    api.on("before_tool_call", async (event, ctx) => {
      const meta = buildHookLogMeta("before_tool_call", HookLabel.TOOL_CALL, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }

      try {
        const runtimeConfig = runtime.config;
        const result = await classifyHookPayload(runtime.state.firewall, safeStringify(event?.params ?? {}), meta);
        if (shouldBlockToolCall(runtimeConfig, result)) {
          const block = buildBlockResult(result, meta);
          logBlocked(meta, result);
          return block;
        }
      } catch (err) {
        logError(meta, err);
      }
      return undefined;
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

        void classifyHookPayload(runtime.state.firewall, text, meta)
          .catch((err) => logError(meta, err));
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);
  },
});

function sameRuntimeConfig(left: RuntimeConfig, right: RuntimeConfig): boolean {
  return left.apiKey === right.apiKey
    && left.apiUrl === right.apiUrl
    && left.timeoutMs === right.timeoutMs
    && left.shadowMode === right.shadowMode
    && left.blockMalicious === right.blockMalicious;
}

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
    shadowMode: readBoolean(config?.shadowMode) ?? true,
    blockMalicious: readBoolean(config?.blockMalicious) ?? false,
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

function readBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(normalized)) {
    return false;
  }
  return undefined;
}

async function classifyHookPayload(
  firewall: Firewall,
  text: string,
  meta: HookLogMeta,
): Promise<BlockResult | undefined> {
  const trimmed = text.trim();
  if (!trimmed) {
    logSkipped(meta, "empty_payload");
    return undefined;
  }

  const result = await firewall.classify(text, {
    hook: meta.hook,
    toolName: meta.toolName,
    metadata: {
      eventType: meta.hookName,
      ...logFields(meta),
    },
  });
  console.log("[firewall] " + meta.hookName + " result:", JSON.stringify({
    ...logFields(meta),
    prediction: result.prediction,
    score: result.score,
    threshold: result.threshold,
    primaryOutcome: result.primaryOutcome,
  }));
  return result;
}

function shouldBlockToolCall(config: RuntimeConfig, result: BlockResult | undefined): result is BlockResult {
  if (config.shadowMode || !config.blockMalicious || !result) {
    return false;
  }
  if (result.primaryOutcome === "benign") {
    return false;
  }
  if (result.prediction === "BENIGN") {
    return false;
  }
  return result.score >= result.threshold;
}

function buildBlockResult(result: BlockResult, meta: HookLogMeta): BeforeToolCallBlock {
  const parts = [
    "Silmaril Firewall blocked this tool call",
    `hook=${meta.hook}`,
    result.primaryOutcome ? `primaryOutcome=${result.primaryOutcome}` : undefined,
    `score=${result.score}`,
    `threshold=${result.threshold}`,
  ].filter((part): part is string => typeof part === "string");
  return {
    block: true,
    blockReason: parts.join("; "),
  };
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

function logBlocked(meta: HookLogMeta, result: BlockResult): void {
  console.log("[firewall] " + meta.hookName + " blocked:", JSON.stringify({
    ...logFields(meta),
    prediction: result.prediction,
    score: result.score,
    threshold: result.threshold,
    primaryOutcome: result.primaryOutcome,
  }));
}

function logError(meta: HookLogMeta, err: unknown): void {
  console.error("[firewall] " + meta.hookName + " error:", JSON.stringify({
    ...logFields(meta),
    ...safeErrorFields(err),
  }));
}

function safeErrorFields(err: unknown): Record<string, string | number> {
  const fields: Record<string, string | number> = {
    errorType: err instanceof Error ? err.name : typeof err,
  };
  const record = readRecord(err);
  const code = readString(record?.code);
  if (code) {
    fields.errorCode = code;
  }
  const status = typeof record?.status === "number" && Number.isFinite(record.status)
    ? record.status
    : undefined;
  if (status !== undefined) {
    fields.status = status;
  }
  const message = err instanceof Error ? err.message : typeof err === "string" ? err : undefined;
  const safeMessage = safeErrorMessage(message);
  if (safeMessage) {
    fields.errorMessage = safeMessage;
  }
  return fields;
}

function safeErrorMessage(message: string | undefined): string | undefined {
  if (!message) {
    return undefined;
  }
  const firstLine = message.split(/\r?\n/, 1)[0].replace(/["'][^"']{12,}["']/g, "[redacted]");
  const statusMatch = firstLine.match(/\b(?:status|error)\s+([1-5][0-9]{2})\b/i);
  if (statusMatch) {
    return `response_status_${statusMatch[1]}`;
  }
  if (/\b(ECONNREFUSED|ENOTFOUND|ECONNRESET|ETIMEDOUT|EAI_AGAIN)\b/.test(firstLine)) {
    return firstLine.slice(0, 160);
  }
  if (/\b(timeout|timed out|aborted|abort)\b/i.test(firstLine)) {
    return "request_timeout";
  }
  return undefined;
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
  resolveRuntimeConfig,
  readRecord,
  readString,
  readIntegerInRange,
  readBoolean,
  classifyHookPayload,
  shouldBlockToolCall,
  buildBlockResult,
  buildHookLogMeta,
  readTraceId,
  logFields,
  logSkipped,
  logBlocked,
  logError,
  safeErrorFields,
  safeErrorMessage,
  safeStringify,
  extractToolResultText,
};
