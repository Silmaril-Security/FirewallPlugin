import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";
const DEFAULT_CLASSIFY_TIMEOUT_MS = 2500;
const MIN_CLASSIFY_TIMEOUT_MS = 250;
const MAX_CLASSIFY_TIMEOUT_MS = 1e4;
var index_default = definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Passes OpenClaw hook payloads to Silmaril for classification",
  register(api) {
    const registrationTimeoutMs = readIntegerInRange(
      readRecord(api.pluginConfig)?.timeoutMs,
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS;
    const hookOptions = { priority: 0, timeoutMs: registrationTimeoutMs };
    let missingConfigWarned = false;
    let runtimeClient;
    const getRuntime = () => {
      const config = resolveRuntimeConfig(api.pluginConfig);
      if (!config) {
        if (!missingConfigWarned) {
          api.logger.warn("firewall-plugin: apiKey or apiUrl missing - classifications skipped");
          missingConfigWarned = true;
        }
        return void 0;
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
              shadowMode: config.shadowMode
            })
          }
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
      return void 0;
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
        void classifyHookPayload(runtime.state.firewall, text, meta).catch((err) => logError(meta, err));
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);
  }
});
function sameRuntimeConfig(left, right) {
  return left.apiKey === right.apiKey && left.apiUrl === right.apiUrl && left.timeoutMs === right.timeoutMs && left.shadowMode === right.shadowMode && left.blockMalicious === right.blockMalicious;
}
function resolveRuntimeConfig(rawConfig) {
  const config = readRecord(rawConfig);
  const apiKey = readString(config?.silmarilApiKey) ?? readString(config?.apiKey);
  const apiUrl = readString(config?.apiUrl);
  if (!apiKey || !apiUrl) {
    return void 0;
  }
  return {
    apiKey,
    apiUrl,
    timeoutMs: readIntegerInRange(
      config?.timeoutMs,
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS,
    shadowMode: readBoolean(config?.shadowMode) ?? true,
    blockMalicious: readBoolean(config?.blockMalicious) ?? false
  };
}
function readRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : void 0;
}
function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : void 0;
}
function readIntegerInRange(value, min, max) {
  const numberValue = typeof value === "string" && value.trim() ? Number(value) : value;
  if (typeof numberValue !== "number" || !Number.isFinite(numberValue)) {
    return void 0;
  }
  const integerValue = Math.trunc(numberValue);
  if (integerValue < min || integerValue > max) {
    return void 0;
  }
  return integerValue;
}
function readBoolean(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value !== "string") {
    return void 0;
  }
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(normalized)) {
    return false;
  }
  return void 0;
}
async function classifyHookPayload(firewall, text, meta) {
  const trimmed = text.trim();
  if (!trimmed) {
    logSkipped(meta, "empty_payload");
    return void 0;
  }
  const result = await firewall.classify(text, {
    hook: meta.hook,
    toolName: meta.toolName,
    metadata: {
      eventType: meta.hookName,
      ...logFields(meta)
    }
  });
  console.log("[firewall] " + meta.hookName + " result:", JSON.stringify({
    ...logFields(meta),
    prediction: result.prediction,
    score: result.score,
    threshold: result.threshold,
    primaryOutcome: result.primaryOutcome
  }));
  return result;
}
function shouldBlockToolCall(config, result) {
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
function buildBlockResult(result, meta) {
  const parts = [
    "Silmaril Firewall blocked this tool call",
    `hook=${meta.hook}`,
    result.primaryOutcome ? `primaryOutcome=${result.primaryOutcome}` : void 0,
    `score=${result.score}`,
    `threshold=${result.threshold}`
  ].filter((part) => typeof part === "string");
  return {
    block: true,
    blockReason: parts.join("; ")
  };
}
function buildHookLogMeta(hookName, hook, event, ctx) {
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
    idempotencyKey: readString(eventRecord?.idempotencyKey) ?? readString(ctxRecord?.idempotencyKey) ?? readString(messageRecord?.idempotencyKey)
  };
}
function readTraceId(value) {
  const record = readRecord(value);
  return readString(record?.traceId) ?? readString(record?.id);
}
function logFields(meta) {
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
      idempotencyKey: meta.idempotencyKey
    }).filter((entry) => typeof entry[1] === "string" && entry[1].length > 0)
  );
}
function logSkipped(meta, reason) {
  console.log("[firewall] " + meta.hookName + " skipped:", JSON.stringify({
    ...logFields(meta),
    reason
  }));
}
function logBlocked(meta, result) {
  console.log("[firewall] " + meta.hookName + " blocked:", JSON.stringify({
    ...logFields(meta),
    prediction: result.prediction,
    score: result.score,
    threshold: result.threshold,
    primaryOutcome: result.primaryOutcome
  }));
}
function logError(meta, err) {
  console.error("[firewall] " + meta.hookName + " error:", JSON.stringify({
    ...logFields(meta),
    ...safeErrorFields(err)
  }));
}
function safeErrorFields(err) {
  const fields = {
    errorType: err instanceof Error ? err.name : typeof err
  };
  const record = readRecord(err);
  const code = readString(record?.code);
  if (code) {
    fields.errorCode = code;
  }
  const status = typeof record?.status === "number" && Number.isFinite(record.status) ? record.status : void 0;
  if (status !== void 0) {
    fields.status = status;
  }
  const message = err instanceof Error ? err.message : typeof err === "string" ? err : void 0;
  const safeMessage = safeErrorMessage(message);
  if (safeMessage) {
    fields.errorMessage = safeMessage;
  }
  return fields;
}
function safeErrorMessage(message) {
  if (!message) {
    return void 0;
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
  return void 0;
}
function safeStringify(value) {
  const seen = /* @__PURE__ */ new WeakSet();
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
function extractToolResultText(event) {
  const content = event?.message?.content;
  if (typeof content === "string") {
    return content;
  }
  if (content && typeof content === "object" && !Array.isArray(content)) {
    const text = content.text;
    return typeof text === "string" ? text : "";
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content.map((part) => {
    if (typeof part === "string") {
      return part;
    }
    if (part && typeof part === "object" && typeof part.text === "string") {
      return part.text;
    }
    return "";
  }).join("\n");
}
const __testInternals = {
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
  extractToolResultText
};
export {
  __testInternals,
  index_default as default
};
