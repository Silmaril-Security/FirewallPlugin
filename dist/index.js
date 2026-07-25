import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";
import { createHash } from "node:crypto";
import {
  buildLocalProtectionEvent,
  emitLocalProtectionEvent,
  emitLocalProtectionEventBestEffort,
  resolveLocalEventDirectory
} from "./local-evidence";
const PLUGIN_ID = "firewall-plugin";
const PLUGIN_VERSION = "1.1.1";
const LOCAL_EVIDENCE_POLICY_VERSION = "openclaw-plugin-policy-v1";
const DEFAULT_CLASSIFY_TIMEOUT_MS = 2500;
const MIN_CLASSIFY_TIMEOUT_MS = 250;
const MAX_CLASSIFY_TIMEOUT_MS = 1e4;
const OUTBOUND_DEDUPE_TTL_MS = 5e3;
const MAX_OUTBOUND_DEDUPE_ENTRIES = 256;
var index_default = definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Passes OpenClaw hook payloads to Silmaril and renders readable blocked-decision feedback",
  register(api) {
    const registrationTimeoutMs = readIntegerInRange(
      readRecord(api.pluginConfig)?.timeoutMs,
      MIN_CLASSIFY_TIMEOUT_MS,
      MAX_CLASSIFY_TIMEOUT_MS
    ) ?? DEFAULT_CLASSIFY_TIMEOUT_MS;
    const hookOptions = { priority: 0, timeoutMs: registrationTimeoutMs };
    let missingConfigWarned = false;
    let runtimeClient;
    const outboundClassificationCache = /* @__PURE__ */ new Map();
    const getRuntime = () => {
      const config = resolveRuntimeConfig(api.pluginConfig);
      if (!config) {
        runtimeClient = void 0;
        outboundClassificationCache.clear();
        if (!missingConfigWarned) {
          api.logger.warn("firewall-plugin: apiKey or apiUrl missing - classifications skipped");
          missingConfigWarned = true;
        }
        return void 0;
      }
      missingConfigWarned = false;
      if (!runtimeClient || !sameRuntimeConfig(runtimeClient.config, config)) {
        outboundClassificationCache.clear();
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
    api.on("before_agent_run", async (event, ctx) => {
      const meta = buildHookLogMeta("before_agent_run", HookLabel.USER_INPUT, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractAgentRunText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const result = await classifyHookPayload(runtime.state.firewall, text, meta);
        if (shouldBlockClassification(runtime.config, result)) {
          emitOpenClawLocalEvidence(meta, text, result, runtime.config, "block_returned", true);
          logBlocked(meta, result);
          return buildBeforeAgentRunBlock(result, meta);
        }
        emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", true);
      } catch (err) {
        logError(meta, err);
      }
      return void 0;
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
        const text = safeStringify(event?.params ?? {});
        const result = await classifyHookPayload(runtime.state.firewall, text, meta);
        if (shouldBlockClassification(runtimeConfig, result)) {
          emitOpenClawLocalEvidence(
            meta,
            text,
            result,
            runtimeConfig,
            "block_returned",
            true
          );
          const block = buildBlockResult(result, meta);
          logBlocked(meta, result);
          return block;
        }
        emitOpenClawLocalEvidence(
          meta,
          text,
          result,
          runtimeConfig,
          "allowed",
          true
        );
      } catch (err) {
        logError(meta, err);
      }
      return void 0;
    }, hookOptions);
    api.on("after_tool_call", async (event, ctx) => {
      const meta = buildHookLogMeta("after_tool_call", HookLabel.TOOL_RESPONSE, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractAfterToolCallText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const result = await classifyHookPayload(runtime.state.firewall, text, meta);
        emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", false);
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
        void classifyHookPayload(runtime.state.firewall, text, meta).then((result) => {
          emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", false);
        }).catch((err) => logError(meta, err));
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);
    api.on("message_sending", async (event, ctx) => {
      const meta = buildHookLogMeta("message_sending", HookLabel.LLM_OUTPUT, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractMessageSendingText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const runtimeConfig = runtime.config;
        const result = await classifyOutboundOnce(
          runtime.state.firewall,
          text,
          meta,
          outboundClassificationCache
        );
        if (shouldBlockClassification(runtimeConfig, result)) {
          emitOpenClawLocalEvidence(meta, text, result, runtimeConfig, "block_returned", true);
          const block = buildMessageSendingBlock(result, meta);
          logBlocked(meta, result);
          return block;
        }
        emitOpenClawLocalEvidence(meta, text, result, runtimeConfig, "allowed", true);
      } catch (err) {
        logError(meta, err);
      }
      return void 0;
    }, hookOptions);
    api.on("reply_payload_sending", async (event, ctx) => {
      const meta = buildHookLogMeta("reply_payload_sending", HookLabel.LLM_OUTPUT, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractReplyPayloadText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const result = await classifyOutboundOnce(
          runtime.state.firewall,
          text,
          meta,
          outboundClassificationCache
        );
        if (shouldBlockClassification(runtime.config, result)) {
          emitOpenClawLocalEvidence(
            meta,
            text,
            result,
            runtime.config,
            "content_replaced",
            true
          );
          const replacement = buildReplyPayloadSendingReplacement(event, result, meta);
          logBlocked(meta, result);
          return replacement;
        }
        emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", true);
      } catch (err) {
        logError(meta, err);
      }
      return void 0;
    }, hookOptions);
    api.on("message_sent", (event, ctx) => {
      const meta = buildHookLogMeta("message_sent", HookLabel.LLM_OUTPUT, event, ctx);
      logObserved(meta);
    }, hookOptions);
    api.on("subagent_delivery_target", async (event, ctx) => {
      const meta = buildHookLogMeta("subagent_delivery_target", HookLabel.USER_INPUT, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractLifecycleText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const result = await classifyHookPayload(runtime.state.firewall, text, meta);
        emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", false);
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);
    api.on("subagent_spawned", async (event, ctx) => {
      const meta = buildHookLogMeta("subagent_spawned", HookLabel.USER_INPUT, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractLifecycleText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const result = await classifyHookPayload(runtime.state.firewall, text, meta);
        emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", false);
      } catch (err) {
        logError(meta, err);
      }
    }, hookOptions);
    api.on("subagent_ended", async (event, ctx) => {
      const meta = buildHookLogMeta("subagent_ended", HookLabel.LLM_OUTPUT, event, ctx);
      const runtime = getRuntime();
      if (!runtime) {
        logSkipped(meta, "missing_config");
        return;
      }
      try {
        const text = extractLifecycleText(event);
        if (!text.trim()) {
          logSkipped(meta, "empty_payload");
          return;
        }
        const result = await classifyHookPayload(runtime.state.firewall, text, meta);
        emitOpenClawLocalEvidence(meta, text, result, runtime.config, "allowed", false);
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
function omitUndefined(record) {
  return Object.fromEntries(
    Object.entries(record).filter((entry) => entry[1] !== void 0)
  );
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
    requestId: buildStableRequestId(meta, text),
    metadata: {
      eventType: meta.hookName,
      conversationId: meta.conversationId,
      ...logFields(meta)
    }
  });
  console.log("[firewall] " + meta.hookName + " result:", JSON.stringify({
    ...logFields(meta),
    prediction: result.prediction,
    risk: describeRisk(result)
  }));
  return result;
}
async function classifyOutboundOnce(firewall, text, meta, cache, now = Date.now()) {
  const key = outboundDedupeKey(meta, text);
  pruneOutboundCache(cache, now);
  const existing = cache.get(key);
  if (existing && now - existing.createdAt <= OUTBOUND_DEDUPE_TTL_MS) {
    return existing.result;
  }
  const result = classifyHookPayload(firewall, text, meta);
  cache.set(key, { createdAt: now, result });
  if (cache.size > MAX_OUTBOUND_DEDUPE_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  result.catch(() => cache.delete(key));
  return result;
}
function outboundDedupeKey(meta, text) {
  const stableEventId = meta.idempotencyKey ?? meta.messageId ?? meta.traceId ?? meta.runId;
  const contentHash = sha256(text);
  return stableEventId ? `stable:${meta.conversationId ?? "unknown"}:${stableEventId}:${contentHash}` : `content:${meta.conversationId ?? "unknown"}:${contentHash}`;
}
function pruneOutboundCache(cache, now) {
  for (const [key, entry] of cache) {
    if (now - entry.createdAt > OUTBOUND_DEDUPE_TTL_MS) cache.delete(key);
  }
}
function buildStableRequestId(meta, text) {
  const stableEventId = meta.idempotencyKey ?? meta.messageId ?? meta.toolCallId ?? meta.runId ?? meta.traceId ?? (meta.hookName.startsWith("subagent_") ? meta.childSessionId : void 0);
  if (!stableEventId) return void 0;
  return `firewall-plugin-${sha256(safeStringify({
    hookName: meta.hookName,
    conversationId: meta.conversationId,
    stableEventId,
    contentHash: sha256(text)
  }))}`;
}
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function shouldBlockClassification(config, result) {
  if (config.shadowMode || !config.blockMalicious || !result) {
    return false;
  }
  return result.prediction === "MALICIOUS";
}
function emitOpenClawLocalEvidence(meta, rawText, result, config, nativeAction, enforceableBoundary) {
  if (!result) {
    return;
  }
  const mode = !config.shadowMode && config.blockMalicious ? "block" : "shadow";
  const malicious = result.prediction === "MALICIOUS";
  emitLocalProtectionEventBestEffort({
    host: "openClaw",
    hook: localHook(meta),
    mode,
    rawText,
    requestIdentity: buildStableRequestId(meta, rawText),
    sessionIdentity: meta.sessionId ?? meta.sessionKey ?? meta.conversationId,
    toolName: meta.toolName,
    classification: result,
    policyDecision: malicious ? mode === "block" && enforceableBoundary ? "block" : "monitor" : "allow",
    nativeAction,
    producer: PLUGIN_ID,
    producerVersion: PLUGIN_VERSION,
    pluginVersion: PLUGIN_VERSION,
    policyVersion: LOCAL_EVIDENCE_POLICY_VERSION
  });
}
function localHook(meta) {
  if (meta.hookName.startsWith("subagent_")) {
    return "subagent";
  }
  switch (meta.hookName) {
    case "before_agent_run":
      return "user_input";
    case "before_tool_call":
      return "pre_tool";
    case "after_tool_call":
      return "post_tool";
    case "tool_result_persist":
      return "tool_result";
    case "message_sending":
    case "reply_payload_sending":
    case "message_sent":
      return "llm_output";
    default:
      return "unknown";
  }
}
const shouldBlockToolCall = shouldBlockClassification;
function buildBlockResult(result, meta) {
  return {
    block: true,
    blockReason: formatBlockReason(result)
  };
}
function buildMessageSendingBlock(result, meta) {
  return {
    cancel: true,
    content: buildBlockedReplacement(result, meta, "The original assistant message was withheld before delivery.")
  };
}
function buildBeforeAgentRunBlock(result, meta) {
  return {
    outcome: "block",
    reason: formatBlockReason(result),
    message: buildBlockedReplacement(result, meta, "The model run was stopped before submission.")
  };
}
function buildReplyPayloadSendingReplacement(event, result, meta) {
  const action = "The original reply payload was replaced before channel delivery.";
  const replacement = buildBlockedReplacement(result, meta, action);
  const originalPayload = readRecord(readRecord(event)?.payload);
  const payload = omitUndefined({
    text: replacement,
    presentation: buildMessagePresentation(result, meta, action),
    isStatusNotice: true,
    replyToId: readString(originalPayload?.replyToId),
    replyToTag: typeof originalPayload?.replyToTag === "boolean" ? originalPayload.replyToTag : void 0,
    replyToCurrent: typeof originalPayload?.replyToCurrent === "boolean" ? originalPayload.replyToCurrent : void 0
  });
  return { payload };
}
function buildMessagePresentation(result, meta, action) {
  return {
    title: "Silmaril Firewall blocked unsafe content",
    tone: "danger",
    blocks: [
      { type: "text", text: `Surface: ${describeSurface(meta)}` },
      { type: "text", text: `Reason: ${describeRisk(result)}` },
      { type: "divider" },
      { type: "context", text: action },
      { type: "context", text: "Next step: Rephrase the request, remove sensitive content, or ask the user for a safer path." }
    ]
  };
}
function buildBlockedReplacement(result, meta, reason) {
  return [
    "Silmaril Firewall blocked unsafe content",
    "",
    `Surface: ${describeSurface(meta)}`,
    `Risk: ${describeRisk(result)}`,
    `Action: ${reason}`,
    "Next step: Rephrase the request, remove sensitive content, or ask the user for a safer path."
  ].join("\n");
}
function formatBlockReason(result) {
  return `Silmaril Firewall blocked this request: ${describeRisk(result)}. Continue without using the blocked content.`;
}
function describeSurface(meta) {
  const labels = {
    before_agent_run: "agent prompt",
    before_tool_call: "tool call",
    after_tool_call: "tool result",
    tool_result_persist: "tool result",
    message_sending: "assistant message",
    reply_payload_sending: "reply delivery payload",
    message_sent: "delivered message",
    subagent_delivery_target: "subagent delivery target",
    subagent_spawned: "subagent start",
    subagent_ended: "subagent final output"
  };
  const base = labels[meta.hookName] ?? "agent event";
  const tool = meta.toolName ? ` (${meta.toolName})` : "";
  const id = meta.toolCallId ? ` [${meta.toolCallId}]` : "";
  return `${base}${tool}${id}`;
}
function describeRisk(result) {
  const outcome = typeof result.primaryOutcome === "string" ? result.primaryOutcome : void 0;
  const prediction = typeof result.prediction === "string" ? result.prediction.trim().toLowerCase() : void 0;
  switch (outcome?.trim().toLowerCase()) {
    case "information_disclosure":
      return "Sensitive information disclosure";
    case "secret_exposure":
      return "Secret or credential exposure";
    case "control_abuse":
    case "prompt_injection":
      return "Unsafe agent control attempt";
    case "system_compromise":
      return "System compromise risk";
    case "service_disruption":
      return "Service disruption risk";
    case "benign":
      return "No flagged risk";
    case void 0:
      return prediction === "benign" ? "No flagged risk" : "Unsafe content";
    default:
      return outcome.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
  }
}
function buildHookLogMeta(hookName, hook, event, ctx) {
  const eventRecord = readRecord(event);
  const ctxRecord = readRecord(ctx);
  const messageRecord = readRecord(eventRecord?.message);
  const childRecord = readRecord(eventRecord?.child);
  const childSessionId = readString(eventRecord?.childSessionId) ?? readString(ctxRecord?.childSessionId) ?? readString(childRecord?.sessionId);
  const sessionId = readString(eventRecord?.sessionId) ?? readString(ctxRecord?.sessionId) ?? readString(messageRecord?.sessionId);
  const sessionKey = readString(eventRecord?.sessionKey) ?? readString(ctxRecord?.sessionKey) ?? readString(messageRecord?.sessionKey);
  const parentSessionId = readString(eventRecord?.parentSessionId) ?? readString(ctxRecord?.parentSessionId) ?? readString(childRecord?.parentSessionId);
  return {
    hookName,
    hook,
    toolName: readString(eventRecord?.toolName) ?? readString(ctxRecord?.toolName) ?? readString(messageRecord?.toolName),
    toolCallId: readString(eventRecord?.toolCallId) ?? readString(ctxRecord?.toolCallId) ?? readString(messageRecord?.toolCallId),
    runId: readString(eventRecord?.runId) ?? readString(ctxRecord?.runId) ?? readString(messageRecord?.runId),
    sessionKey,
    sessionId,
    childSessionId,
    parentSessionId,
    conversationId: childSessionId ?? sessionId ?? sessionKey ?? parentSessionId,
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
      childSessionId: meta.childSessionId,
      parentSessionId: meta.parentSessionId,
      conversationId: meta.conversationId,
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
    risk: describeRisk(result)
  }));
}
function logObserved(meta) {
  console.log("[firewall] " + meta.hookName + " observed:", JSON.stringify(logFields(meta)));
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
  const networkMatch = firstLine.match(/\b(ECONNREFUSED|ENOTFOUND|ECONNRESET|ETIMEDOUT|EAI_AGAIN)\b/);
  if (networkMatch) {
    return `network_error_${networkMatch[1]}`;
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
const MAX_CONTENT_TEXT_DEPTH = 24;
function extractContentText(content, depth = 0, seen = /* @__PURE__ */ new WeakSet()) {
  if (depth > MAX_CONTENT_TEXT_DEPTH) {
    return "";
  }
  if (typeof content === "string") {
    return content;
  }
  if (content && typeof content === "object" && !Array.isArray(content)) {
    if (seen.has(content)) {
      return "";
    }
    seen.add(content);
    const record = content;
    if (typeof record.text === "string") {
      return record.text;
    }
    if (record.content !== void 0) {
      return extractContentText(record.content, depth + 1, seen);
    }
    return "";
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content.map((part) => extractContentText(part, depth + 1, seen)).join("\n");
}
function extractToolResultText(event) {
  return extractContentText(event?.message?.content);
}
function extractAfterToolCallText(event) {
  const record = readRecord(event);
  const candidate = record?.result ?? record?.toolResult ?? record?.message ?? record?.output ?? record?.error;
  const text = extractContentText(candidate);
  return text.trim() ? text : safeStringify(candidate ?? record ?? {});
}
function extractMessageSendingText(event) {
  return extractContentText(event?.content);
}
function extractReplyPayloadText(event) {
  const record = readRecord(event);
  const payload = readRecord(record?.payload) ?? record;
  const parts = [
    readString(payload?.text),
    readString(payload?.spokenText),
    extractPresentationText(payload?.presentation)
  ].filter((part) => typeof part === "string" && part.trim().length > 0);
  const text = parts.join("\n\n");
  return text.trim() ? text : safeStringify(payload ?? {});
}
function extractMessageSentText(event) {
  const record = readRecord(event);
  const candidate = record?.content ?? record?.text ?? record?.message ?? record?.payload;
  const text = extractContentText(candidate);
  return text.trim() ? text : safeStringify(candidate ?? record ?? {});
}
function extractPresentationText(presentation) {
  const record = readRecord(presentation);
  if (!record) {
    return "";
  }
  const parts = [];
  const title = readString(record.title);
  if (title) {
    parts.push(title);
  }
  if (Array.isArray(record.blocks)) {
    for (const block of record.blocks) {
      const blockRecord = readRecord(block);
      if (!blockRecord) {
        continue;
      }
      const text = readString(blockRecord.text) ?? readString(blockRecord.label) ?? readString(blockRecord.title);
      if (text) {
        parts.push(text);
      }
      const elements = blockRecord.elements;
      if (Array.isArray(elements)) {
        for (const element of elements) {
          const elementRecord = readRecord(element);
          const elementText = readString(elementRecord?.text) ?? readString(elementRecord?.label) ?? readString(elementRecord?.title);
          if (elementText) {
            parts.push(elementText);
          }
        }
      }
    }
  }
  return parts.join("\n");
}
function extractLifecycleText(event) {
  const record = readRecord(event);
  if (!record) {
    return "";
  }
  const parts = [];
  const seen = /* @__PURE__ */ new Set();
  const add = (value) => {
    const text = typeof value === "string" ? readString(value) : extractContentText(value);
    if (text && !seen.has(text)) {
      seen.add(text);
      parts.push(text);
    }
  };
  const addRecordFields = (source) => {
    if (!source) {
      return;
    }
    for (const key of [
      "message",
      "content",
      "text",
      "prompt",
      "goal",
      "task",
      "summary",
      "result",
      "finalOutput",
      "output",
      "childGoal",
      "childSummary",
      "deliveryTarget"
    ]) {
      add(source[key]);
    }
  };
  addRecordFields(record);
  addRecordFields(readRecord(record.child));
  add(record.payload);
  add(record.messages);
  add(record.presentation);
  return parts.join("\n");
}
function extractAgentRunText(event) {
  const record = readRecord(event);
  const prompt = readString(record?.prompt) ?? readString(record?.finalPrompt);
  if (prompt) {
    return prompt;
  }
  const messages = extractContentText(record?.messages);
  if (messages.trim()) {
    return messages;
  }
  return safeStringify(record?.messages ?? record?.prompt ?? record ?? {});
}
const __testInternals = {
  resolveRuntimeConfig,
  readRecord,
  readString,
  readIntegerInRange,
  readBoolean,
  classifyHookPayload,
  classifyOutboundOnce,
  outboundDedupeKey,
  buildStableRequestId,
  shouldBlockClassification,
  shouldBlockToolCall,
  buildBlockResult,
  buildMessageSendingBlock,
  buildBeforeAgentRunBlock,
  buildReplyPayloadSendingReplacement,
  buildMessagePresentation,
  buildBlockedReplacement,
  formatBlockReason,
  describeRisk,
  buildHookLogMeta,
  readTraceId,
  logFields,
  logSkipped,
  logBlocked,
  logError,
  safeErrorFields,
  safeErrorMessage,
  safeStringify,
  extractContentText,
  extractToolResultText,
  extractAfterToolCallText,
  extractMessageSendingText,
  extractReplyPayloadText,
  extractMessageSentText,
  extractPresentationText,
  extractLifecycleText,
  extractAgentRunText,
  buildLocalProtectionEvent,
  emitLocalProtectionEvent,
  resolveLocalEventDirectory,
  emitOpenClawLocalEvidence,
  localHook
};
export {
  __testInternals,
  index_default as default
};
