import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";

const DEFAULT_CLASSIFY_TIMEOUT_MS = 2500;
const MIN_CLASSIFY_TIMEOUT_MS = 250;
const MAX_CLASSIFY_TIMEOUT_MS = 10000;

type RuntimeConfig = {
  apiKey: string;
  apiUrl: string;
  timeoutMs: number;
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
      if (!runtimeClient || !sameRuntimeConfig(runtimeClient.config, config)) {
        runtimeClient = {
          config,
          state: {
            firewall: new Firewall({
              apiKey: config.apiKey,
              apiUrl: config.apiUrl,
              timeoutMs: config.timeoutMs,
            }),
          },
        };
      }

      return runtimeClient.state;
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
        await classifyHookPayload(runtime.firewall, event.prompt, meta);
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

        void classifyHookPayload(runtime.firewall, text, meta)
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
    && left.timeoutMs === right.timeoutMs;
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
  classifyHookPayload,
  buildHookLogMeta,
  readTraceId,
  logFields,
  logSkipped,
  logError,
  safeStringify,
  extractToolResultText,
};
