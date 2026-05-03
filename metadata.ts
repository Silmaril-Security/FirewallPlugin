export type MetadataRecord = Record<string, unknown>;

type TraceLike = {
  traceId?: unknown;
  spanId?: unknown;
  parentSpanId?: unknown;
  traceFlags?: unknown;
};

type ContextLike = {
  runId?: unknown;
  jobId?: unknown;
  trace?: TraceLike;
  agentId?: unknown;
  sessionKey?: unknown;
  sessionId?: unknown;
  workspaceDir?: unknown;
  modelProviderId?: unknown;
  modelId?: unknown;
  messageProvider?: unknown;
  trigger?: unknown;
  channelId?: unknown;
  toolName?: unknown;
  toolCallId?: unknown;
};

function addDefined(target: MetadataRecord, key: string, value: unknown): void {
  if (value !== undefined && value !== null) {
    target[key] = value;
  }
}

function addTrace(target: MetadataRecord, trace: TraceLike | undefined): void {
  if (!trace || typeof trace !== "object") {
    return;
  }
  addDefined(target, "trace_id", trace.traceId);
  addDefined(target, "span_id", trace.spanId);
  addDefined(target, "parent_span_id", trace.parentSpanId);
  addDefined(target, "trace_flags", trace.traceFlags);
}

function commonMetadata(
  pluginHook: string,
  firewallHook: string,
  ctx: ContextLike | undefined,
): MetadataRecord {
  const metadata: MetadataRecord = {
    platform: "openclaw",
    plugin_hook: pluginHook,
    firewall_hook: firewallHook,
  };

  addDefined(metadata, "run_id", ctx?.runId);
  addDefined(metadata, "agent_id", ctx?.agentId);
  addDefined(metadata, "session_key", ctx?.sessionKey);
  addDefined(metadata, "session_id", ctx?.sessionId);
  addTrace(metadata, ctx?.trace);

  return metadata;
}

export function buildBeforeToolCallMetadata(
  event: { toolName?: unknown; runId?: unknown; toolCallId?: unknown },
  ctx: ContextLike | undefined,
  firewallHook: string,
): MetadataRecord {
  const metadata = commonMetadata("before_tool_call", firewallHook, ctx);

  addDefined(metadata, "run_id", metadata.run_id ?? event.runId);
  addDefined(metadata, "tool_name", event.toolName ?? ctx?.toolName);
  addDefined(metadata, "tool_call_id", event.toolCallId ?? ctx?.toolCallId);

  return metadata;
}

export function buildToolResultPersistMetadata(
  event: {
    toolName?: unknown;
    toolCallId?: unknown;
    isSynthetic?: unknown;
    message?: { role?: unknown; content?: unknown };
  },
  ctx: ContextLike | undefined,
  firewallHook: string,
): MetadataRecord {
  const metadata = commonMetadata("tool_result_persist", firewallHook, ctx);
  const contentParts = messageContentParts(event.message);

  addDefined(metadata, "tool_name", event.toolName ?? ctx?.toolName);
  addDefined(metadata, "tool_call_id", event.toolCallId ?? ctx?.toolCallId);
  addDefined(metadata, "is_synthetic", event.isSynthetic);
  addDefined(metadata, "message_role", event.message?.role);
  metadata.content_part_count = contentParts.length;
  metadata.content_types = contentParts.map(contentPartType);

  return metadata;
}

export function buildBeforePromptBuildMetadata(
  event: { messages?: unknown },
  ctx: ContextLike | undefined,
  firewallHook: string,
): MetadataRecord {
  const metadata = commonMetadata("before_prompt_build", firewallHook, ctx);

  addDefined(metadata, "job_id", ctx?.jobId);
  addDefined(metadata, "workspace_dir", ctx?.workspaceDir);
  addDefined(metadata, "model_provider_id", ctx?.modelProviderId);
  addDefined(metadata, "model_id", ctx?.modelId);
  addDefined(metadata, "message_provider", ctx?.messageProvider);
  addDefined(metadata, "trigger", ctx?.trigger);
  addDefined(metadata, "channel_id", ctx?.channelId);
  if (Array.isArray(event.messages)) {
    metadata.message_count = event.messages.length;
  }

  return metadata;
}

export function extractToolResultText(event: { message?: { content?: unknown } }): string {
  const content = event.message?.content;
  if (typeof content === "string") {
    return content;
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

function messageContentParts(message: { content?: unknown } | undefined): unknown[] {
  const content = message?.content;
  if (Array.isArray(content)) {
    return content;
  }
  if (content === undefined || content === null) {
    return [];
  }
  return [content];
}

function contentPartType(part: unknown): string {
  if (typeof part === "string") {
    return "text";
  }
  if (part && typeof part === "object") {
    const record = part as { type?: unknown; kind?: unknown };
    if (typeof record.type === "string") {
      return record.type;
    }
    if (typeof record.kind === "string") {
      return record.kind;
    }
    if (typeof (part as { text?: unknown }).text === "string") {
      return "text";
    }
  }
  return typeof part;
}
