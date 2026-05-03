import assert from "node:assert/strict";
import test from "node:test";

import {
  buildBeforePromptBuildMetadata,
  buildBeforeToolCallMetadata,
  buildToolResultPersistMetadata,
  extractToolResultText,
} from "../metadata.ts";

test("before_tool_call metadata includes common, trace, and tool fields", () => {
  const metadata = buildBeforeToolCallMetadata(
    {
      toolName: "read_file",
      runId: "event-run",
      toolCallId: "event-call",
    },
    {
      runId: "ctx-run",
      agentId: "agent-1",
      sessionKey: "session-key",
      sessionId: "session-id",
      trace: {
        traceId: "0".repeat(32),
        spanId: "1".repeat(16),
        parentSpanId: "2".repeat(16),
        traceFlags: "01",
      },
    },
    "tool_call",
  );

  assert.deepEqual(metadata, {
    platform: "openclaw",
    plugin_hook: "before_tool_call",
    firewall_hook: "tool_call",
    run_id: "ctx-run",
    agent_id: "agent-1",
    session_key: "session-key",
    session_id: "session-id",
    trace_id: "0".repeat(32),
    span_id: "1".repeat(16),
    parent_span_id: "2".repeat(16),
    trace_flags: "01",
    tool_name: "read_file",
    tool_call_id: "event-call",
  });
});

test("tool_result_persist metadata includes message and content part metadata", () => {
  const metadata = buildToolResultPersistMetadata(
    {
      toolName: "shell_exec",
      toolCallId: "call-1",
      isSynthetic: false,
      message: {
        role: "tool",
        content: [
          { type: "text", text: "first" },
          { kind: "image" },
          { text: "second" },
        ],
      },
    },
    { agentId: "agent-1", sessionKey: "session-key" },
    "tool_response",
  );

  assert.equal(metadata.platform, "openclaw");
  assert.equal(metadata.plugin_hook, "tool_result_persist");
  assert.equal(metadata.firewall_hook, "tool_response");
  assert.equal(metadata.agent_id, "agent-1");
  assert.equal(metadata.session_key, "session-key");
  assert.equal(metadata.tool_name, "shell_exec");
  assert.equal(metadata.tool_call_id, "call-1");
  assert.equal(metadata.is_synthetic, false);
  assert.equal(metadata.message_role, "tool");
  assert.equal(metadata.content_part_count, 3);
  assert.deepEqual(metadata.content_types, ["text", "image", "text"]);
});

test("before_prompt_build metadata includes model context and omits missing optionals", () => {
  const metadata = buildBeforePromptBuildMetadata(
    { messages: [{}, {}] },
    {
      runId: "run-1",
      jobId: "job-1",
      workspaceDir: "/workspace",
      modelProviderId: "openai",
      modelId: "gpt-test",
      messageProvider: "slack",
      trigger: "manual",
      channelId: "channel-1",
    },
    "user_input",
  );

  assert.equal(metadata.plugin_hook, "before_prompt_build");
  assert.equal(metadata.run_id, "run-1");
  assert.equal(metadata.job_id, "job-1");
  assert.equal(metadata.workspace_dir, "/workspace");
  assert.equal(metadata.model_provider_id, "openai");
  assert.equal(metadata.model_id, "gpt-test");
  assert.equal(metadata.message_provider, "slack");
  assert.equal(metadata.trigger, "manual");
  assert.equal(metadata.channel_id, "channel-1");
  assert.equal(metadata.message_count, 2);
  assert.equal("session_id" in metadata, false);
});

test("extractToolResultText preserves the existing text-part join behavior", () => {
  assert.equal(
    extractToolResultText({
      message: {
        content: [{ text: "alpha" }, { image: "ignored" }, { text: "omega" }],
      },
    }),
    "alpha\n\nomega",
  );
});
