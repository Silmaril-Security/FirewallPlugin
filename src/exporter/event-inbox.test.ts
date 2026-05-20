import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DurableEventInbox, EventSequencer, prepareQueuedEvent } from "./event-inbox";
import type { ExporterLogger, ExporterRuntime, FirewallExportEventInput } from "./types";

const logger: ExporterLogger = {
  info() {},
  warn() {},
  error() {},
};

test("prepareQueuedEvent preserves source timestamp and sanitizes payloads", () => {
  const circular: Record<string, unknown> = { ok: true };
  circular.self = circular;

  const queued = prepareQueuedEvent(
    {
      source: "tool_call",
      ts: "2026-05-02T04:40:21.270Z",
      toolName: "write",
      payload: circular,
      firewallResult: { prediction: "BENIGN" },
    },
    new Date("2026-05-02T04:40:22.000Z"),
  );

  assert.equal(queued.sourceTs, "2026-05-02T04:40:21.270Z");
  assert.equal(queued.event.ts, "2026-05-02T04:40:21.270Z");
  assert.equal(queued.event.toolName, "write");
  assert.deepEqual(queued.event.payload, { ok: true, self: "[Circular]" });
  assert.equal(typeof queued.event.eventId, "string");
});

test("sequencer writes ready inbox events in source timestamp order", async () => {
  await withInbox(async ({ inbox, sequencer, writer }) => {
    await inbox.enqueue(event("agent_session_event", "agent-1", "2026-05-02T04:40:22.000Z"));
    await inbox.enqueue(event("user_input", "hook-1", "2026-05-02T04:40:21.000Z"));

    await sequencer.kick({ flushAll: true });

    assert.deepEqual(
      writer.events.map((item) => item.eventId),
      ["hook-1", "agent-1"],
    );
  });
});

test("sequencer uses hook priority for same-timestamp ties", async () => {
  await withInbox(async ({ inbox, sequencer, writer }) => {
    const ts = "2026-05-02T04:40:21.000Z";
    await inbox.enqueue(event("agent_session_event", "agent-1", ts));
    await inbox.enqueue(event("tool_call", "hook-1", ts));

    await sequencer.kick({ flushAll: true });

    assert.deepEqual(
      writer.events.map((item) => item.eventId),
      ["hook-1", "agent-1"],
    );
  });
});

test("sequencer reorder window holds recent events until they age out", async () => {
  await withInbox(
    async ({ inbox, sequencer, writer, readyDir }) => {
      await inbox.enqueue(event("user_input", "recent-hook", new Date().toISOString()));

      await sequencer.kick();
      assert.equal(writer.events.length, 0);
      assert.equal((await readdir(readyDir)).filter((name) => name.endsWith(".json")).length, 1);

      await sequencer.kick({ flushAll: true });
      assert.deepEqual(
        writer.events.map((item) => item.eventId),
        ["recent-hook"],
      );
    },
    { reorderWindowMs: 60_000 },
  );
});

test("sequencer dedupes repeated deterministic event ids", async () => {
  await withInbox(async ({ inbox, sequencer, writer, readyDir }) => {
    const first = event("agent_session_event", "agent-duplicate", "2026-05-02T04:40:21.000Z");
    const second = event("agent_session_event", "agent-duplicate", "2026-05-02T04:40:21.000Z");
    await inbox.enqueue(first);
    await inbox.enqueue(second);

    await sequencer.kick({ flushAll: true });

    assert.deepEqual(
      writer.events.map((item) => item.eventId),
      ["agent-duplicate"],
    );
    assert.equal((await readdir(readyDir)).filter((name) => name.endsWith(".json")).length, 0);
  });
});

test("sequencer runs file collector hook before sorting eligible events", async () => {
  let inboxRef: DurableEventInbox | undefined;
  await withInbox(
    async ({ inbox, sequencer, writer }) => {
      inboxRef = inbox;
      await inbox.enqueue(event("tool_call", "hook-later", "2026-05-02T04:40:22.000Z"));

      await sequencer.kick();

      assert.deepEqual(
        writer.events.map((item) => item.eventId),
        ["agent-earlier", "hook-later"],
      );
    },
    {
      beforeDrain: async () => {
        await inboxRef?.enqueue(event("agent_session_event", "agent-earlier", "2026-05-02T04:40:21.000Z"));
      },
    },
  );
});


function event(source: FirewallExportEventInput["source"], eventId: string, ts: string): FirewallExportEventInput {
  return {
    source,
    eventId,
    ts,
    payload: {
      eventId,
    },
  };
}

async function withInbox(
  fn: (ctx: {
    inbox: DurableEventInbox;
    sequencer: EventSequencer;
    writer: FakeWriter;
    readyDir: string;
  }) => Promise<void>,
  options: { reorderWindowMs?: number; beforeDrain?: () => Promise<void> } = {},
): Promise<void> {
  const root = await mkdtemp(path.join(os.tmpdir(), "firewall-event-inbox-test-"));
  const readyDir = path.join(root, "ready");
  const inbox = new DurableEventInbox(
    {
      inboxTmpDir: path.join(root, "tmp"),
      inboxReadyDir: readyDir,
    },
    logger,
  );
  const writer = new FakeWriter();
  const runtime = {
    logger,
  } as ExporterRuntime;
  const sequencer = new EventSequencer(runtime, inbox, writer as never, path.join(root, "sequencer-checkpoint.json"), {
    loopIntervalMs: 60_000,
    reorderWindowMs: options.reorderWindowMs ?? 0,
    beforeDrain: options.beforeDrain,
  });

  try {
    await fn({ inbox, sequencer, writer, readyDir });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

class FakeWriter {
  readonly events: FirewallExportEventInput[] = [];

  async writeEvent(event: FirewallExportEventInput): Promise<void> {
    this.events.push(event);
  }
}
