import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import * as fsp from "node:fs/promises";
import { gunzipSync } from "node:zlib";
import os from "node:os";
import path from "node:path";
import test, { mock } from "node:test";

import {
  claimBatch,
  commitBatch,
  enqueueEvent,
  ensureQueueDirectories,
  fsp as queueFs,
  prepareEvent,
  recoverStaleBatches,
} from "./simple-queue";
import { Uploader } from "./uploader";
import {
  EXPORT_BUCKET,
  EXPORT_LOGS_PREFIX,
  type ExporterLogger,
  type ExporterPaths,
  type ExporterRuntime,
  type FirewallExportEvent,
  type FirewallExportEventInput,
  type UploadLease,
} from "./types";

function makePaths(stateRoot: string): ExporterPaths {
  const exportDir = path.join(stateRoot, "firewall-plugin", "export");
  return {
    stateDir: stateRoot,
    exportDir,
    pendingDir: path.join(exportDir, "pending"),
    inflightDir: path.join(exportDir, "inflight"),
    tmpDir: path.join(exportDir, "tmp"),
    logsDir: path.join(exportDir, "logs"),
    leasePath: path.join(exportDir, "upload-lease.json"),
    logPath: path.join(exportDir, "logs", "exporter.log"),
  };
}

async function makeTempPaths(): Promise<ExporterPaths> {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "exporter-queue-"));
  const paths = makePaths(root);
  await ensureQueueDirectories(paths);
  return paths;
}

async function cleanup(paths: ExporterPaths): Promise<void> {
  await fsp.rm(paths.stateDir, { recursive: true, force: true });
}

const TEST_RUNTIME_FIELDS = {
  apiKeyPathId: "test-key-path",
  host: "test-host",
};

function silentLogger(): ExporterLogger {
  return {
    info() {},
    warn() {},
    error() {},
  };
}

function makeRuntime(paths: ExporterPaths): ExporterRuntime {
  return {
    apiKey: "test-api-key",
    apiKeyPathId: TEST_RUNTIME_FIELDS.apiKeyPathId,
    host: TEST_RUNTIME_FIELDS.host,
    paths,
    logger: silentLogger(),
  };
}

function makeFakeLease(): UploadLease {
  return {
    type: "s3-post",
    bucket: EXPORT_BUCKET,
    url: "https://example-bucket.s3.amazonaws.com/",
    fields: {
      Policy: Buffer.from(JSON.stringify({ conditions: [["starts-with", "$key", `${EXPORT_LOGS_PREFIX}test-tenant/`]] })).toString("base64"),
      "X-Amz-Signature": "sig",
    },
    keyPrefix: `${EXPORT_LOGS_PREFIX}test-tenant/`,
    contentType: "application/gzip",
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    fetchedAt: new Date().toISOString(),
  };
}

async function seedLease(paths: ExporterPaths, lease: UploadLease): Promise<void> {
  await fsp.writeFile(paths.leasePath, JSON.stringify(lease), "utf8");
}

function makeInput(suffix: string): FirewallExportEventInput {
  return {
    source: "hook_event",
    hookName: "before_prompt_build",
    payload: { suffix },
  };
}

test("enqueueEvent — N parallel writes produce N distinct files", async () => {
  const paths = await makeTempPaths();
  try {
    const count = 25;
    const inputs = Array.from({ length: count }, (_, i) => makeInput(`evt-${i}`));
    const prepared = inputs.map((input) => prepareEvent(input, TEST_RUNTIME_FIELDS));

    await Promise.all(prepared.map((event) => enqueueEvent(paths, event)));

    const entries = await fsp.readdir(paths.pendingDir);
    assert.equal(entries.length, count, "expected one pending file per enqueue");

    const seenIds = new Set<string>();
    for (const fileName of entries) {
      const raw = await fsp.readFile(path.join(paths.pendingDir, fileName), "utf8");
      const parsed = JSON.parse(raw) as FirewallExportEvent;
      assert.equal(parsed.schemaVersion, 1);
      assert.equal(parsed.source, "hook_event");
      assert.ok(parsed.eventId, "eventId is set");
      seenIds.add(parsed.eventId);
    }
    assert.equal(seenIds.size, count, "every event has a unique id");
  } finally {
    await cleanup(paths);
  }
});

test("two uploaders against the same paths upload each event exactly once", async () => {
  const paths = await makeTempPaths();
  await seedLease(paths, makeFakeLease());

  const recordedKeys: string[] = [];
  const uploadedEventIds: string[] = [];
  const fetchMock = mock.method(globalThis, "fetch", async (input: unknown, init?: { body?: unknown }) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    if (!url.includes("amazonaws.com")) {
      return new Response(JSON.stringify({}), { status: 200 });
    }

    const form = init?.body as FormData;
    const key = form.get("key") as string;
    const file = form.get("file") as Blob;
    const buf = Buffer.from(await file.arrayBuffer());
    const text = gunzipSync(buf).toString("utf8");
    for (const line of text.split("\n").filter(Boolean)) {
      uploadedEventIds.push((JSON.parse(line) as FirewallExportEvent).eventId);
    }
    recordedKeys.push(key);
    return new Response(null, { status: 204 });
  });

  try {
    const total = 30;
    const events = Array.from({ length: total }, (_, i) =>
      prepareEvent({ ...makeInput(`race-${i}`), eventId: `race-${i}` }, TEST_RUNTIME_FIELDS),
    );
    await Promise.all(events.map((evt) => enqueueEvent(paths, evt)));

    const uploaderA = new Uploader(makeRuntime(paths));
    const uploaderB = new Uploader(makeRuntime(paths));

    await Promise.all([uploaderA.kick(), uploaderB.kick()]);

    assert.equal(uploadedEventIds.length, total, "every event uploaded exactly once");
    const unique = new Set(uploadedEventIds);
    assert.equal(unique.size, total, "no duplicates across the two uploaders");

    const remainingPending = await fsp.readdir(paths.pendingDir);
    assert.equal(remainingPending.length, 0, "pending dir is drained");

    const remainingInflight = await fsp.readdir(paths.inflightDir);
    assert.equal(remainingInflight.length, 0, "inflight dirs are cleaned up");
  } finally {
    fetchMock.mock.restore();
    await cleanup(paths);
  }
});

test("recoverStaleBatches moves files from old inflight back to pending", async () => {
  const paths = await makeTempPaths();
  try {
    const deadDir = path.join(paths.inflightDir, `99999-${randomUUID()}`);
    await fsp.mkdir(deadDir, { recursive: true });

    const fileNames = ["a.json", "b.json", "c.json"];
    for (const name of fileNames) {
      const event = prepareEvent({ ...makeInput(name), eventId: name }, TEST_RUNTIME_FIELDS);
      await fsp.writeFile(path.join(deadDir, name), `${JSON.stringify(event)}\n`, "utf8");
    }

    const old = (Date.now() - 6 * 60 * 1000) / 1000;
    await fsp.utimes(deadDir, old, old);
    for (const name of fileNames) {
      await fsp.utimes(path.join(deadDir, name), old, old);
    }

    await recoverStaleBatches(paths, silentLogger(), 5 * 60 * 1000);

    const pending = await fsp.readdir(paths.pendingDir);
    assert.equal(pending.length, fileNames.length, "all files returned to pending");
    const inflight = await fsp.readdir(paths.inflightDir);
    assert.equal(inflight.length, 0, "stale inflight dir was removed");
  } finally {
    await cleanup(paths);
  }
});

test("uploader retries with a fresh lease after a 403 ExpiredToken", async () => {
  const paths = await makeTempPaths();
  await seedLease(paths, makeFakeLease());
  let postCount = 0;
  let leaseRefreshCount = 0;
  const uploadedEventIds: string[] = [];

  const fetchMock = mock.method(globalThis, "fetch", async (input: unknown, init?: { body?: unknown; method?: string }) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    if (url.includes("upload-lease")) {
      leaseRefreshCount += 1;
      return new Response(JSON.stringify(makeFakeLease()), { status: 200 });
    }

    postCount += 1;
    if (postCount === 1) {
      return new Response("<Error><Code>ExpiredToken</Code></Error>", {
        status: 403,
        statusText: "Forbidden",
      });
    }

    const form = init?.body as FormData;
    const file = form.get("file") as Blob;
    const text = gunzipSync(Buffer.from(await file.arrayBuffer())).toString("utf8");
    for (const line of text.split("\n").filter(Boolean)) {
      uploadedEventIds.push((JSON.parse(line) as FirewallExportEvent).eventId);
    }
    return new Response(null, { status: 204 });
  });

  try {
    const events = Array.from({ length: 5 }, (_, i) =>
      prepareEvent({ ...makeInput(`fresh-${i}`), eventId: `fresh-${i}` }, TEST_RUNTIME_FIELDS),
    );
    await Promise.all(events.map((evt) => enqueueEvent(paths, evt)));

    const uploader = new Uploader(makeRuntime(paths));
    await uploader.kick();

    assert.equal(postCount, 2, "exactly two POSTs (one rejected, one accepted)");
    assert.ok(leaseRefreshCount >= 1, "lease was refreshed at least once");
    assert.equal(uploadedEventIds.length, 5, "all events uploaded once");
    assert.equal(new Set(uploadedEventIds).size, 5, "no duplicate event ids");

    const pending = await fsp.readdir(paths.pendingDir);
    assert.equal(pending.length, 0, "pending drained");
    const inflight = await fsp.readdir(paths.inflightDir);
    assert.equal(inflight.length, 0, "inflight cleaned up");
  } finally {
    fetchMock.mock.restore();
    await cleanup(paths);
  }
});

test("malformed pending file is skipped without breaking the batch", async () => {
  const paths = await makeTempPaths();
  await seedLease(paths, makeFakeLease());
  const uploadedEventIds: string[] = [];

  const fetchMock = mock.method(globalThis, "fetch", async (input: unknown, init?: { body?: unknown }) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    if (!url.includes("amazonaws.com")) {
      return new Response(JSON.stringify({}), { status: 200 });
    }
    const form = init?.body as FormData;
    const file = form.get("file") as Blob;
    const text = gunzipSync(Buffer.from(await file.arrayBuffer())).toString("utf8");
    for (const line of text.split("\n").filter(Boolean)) {
      uploadedEventIds.push((JSON.parse(line) as FirewallExportEvent).eventId);
    }
    return new Response(null, { status: 204 });
  });

  try {
    const events = Array.from({ length: 3 }, (_, i) =>
      prepareEvent({ ...makeInput(`ok-${i}`), eventId: `ok-${i}` }, TEST_RUNTIME_FIELDS),
    );
    await Promise.all(events.map((evt) => enqueueEvent(paths, evt)));

    // Filename starts with "0-" so it sorts before any ISO-prefixed file and is
    // claimed first in the batch.
    await fsp.writeFile(path.join(paths.pendingDir, "0-corrupt.json"), "{not json}", "utf8");

    const uploader = new Uploader(makeRuntime(paths));
    await uploader.kick();

    assert.deepEqual(
      uploadedEventIds.sort(),
      ["ok-0", "ok-1", "ok-2"],
      "valid events still uploaded",
    );

    const pending = await fsp.readdir(paths.pendingDir);
    assert.deepEqual(pending, [], "pending drained");
    const inflightDirs = await fsp.readdir(paths.inflightDir);
    assert.deepEqual(inflightDirs, [], "inflight drained — corrupt file dropped, batch committed cleanly");
  } finally {
    fetchMock.mock.restore();
    await cleanup(paths);
  }
});

test("claimBatch tolerates transient EBUSY/EPERM rename failures", async () => {
  const paths = await makeTempPaths();
  try {
    const events = Array.from({ length: 4 }, (_, i) =>
      prepareEvent({ ...makeInput(`busy-${i}`), eventId: `busy-${i}` }, TEST_RUNTIME_FIELDS),
    );
    await Promise.all(events.map((evt) => enqueueEvent(paths, evt)));

    const realRename = queueFs.rename;
    let busyRemaining = 3;
    const renameMock = mock.method(queueFs, "rename", async (from: string, to: string) => {
      if (busyRemaining > 0 && from.includes(path.sep + "pending" + path.sep)) {
        busyRemaining -= 1;
        const err = new Error("simulated antivirus hold") as NodeJS.ErrnoException;
        err.code = "EBUSY";
        throw err;
      }
      return realRename(from, to);
    });

    try {
      const firstBatch = await claimBatch(paths, { maxEvents: 100, maxBytes: 10 * 1024 * 1024 });
      assert.ok(firstBatch, "first claim returns a batch");
      assert.equal(
        firstBatch!.events.length,
        events.length - 3,
        "first claim skipped 3 EBUSY-rejected files",
      );
      await commitBatch(firstBatch!);
    } finally {
      renameMock.mock.restore();
    }

    const secondBatch = await claimBatch(paths, { maxEvents: 100, maxBytes: 10 * 1024 * 1024 });
    assert.ok(secondBatch, "second claim picks up the previously-busy files");
    assert.equal(secondBatch!.events.length, 3, "remaining files claimed on next tick");
    await commitBatch(secondBatch!);

    const pending = await fsp.readdir(paths.pendingDir);
    assert.deepEqual(pending, []);
  } finally {
    await cleanup(paths);
  }
});
