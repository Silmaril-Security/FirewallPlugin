#!/usr/bin/env node
// Synthetic exporter event injector. Imports the queue helpers directly and
// writes N events to the on-disk pending/ queue without going through the
// OpenClaw gateway. The actual uploader (running in the OpenClaw process)
// will pick up the events on its next tick. Used by docker/e2e-exporter.ps1.
//
// Usage:
//   node --import tsx scripts/exporter-bench.mjs \
//        --state-dir /tmp/x --count 50 --corr-id RUN_A \
//        [--source hook_event] [--hook-name before_prompt_build] \
//        [--payload-bytes 100] [--concurrent 1] [--prefix runtime]

import path from "node:path";
import os from "node:os";
import { ensureQueueDirectories, enqueueEvent, prepareEvent } from "../src/exporter/simple-queue.ts";

function parseArgs(argv) {
  const args = {
    stateDir: process.env.OPENCLAW_STATE_DIR ?? path.join(os.homedir(), ".openclaw"),
    count: 1,
    corrId: "RUN_DEFAULT",
    source: "hook_event",
    hookName: "before_prompt_build",
    toolName: undefined,
    payloadBytes: 100,
    concurrent: 1,
    prefix: "bench",
    printPayloadKeys: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--state-dir": args.stateDir = next; i++; break;
      case "--count": args.count = Number(next); i++; break;
      case "--corr-id": args.corrId = next; i++; break;
      case "--source": args.source = next; i++; break;
      case "--hook-name": args.hookName = next === "" ? undefined : next; i++; break;
      case "--tool-name": args.toolName = next; i++; break;
      case "--payload-bytes": args.payloadBytes = Number(next); i++; break;
      case "--concurrent": args.concurrent = Number(next); i++; break;
      case "--prefix": args.prefix = next; i++; break;
      case "--print-payload-keys": args.printPayloadKeys = true; break;
      default: throw new Error(`unknown arg: ${arg}`);
    }
  }
  return args;
}

function deriveExporterPaths(stateDir) {
  const exportDir = path.join(stateDir, "firewall-plugin", "export");
  return {
    stateDir,
    exportDir,
    pendingDir: path.join(exportDir, "pending"),
    inflightDir: path.join(exportDir, "inflight"),
    tmpDir: path.join(exportDir, "tmp"),
    logsDir: path.join(exportDir, "logs"),
    leasePath: path.join(exportDir, "upload-lease.json"),
    logPath: path.join(exportDir, "logs", "exporter.log"),
  };
}

function buildPayload(args, idx) {
  // Pad to roughly args.payloadBytes (for batch-sizing tests). The
  // padding string is deterministic so events are byte-stable across runs.
  const padTarget = Math.max(0, args.payloadBytes - 100);
  const pad = padTarget > 0 ? "P".repeat(padTarget) : "";
  return {
    correlationId: args.corrId,
    benchPrefix: args.prefix,
    idx,
    pid: process.pid,
    stamp: Date.now(),
    pad,
  };
}

async function main() {
  const args = parseArgs(process.argv);
  const paths = deriveExporterPaths(args.stateDir);
  await ensureQueueDirectories(paths);

  const runtime = { apiKeyPathId: "1of9epawm2", host: os.hostname() };

  const enqueueOne = async (i) => {
    const event = prepareEvent({
      source: args.source,
      hookName: args.hookName,
      toolName: args.toolName,
      payload: buildPayload(args, i),
    }, runtime);
    await enqueueEvent(paths, event);
    return event;
  };

  let done = 0;
  if (args.concurrent <= 1) {
    for (let i = 0; i < args.count; i++) {
      await enqueueOne(i);
      done++;
    }
  } else {
    // Fire in waves of `concurrent` parallel calls.
    let i = 0;
    while (i < args.count) {
      const wave = [];
      for (let k = 0; k < args.concurrent && i < args.count; k++, i++) {
        wave.push(enqueueOne(i));
      }
      await Promise.all(wave);
      done += wave.length;
    }
  }

  console.log(`bench:enqueued count=${done} corrId=${args.corrId} prefix=${args.prefix} pendingDir=${paths.pendingDir}`);
}

main().catch((err) => {
  console.error(`bench:error ${err?.message ?? err}`);
  process.exit(1);
});
