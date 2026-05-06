import assert from "node:assert/strict";
import test from "node:test";

import { runClassification } from "./classify";
import type { FirewallClassifier } from "./types";

test("runClassification returns the firewall result", async () => {
  const calls: unknown[] = [];
  const firewall: FirewallClassifier = {
    async classify(text, options) {
      calls.push({ text, options });
      return { prediction: "MALICIOUS", score: 0.8 };
    },
  };

  assert.deepEqual(
    await runClassification({
      firewall,
      text: "payload",
      hook: "tool_response",
      toolName: "web_fetch",
      metadata: { user_email: "user@example.com" },
    }),
    { prediction: "MALICIOUS", score: 0.8 },
  );
  assert.deepEqual(calls, [
    {
      text: "payload",
      options: {
        hook: "tool_response",
        toolName: "web_fetch",
        metadata: { user_email: "user@example.com" },
      },
    },
  ]);
});

test("runClassification fails open on classifier errors and logs", async () => {
  const warnings: unknown[] = [];
  const firewall: FirewallClassifier = {
    async classify() {
      throw new Error("network down");
    },
  };

  assert.deepEqual(
    await runClassification({
      firewall,
      text: "payload",
      hook: "tool_response",
      logger: {
        warn(message, err) {
          warnings.push({ message, err });
        },
      },
    }),
    { prediction: "BENIGN", score: 0, classifierFailed: true },
  );
  assert.equal(warnings.length, 1);
  assert.match(String((warnings[0] as { message: string }).message), /classification failed/);
});

test("runClassification throws quickly when signal is already aborted", async () => {
  const controller = new AbortController();
  controller.abort(new DOMException("aborted", "AbortError"));

  await assert.rejects(
    runClassification({
      firewall: {
        async classify() {
          throw new Error("should not run");
        },
      },
      text: "payload",
      hook: "tool_response",
      signal: controller.signal,
    }),
    /aborted/i,
  );
});
