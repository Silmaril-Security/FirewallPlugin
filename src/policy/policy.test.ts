import assert from "node:assert/strict";
import test from "node:test";

import { SessionLock } from "./session-lock";
import { PolicyCache } from "./policy-cache";
import { createHardcodedPolicyClient, type PolicyClient } from "./policy-client";
import {
  decide,
  translateForToolCall,
  translateForToolResult,
  translateForPromptBuild,
} from "./policy-engine";
import type { ClassifyResult, PolicyAction, PolicyResponse } from "./types";

// ---------------- SessionLock ----------------

test("SessionLock: not locked by default", () => {
  const lock = new SessionLock();
  assert.equal(lock.isLocked("s1"), false);
});

test("SessionLock: lock then isLocked is true; idempotent", () => {
  const lock = new SessionLock();
  lock.lock("s1");
  lock.lock("s1");
  assert.equal(lock.isLocked("s1"), true);
});

test("SessionLock: lock is per-session", () => {
  const lock = new SessionLock();
  lock.lock("s1");
  assert.equal(lock.isLocked("s2"), false);
});

test("SessionLock: lock no-ops for empty/undefined session id", () => {
  const lock = new SessionLock();
  lock.lock(undefined);
  lock.lock("");
  assert.equal(lock.isLocked(undefined), false);
  assert.equal(lock.isLocked(""), false);
});

// ---------------- decide() — 24-case table ----------------

interface DecideCase {
  locked: boolean;
  prediction: "MALICIOUS" | "BENIGN" | "UNKNOWN";
  policy: PolicyAction;
  approval: boolean;
  expected: "noop" | "warn" | "block";
  expectsLockSideEffect: boolean;
}

const DECIDE_CASES: DecideCase[] = [
  // unlocked + approval prompt — approval branches first, policy decides honor vs refuse
  { locked: false, prediction: "BENIGN",   policy: "warn",  approval: true,  expected: "noop",  expectsLockSideEffect: false },
  { locked: false, prediction: "BENIGN",   policy: "block", approval: true,  expected: "block", expectsLockSideEffect: true  },
  { locked: false, prediction: "UNKNOWN",  policy: "warn",  approval: true,  expected: "noop",  expectsLockSideEffect: false },
  { locked: false, prediction: "UNKNOWN",  policy: "block", approval: true,  expected: "block", expectsLockSideEffect: true  },
  { locked: false, prediction: "MALICIOUS",policy: "warn",  approval: true,  expected: "noop",  expectsLockSideEffect: false },
  { locked: false, prediction: "MALICIOUS",policy: "block", approval: true,  expected: "block", expectsLockSideEffect: true  },
  // unlocked, non-approval, BENIGN — always noop
  { locked: false, prediction: "BENIGN",   policy: "warn",  approval: false, expected: "noop",  expectsLockSideEffect: false },
  { locked: false, prediction: "BENIGN",   policy: "block", approval: false, expected: "noop",  expectsLockSideEffect: false },
  // unlocked, non-approval, UNKNOWN — fail-open at classifier layer
  { locked: false, prediction: "UNKNOWN",  policy: "warn",  approval: false, expected: "noop",  expectsLockSideEffect: false },
  { locked: false, prediction: "UNKNOWN",  policy: "block", approval: false, expected: "noop",  expectsLockSideEffect: false },
  // unlocked, non-approval, MALICIOUS — policy applies
  { locked: false, prediction: "MALICIOUS",policy: "warn",  approval: false, expected: "warn",  expectsLockSideEffect: false },
  { locked: false, prediction: "MALICIOUS",policy: "block", approval: false, expected: "block", expectsLockSideEffect: true  },
  // locked — short-circuit to block regardless of anything else
  { locked: true,  prediction: "BENIGN",   policy: "warn",  approval: false, expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "BENIGN",   policy: "warn",  approval: true,  expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "BENIGN",   policy: "block", approval: false, expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "BENIGN",   policy: "block", approval: true,  expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "UNKNOWN",  policy: "warn",  approval: false, expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "UNKNOWN",  policy: "warn",  approval: true,  expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "UNKNOWN",  policy: "block", approval: false, expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "UNKNOWN",  policy: "block", approval: true,  expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "MALICIOUS",policy: "warn",  approval: false, expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "MALICIOUS",policy: "warn",  approval: true,  expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "MALICIOUS",policy: "block", approval: false, expected: "block", expectsLockSideEffect: false },
  { locked: true,  prediction: "MALICIOUS",policy: "block", approval: true,  expected: "block", expectsLockSideEffect: false },
];

for (const [i, c] of DECIDE_CASES.entries()) {
  const label = `decide #${i + 1}: locked=${c.locked} pred=${c.prediction} policy=${c.policy} approval=${c.approval} -> ${c.expected}`;
  test(label, () => {
    const lock = new SessionLock();
    if (c.locked) lock.lock("session-x");
    const wasLockedBefore = lock.isLocked("session-x");
    const decision = decide(
      {
        policyAction: c.policy,
        classifyResult: { prediction: c.prediction, score: 0.99 } satisfies ClassifyResult,
        sessionId: "session-x",
        isApprovalPrompt: c.approval,
      },
      lock,
    );
    assert.equal(decision.kind, c.expected);
    if (c.expectsLockSideEffect && !wasLockedBefore) {
      assert.equal(lock.isLocked("session-x"), true, "lock should have been set as a side effect");
    }
  });
}

test("decide: locking a malicious tool_call under block policy locks the session for subsequent calls", () => {
  const lock = new SessionLock();
  const first = decide(
    {
      policyAction: "block",
      classifyResult: { prediction: "MALICIOUS", score: 0.9 },
      sessionId: "s",
      isApprovalPrompt: false,
    },
    lock,
  );
  assert.equal(first.kind, "block");
  // Second call with BENIGN content in the now-locked session must still block
  const second = decide(
    {
      policyAction: "warn",
      classifyResult: { prediction: "BENIGN", score: 0.0 },
      sessionId: "s",
      isApprovalPrompt: false,
    },
    lock,
  );
  assert.equal(second.kind, "block");
});

// ---------------- translateForX ----------------

test("translateForToolCall: noop returns undefined", () => {
  const out = translateForToolCall({ kind: "noop" }, {
    warnDescription: "w",
    blockReason: "b",
    pluginId: "firewall-plugin",
  });
  assert.equal(out, undefined);
});

test("translateForToolCall: warn returns native requireApproval modal shape", () => {
  const out = translateForToolCall({ kind: "warn" }, {
    warnDescription: "warn-desc",
    blockReason: "br",
    pluginId: "firewall-plugin",
    toolName: "web_fetch",
  });
  assert.ok(out && "requireApproval" in out, "warn must return requireApproval");
  assert.equal(out.requireApproval.severity, "warning");
  assert.equal(out.requireApproval.timeoutBehavior, "deny");
  assert.equal(out.requireApproval.timeoutMs, 60_000);
  assert.equal(out.requireApproval.pluginId, "firewall-plugin");
  assert.equal(out.requireApproval.description, "warn-desc");
  assert.match(out.requireApproval.title, /web_fetch/);
});

test("translateForToolCall: block returns block:true with blockReason", () => {
  const out = translateForToolCall({ kind: "block" }, {
    warnDescription: "w",
    blockReason: "block-reason-text",
    pluginId: "firewall-plugin",
  });
  assert.deepEqual(out, { block: true, blockReason: "block-reason-text" });
});

test("translateForToolResult: warn vs block routes to the right message", () => {
  const warnMsg = { content: [{ type: "text", text: "warn" }] };
  const blockMsg = { content: [{ type: "text", text: "block" }] };
  assert.deepEqual(translateForToolResult({ kind: "noop" }, { warnMessage: warnMsg, blockMessage: blockMsg }), undefined);
  assert.deepEqual(translateForToolResult({ kind: "warn" }, { warnMessage: warnMsg, blockMessage: blockMsg }), { message: warnMsg });
  assert.deepEqual(translateForToolResult({ kind: "block" }, { warnMessage: warnMsg, blockMessage: blockMsg }), { message: blockMsg });
});

test("translateForPromptBuild: warn vs block routes to the right guard", () => {
  const warn = { appendSystemContext: "wa", prependContext: "wp" };
  const block = { appendSystemContext: "ba", prependContext: "bp" };
  assert.deepEqual(translateForPromptBuild({ kind: "noop" }, { warnGuard: warn, blockGuard: block }), undefined);
  assert.deepEqual(translateForPromptBuild({ kind: "warn" }, { warnGuard: warn, blockGuard: block }), warn);
  assert.deepEqual(translateForPromptBuild({ kind: "block" }, { warnGuard: warn, blockGuard: block }), block);
});

// ---------------- PolicyCache ----------------

class MockClient implements PolicyClient {
  calls = 0;
  failNext = 0;
  constructor(private response: PolicyResponse) {}
  async fetchPolicy(_email: string | null): Promise<PolicyResponse> {
    this.calls++;
    if (this.failNext > 0) {
      this.failNext--;
      throw new Error("simulated fetch failure");
    }
    return this.response;
  }
}

test("PolicyCache: returns cached value within TTL", async () => {
  const client = new MockClient({ action: "warn", resolved_role: "admin" });
  const cache = new PolicyCache(client, 60_000);
  const a = await cache.get("gary@silmaril.dev");
  const b = await cache.get("gary@silmaril.dev");
  assert.deepEqual(a, b);
  assert.equal(client.calls, 1, "should not refetch within TTL");
});

test("PolicyCache: refetches after TTL expiry", async () => {
  const client = new MockClient({ action: "block", resolved_role: "user" });
  const cache = new PolicyCache(client, 1);
  await cache.get("x@y");
  await new Promise((r) => setTimeout(r, 5));
  await cache.get("x@y");
  assert.equal(client.calls, 2);
});

test("PolicyCache: serves cached value on fetch error", async () => {
  const client = new MockClient({ action: "warn", resolved_role: "admin" });
  const cache = new PolicyCache(client, 1);
  const first = await cache.get("a@b");
  await new Promise((r) => setTimeout(r, 5));
  client.failNext = 1;
  const second = await cache.get("a@b");
  assert.deepEqual(second, first, "should return cached on fetch failure");
});

test("PolicyCache: synthesizes warn fallback when no cache and fetch fails", async () => {
  const client = new MockClient({ action: "block", resolved_role: "user" });
  client.failNext = 1;
  const logs: string[] = [];
  const cache = new PolicyCache(client, 60_000, { warn: (m) => logs.push(m) });
  const out = await cache.get("nobody@nowhere");
  assert.equal(out.action, "warn");
  assert.equal(out.resolved_role, "fallback");
  assert.equal(logs.length, 1);
  assert.match(logs[0], /falling back to warn/);
});

test("PolicyCache: invalidate forces refetch", async () => {
  const client = new MockClient({ action: "warn", resolved_role: "admin" });
  const cache = new PolicyCache(client, 60_000);
  await cache.get("a@b");
  cache.invalidate("a@b");
  await cache.get("a@b");
  assert.equal(client.calls, 2);
});

test("PolicyCache: peek returns undefined before any get", () => {
  const client = new MockClient({ action: "warn", resolved_role: "admin" });
  const cache = new PolicyCache(client, 60_000);
  assert.equal(cache.peek("a@b"), undefined);
});

test("PolicyCache: peek returns cached value after get", async () => {
  const client = new MockClient({ action: "warn", resolved_role: "admin" });
  const cache = new PolicyCache(client, 60_000);
  await cache.get("a@b");
  assert.deepEqual(cache.peek("a@b"), { action: "warn", resolved_role: "admin" });
});

test("PolicyCache: case-insensitive email key", async () => {
  const client = new MockClient({ action: "warn", resolved_role: "admin" });
  const cache = new PolicyCache(client, 60_000);
  await cache.get("Gary@Silmaril.DEV");
  await cache.get("gary@silmaril.dev");
  assert.equal(client.calls, 1);
});

test("PolicyCache: de-duplicates concurrent fetches for same key", async () => {
  let resolveFn!: () => void;
  const gate = new Promise<void>((resolve) => { resolveFn = resolve; });
  const slowClient: PolicyClient = {
    async fetchPolicy() {
      await gate;
      return { action: "warn", resolved_role: "admin" };
    },
  };
  let calls = 0;
  const counted: PolicyClient = {
    async fetchPolicy(email) {
      calls++;
      return slowClient.fetchPolicy(email);
    },
  };
  const cache = new PolicyCache(counted, 60_000);
  const p1 = cache.get("a@b");
  const p2 = cache.get("a@b");
  resolveFn();
  await Promise.all([p1, p2]);
  assert.equal(calls, 1, "second concurrent get should reuse the inflight promise");
});

// ---------------- Hardcoded PolicyClient ----------------

test("hardcoded client: gary@silmaril.dev maps to admin/warn", async () => {
  const client = createHardcodedPolicyClient();
  const out = await client.fetchPolicy("gary@silmaril.dev");
  assert.deepEqual(out, { action: "warn", resolved_role: "admin" });
});

test("hardcoded client: case-insensitive admin match", async () => {
  const client = createHardcodedPolicyClient();
  const out = await client.fetchPolicy("Gary@Silmaril.Dev");
  assert.equal(out.action, "warn");
  assert.equal(out.resolved_role, "admin");
});

test("hardcoded client: any other email maps to user/block", async () => {
  const client = createHardcodedPolicyClient();
  const out = await client.fetchPolicy("not-gary@example.com");
  assert.deepEqual(out, { action: "block", resolved_role: "user" });
});

test("hardcoded client: null email maps to user/block (fail-closed default)", async () => {
  const client = createHardcodedPolicyClient();
  const out = await client.fetchPolicy(null);
  assert.deepEqual(out, { action: "block", resolved_role: "user" });
});

// Identity resolution is provided by dev's `src/user-email.ts` (resolveUserEmail).
// Tests for that module live in `src/user-email.test.ts`.
