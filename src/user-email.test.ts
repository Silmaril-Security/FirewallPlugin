import assert from "node:assert/strict";
import test from "node:test";

import { resolveUserEmail, withUserEmailClassifyOptions } from "./user-email";

test("resolveUserEmail prefers plugin config over USER_EMAIL", () => {
  assert.equal(resolveUserEmail("  config@example.com  ", { USER_EMAIL: "env@example.com" }), "config@example.com");
});

test("resolveUserEmail falls back to USER_EMAIL", () => {
  assert.equal(resolveUserEmail(undefined, { USER_EMAIL: " env@example.com " }), "env@example.com");
});

test("withUserEmailClassifyOptions adds user email metadata without losing existing fields", () => {
  assert.deepEqual(
    withUserEmailClassifyOptions(
      {
        hook: "tool_response",
        toolName: "web_fetch",
        metadata: {
          run_id: "run-1",
        },
      },
      "owner@example.com",
    ),
    {
      hook: "tool_response",
      toolName: "web_fetch",
      metadata: {
        run_id: "run-1",
        user_email: "owner@example.com",
      },
    },
  );
});

// ---- identity-resolution edge cases (e2e-routed unit coverage) ----

test("resolveUserEmail: empty string in config falls through to env", () => {
  assert.equal(resolveUserEmail("", { USER_EMAIL: "env@example.com" }), "env@example.com");
});

test("resolveUserEmail: whitespace-only config trims to undefined and falls to env", () => {
  assert.equal(resolveUserEmail("   ", { USER_EMAIL: "env@example.com" }), "env@example.com");
});

test("resolveUserEmail: number config returns undefined (typeguard)", () => {
  assert.equal(resolveUserEmail(42, { USER_EMAIL: "env@example.com" }), "env@example.com");
});

test("resolveUserEmail: object config returns undefined (typeguard)", () => {
  assert.equal(resolveUserEmail({ value: "x" }, { USER_EMAIL: "env@example.com" }), "env@example.com");
});

test("resolveUserEmail: array config returns undefined (typeguard)", () => {
  assert.equal(resolveUserEmail(["x"], { USER_EMAIL: "env@example.com" }), "env@example.com");
});

test("resolveUserEmail: very-long string returned verbatim (no DoS, no truncation)", () => {
  const long = "a".repeat(10000) + "@silmaril.dev";
  assert.equal(resolveUserEmail(long, {}), long);
});

test("resolveUserEmail: leading/trailing whitespace trimmed", () => {
  assert.equal(resolveUserEmail("  gary@silmaril.dev  "), "gary@silmaril.dev");
});

test("resolveUserEmail: internal whitespace preserved (no normalization)", () => {
  // Note: trimmed() trims only outer whitespace; internal newline / tab preserved.
  assert.equal(resolveUserEmail("gary@silmaril.dev\nx"), "gary@silmaril.dev\nx");
});

test("resolveUserEmail: when both config and env are empty, returns undefined", () => {
  assert.equal(resolveUserEmail("", { USER_EMAIL: "" }), undefined);
});

test("withUserEmailClassifyOptions: no email leaves options untouched", () => {
  const opts = { hook: "prompt" as const, metadata: { run_id: "r1" } };
  const out = withUserEmailClassifyOptions(opts, undefined);
  assert.deepEqual(out, opts);
});

test("withUserEmailClassifyOptions: undefined existing metadata creates the metadata object", () => {
  const opts = { hook: "prompt" as const };
  const out = withUserEmailClassifyOptions(opts, "owner@example.com");
  assert.deepEqual(out.metadata, { user_email: "owner@example.com" });
});

test("withUserEmailClassifyOptions: array metadata is rejected (typeguard) and replaced", () => {
  const opts = { hook: "prompt" as const, metadata: ["bad"] as unknown as Record<string, unknown> };
  const out = withUserEmailClassifyOptions(opts, "owner@example.com");
  assert.deepEqual(out.metadata, { user_email: "owner@example.com" });
});
