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
