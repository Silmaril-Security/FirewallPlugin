import assert from "node:assert/strict";
import test from "node:test";
import { createBypassRegistry } from "./registry";
import type { BypassPattern } from "./types";

test("createBypassRegistry detects registered patterns and returns retry hint", () => {
  const pattern: BypassPattern = {
    toolName: "example_tool",
    label: "example",
    detect(command) {
      return command.includes("blocked") ? { matched: true, details: { command } } : { matched: false };
    },
    buildRetryHint(details) {
      return `retry ${details.command}`;
    },
  };
  const registry = createBypassRegistry([pattern]);

  assert.deepEqual(registry.detect("exec", { command: "blocked command" }), {
    toolName: "example_tool",
    label: "example",
    details: { command: "blocked command" },
    blockReason: "retry blocked command",
  });
});

test("createBypassRegistry returns undefined for no match or non-shell tools", () => {
  const registry = createBypassRegistry([
    {
      toolName: "example_tool",
      label: "example",
      detect: () => ({ matched: false }),
      buildRetryHint: () => "retry",
    },
  ]);

  assert.equal(registry.detect("exec", { command: "allowed" }), undefined);
  assert.equal(registry.detect("web_fetch", { command: "blocked" }), undefined);
});

test("createBypassRegistry uses registration order and first match wins", () => {
  const registry = createBypassRegistry();
  registry.register({
    toolName: "first",
    label: "first",
    detect: () => ({ matched: true, details: { value: 1 } }),
    buildRetryHint: () => "first",
  });
  registry.register({
    toolName: "second",
    label: "second",
    detect: () => ({ matched: true, details: { value: 2 } }),
    buildRetryHint: () => "second",
  });

  assert.equal(registry.detect("bash", { command: "anything" })?.blockReason, "first");
});

test("createBypassRegistry checks tool availability at detection time", () => {
  const available = new Set<string>();
  const registry = createBypassRegistry(
    [
      {
        toolName: "late_tool",
        label: "late",
        detect: () => ({ matched: true, details: { value: 1 } }),
        buildRetryHint: () => "retry late_tool",
      },
    ],
    {
      isToolAvailable: (toolName) => available.has(toolName),
    },
  );

  assert.equal(registry.detect("exec", { command: "blocked" }), undefined);

  available.add("late_tool");

  assert.equal(registry.detect("exec", { command: "blocked" })?.blockReason, "retry late_tool");
});
