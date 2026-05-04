import assert from "node:assert/strict";
import test from "node:test";
import { extractCommandStringFromExecParams } from "./shell-parse";

test("extractCommandStringFromExecParams reads command, cmd, and script", () => {
  assert.equal(extractCommandStringFromExecParams("exec", { command: "echo hi" }), "echo hi");
  assert.equal(extractCommandStringFromExecParams("bash", { cmd: "echo hi" }), "echo hi");
  assert.equal(extractCommandStringFromExecParams("shell", { script: "echo hi" }), "echo hi");
});

test("extractCommandStringFromExecParams ignores non-shell tools and bad params", () => {
  assert.equal(extractCommandStringFromExecParams("web_fetch", { command: "echo hi" }), undefined);
  assert.equal(extractCommandStringFromExecParams("exec", null), undefined);
  assert.equal(extractCommandStringFromExecParams("exec", []), undefined);
  assert.equal(extractCommandStringFromExecParams("exec", { command: 123 }), undefined);
});
