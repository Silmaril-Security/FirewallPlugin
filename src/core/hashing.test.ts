import assert from "node:assert/strict";
import test from "node:test";

import { sha256, shortHash16 } from "./hashing";

test("sha256 produces stable lowercase 64-character hex", () => {
  const hash = sha256("same input");

  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(hash, sha256("same input"));
  assert.notEqual(hash, sha256("different input"));
});

test("shortHash16 returns the first 16 characters", () => {
  assert.equal(shortHash16("1234567890abcdefEXTRA"), "1234567890abcdef");
});
