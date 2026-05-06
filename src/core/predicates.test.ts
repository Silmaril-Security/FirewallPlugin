import assert from "node:assert/strict";
import test from "node:test";

import { isMaliciousPrediction, isRecord } from "./predicates";

test("isRecord accepts plain records only", () => {
  assert.equal(isRecord({}), true);
  assert.equal(isRecord(Object.create(null)), true);
  assert.equal(isRecord(null), false);
  assert.equal(isRecord(undefined), false);
  assert.equal(isRecord([]), false);
  assert.equal(isRecord("value"), false);
  assert.equal(isRecord(1), false);
  assert.equal(isRecord(new Map()), false);
  assert.equal(isRecord(new Date()), false);
});

test("isMaliciousPrediction matches only malicious strings case-insensitively", () => {
  assert.equal(isMaliciousPrediction("MALICIOUS"), true);
  assert.equal(isMaliciousPrediction("malicious"), true);
  assert.equal(isMaliciousPrediction("Malicious"), true);
  assert.equal(isMaliciousPrediction("BENIGN"), false);
  assert.equal(isMaliciousPrediction(""), false);
  assert.equal(isMaliciousPrediction(null), false);
  assert.equal(isMaliciousPrediction(undefined), false);
  assert.equal(isMaliciousPrediction(1), false);
});
