import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, expect } from "vitest";

let productionOpenClawMtime: number | undefined;

beforeAll(async () => {
  productionOpenClawMtime = await maxMtime(path.join(os.homedir(), ".openclaw"));
});

afterAll(async () => {
  if (process.env.FIREWALL_E2E_ASSERT_PROD_UNTOUCHED === "0") return;
  const after = await maxMtime(path.join(os.homedir(), ".openclaw"));
  expect(after).toBe(productionOpenClawMtime);
});

async function maxMtime(target: string): Promise<number | undefined> {
  const stat = await fs.stat(target).catch(() => undefined);
  if (!stat) return undefined;
  if (stat.isFile()) return stat.mtimeMs;
  let max = stat.mtimeMs;
  const entries = await fs.readdir(target, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const child = await maxMtime(path.join(target, entry.name));
    if (child !== undefined) {
      max = Math.max(max, child);
    }
  }
  return max;
}
