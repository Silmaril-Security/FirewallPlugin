import assert from "node:assert/strict";
import test from "node:test";
import { createGoogleTokenCache } from "./token-cache";

test("createGoogleTokenCache caches tokens until expiry", async () => {
  let now = 0;
  let refreshes = 0;
  const cache = createGoogleTokenCache({
    now: () => now,
    async refresh() {
      refreshes += 1;
      return { accessToken: `token-${refreshes}`, tokenType: "Bearer", expiresAt: now + 1000 };
    },
  });

  assert.equal((await cache.get()).accessToken, "token-1");
  assert.equal((await cache.get()).accessToken, "token-1");
  now = 1001;
  assert.equal((await cache.get()).accessToken, "token-2");
  assert.equal(refreshes, 2);
});

test("createGoogleTokenCache deduplicates concurrent refreshes", async () => {
  let refreshes = 0;
  const cache = createGoogleTokenCache({
    async refresh() {
      refreshes += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { accessToken: "token", tokenType: "Bearer", expiresAt: Date.now() + 1000 };
    },
  });

  const results = await Promise.all([cache.get(), cache.get(), cache.get(), cache.get(), cache.get()]);
  assert.equal(new Set(results.map((result) => result.accessToken)).size, 1);
  assert.equal(refreshes, 1);
});

test("createGoogleTokenCache propagates refresh failures to all callers", async () => {
  const cache = createGoogleTokenCache({
    async refresh() {
      throw new Error("refresh failed");
    },
  });

  await assert.rejects(Promise.all([cache.get(), cache.get(), cache.get()]), /refresh failed/);
});
