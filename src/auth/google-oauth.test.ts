import assert from "node:assert/strict";
import test from "node:test";
import { refreshGoogleAccessToken } from "./google-oauth";

test("refreshGoogleAccessToken returns parsed token with skewed expiry", async () => {
  const token = await refreshGoogleAccessToken(
    { clientId: "client", clientSecret: "secret", refreshToken: "refresh" },
    {
      now: () => 1_000,
      fetchImpl: (async (_url, init) => {
        assert.equal(init?.method, "POST");
        assert.match(String(init?.body), /grant_type=refresh_token/);
        return new Response(JSON.stringify({ access_token: "access", token_type: "Bearer", expires_in: 120 }));
      }) as typeof fetch,
    },
  );

  assert.deepEqual(token, {
    accessToken: "access",
    tokenType: "Bearer",
    expiresAt: 61_000,
  });
});

test("refreshGoogleAccessToken throws on non-2xx and does not log secrets", async () => {
  const calls: string[] = [];
  await assert.rejects(
    refreshGoogleAccessToken(
      { clientId: "client", clientSecret: "top-secret", refreshToken: "refresh-secret" },
      {
        logger: { warn: (message) => calls.push(message) },
        fetchImpl: (async () => new Response("bad", { status: 400, statusText: "Bad Request" })) as typeof fetch,
      },
    ),
  );

  assert.equal(calls.join("\n").includes("top-secret"), false);
  assert.equal(calls.join("\n").includes("refresh-secret"), false);
});
