import { afterEach, test } from "node:test";
import assert from "node:assert/strict";
import {
  EXPORT_BUCKET,
  EXPORT_LOGS_PREFIX,
  type ExporterRuntime,
} from "./types";
import { requestUploadLease, resolveUploadLeaseUrl } from "./uploader";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("requestUploadLease uses API Gateway x-api-key and host-only request body", async () => {
  const calls: Array<{
    url: string;
    init: RequestInit;
  }> = [];

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(
      JSON.stringify({
        type: "s3-post",
        bucket: EXPORT_BUCKET,
        url: "https://s3.example.test/",
        fields: {
          "Content-Type": "application/gzip",
        },
        keyPrefix: `${EXPORT_LOGS_PREFIX}1of9epawm2/`,
        contentType: "application/gzip",
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      }),
      {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      },
    );
  }) as typeof fetch;

  await requestUploadLease({
    apiKey: "export-api-key",
    apiKeyPathId: "1of9epawm2",
    userEmail: "user@example.com",
    host: "workstation",
    paths: {} as ExporterRuntime["paths"],
    logger: {
      info() {},
      warn() {},
      error() {},
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, resolveUploadLeaseUrl());
  assert.equal(calls[0].init.method, "POST");
  assert.deepEqual(calls[0].init.headers, {
    "Content-Type": "application/json",
    "x-api-key": "export-api-key",
  });
  assert.equal(calls[0].init.body, JSON.stringify({ host: "workstation" }));
});
