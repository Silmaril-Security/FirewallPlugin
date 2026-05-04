import fs from "node:fs";
import path from "node:path";
import { MockAgent, fetch as undiciFetch, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { EXPORT_BUCKET, EXPORT_LOGS_PREFIX } from "../../../src/exporter/types";

export type ApiInterceptor = {
  mockAgent: MockAgent;
  restore(): Promise<void>;
};

export type ApiInterceptorOptions = {
  fakeS3Url: string;
  fpReviewLog: string;
  uploadLeaseLog: string;
  allowNetConnect?: RegExp | string | ((host: string) => boolean);
};

export function installApiInterceptor(options: ApiInterceptorOptions): ApiInterceptor {
  const previous = getGlobalDispatcher();
  const previousFetch = globalThis.fetch;
  const mockAgent = new MockAgent({ connections: 1 });
  mockAgent.disableNetConnect();
  mockAgent.enableNetConnect(
    options.allowNetConnect ??
      /^(127\.0\.0\.1|localhost)(:\d+)?$|^api\.openai\.com:443$|^api\.anthropic\.com:443$/,
  );

  const apigw = mockAgent.get("https://v6x0guucsb.execute-api.us-west-2.amazonaws.com");
  apigw
    .intercept({
      method: "POST",
      path: "/prod/v1/openclaw/firewall-export/upload-lease",
    })
    .reply(200, (request) => {
      appendLine(options.uploadLeaseLog, {
        ts: new Date().toISOString(),
        body: serializeBody((request as { body?: unknown }).body),
      });
      return buildUploadLease(options.fakeS3Url);
    })
    .persist();

  apigw
    .intercept({
      method: "POST",
      path: "/prod/v1/openclaw/firewall-export/false-positive",
    })
    .reply(200, (request) => {
      appendLine(options.fpReviewLog, {
        ts: new Date().toISOString(),
        body: serializeBody((request as { body?: unknown }).body),
      });
      return { status: "stored" };
    })
    .persist();

  setGlobalDispatcher(mockAgent);
  globalThis.fetch = undiciFetch as unknown as typeof globalThis.fetch;
  return {
    mockAgent,
    async restore() {
      setGlobalDispatcher(previous);
      globalThis.fetch = previousFetch;
      await mockAgent.close();
    },
  };
}

export function buildUploadLease(fakeS3Url: string): Record<string, unknown> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 60 * 1000);
  const policy = Buffer.from(
    JSON.stringify({
      expiration: expiresAt.toISOString(),
      conditions: [
        { bucket: EXPORT_BUCKET },
        ["starts-with", "$key", EXPORT_LOGS_PREFIX],
        ["content-length-range", 0, 10 * 1024 * 1024],
      ],
    }),
  ).toString("base64");

  return {
    type: "s3-post",
    bucket: EXPORT_BUCKET,
    url: fakeS3Url,
    fields: {
      Policy: policy,
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": "test/20260503/us-west-2/s3/aws4_request",
      "X-Amz-Date": "20260503T000000Z",
      "X-Amz-Signature": "test-signature",
    },
    keyPrefix: `${EXPORT_LOGS_PREFIX}e2e-run/`,
    expiresAt: expiresAt.toISOString(),
    fetchedAt: now.toISOString(),
    maxObjectBytes: 10 * 1024 * 1024,
    expiresInSeconds: 1800,
  };
}

function appendLine(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify(value)}\n`, "utf8");
}

function serializeBody(value: unknown): unknown {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  if (value && typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return value;
}
