import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const requireFromHere = createRequire(import.meta.url);
const requireFromCwd = createRequire(path.join(process.cwd(), "package.json"));

function requireUndici() {
  try {
    return requireFromHere("undici");
  } catch {
    return requireFromCwd("undici");
  }
}

const { MockAgent, fetch, setGlobalDispatcher } = requireUndici();

const fakeS3Url = process.env.FIREWALL_E2E_FAKE_S3_URL;
const fpReviewLog = process.env.FIREWALL_E2E_FP_REVIEW_UPLOADS;
const uploadLeaseLog = process.env.FIREWALL_E2E_UPLOAD_LEASE_LOG;

if (fakeS3Url && fpReviewLog && uploadLeaseLog) {
  const EXPORT_BUCKET = "silmaril-openclaw-firewall-exports-prod";
  const EXPORT_LOGS_PREFIX = "openclaw-firewall/v1/logs/";
  const mock = new MockAgent({ connections: 1 });
  mock.disableNetConnect();
  mock.enableNetConnect(/^(127\.0\.0\.1|localhost)(:\d+)?$|^api\.openai\.com:443$|^api\.anthropic\.com:443$/);

  const apigw = mock.get("https://v6x0guucsb.execute-api.us-west-2.amazonaws.com");
  apigw
    .intercept({ method: "POST", path: "/prod/v1/openclaw/firewall-export/upload-lease" })
    .reply(200, (request) => {
      appendLine(uploadLeaseLog, {
        ts: new Date().toISOString(),
        body: serializeBody(request.body),
      });
      return buildUploadLease(fakeS3Url, EXPORT_BUCKET, EXPORT_LOGS_PREFIX);
    })
    .persist();

  apigw
    .intercept({ method: "POST", path: "/prod/v1/openclaw/firewall-export/false-positive" })
    .reply(200, (request) => {
      appendLine(fpReviewLog, {
        ts: new Date().toISOString(),
        body: serializeBody(request.body),
      });
      return { status: "stored" };
    })
    .persist();

  setGlobalDispatcher(mock);
  globalThis.fetch = fetch;
}

function buildUploadLease(fakeS3Url, bucket, prefix) {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 60 * 1000);
  const policy = Buffer.from(
    JSON.stringify({
      expiration: expiresAt.toISOString(),
      conditions: [
        { bucket },
        ["starts-with", "$key", prefix],
        ["content-length-range", 0, 10 * 1024 * 1024],
      ],
    }),
  ).toString("base64");

  return {
    type: "s3-post",
    bucket,
    url: fakeS3Url,
    fields: {
      Policy: policy,
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": "test/20260503/us-west-2/s3/aws4_request",
      "X-Amz-Date": "20260503T000000Z",
      "X-Amz-Signature": "test-signature",
    },
    keyPrefix: `${prefix}e2e-run/`,
    expiresAt: expiresAt.toISOString(),
    fetchedAt: now.toISOString(),
    maxObjectBytes: 10485760,
    expiresInSeconds: 1800,
  };
}

function appendLine(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify(value)}\n`, "utf8");
}

function serializeBody(value) {
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
