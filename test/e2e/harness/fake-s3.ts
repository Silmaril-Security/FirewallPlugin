import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import zlib from "node:zlib";
import {
  appendNdjson,
  ensureDir,
  listen,
  readRequestBody,
  readRequestJson,
  writeJson,
  writeText,
  type ServerHandle,
} from "./common";

export type FakeS3Failure =
  | "s3ExpiredToken"
  | "s3KeyAlreadyExists"
  | "s3SlowDown"
  | "s3RequestTimeout"
  | "s3EntityTooLarge"
  | "s3InvalidAccessKey"
  | "s3SignatureMismatch"
  | "s3WAFBlock"
  | "s3ConnectionReset";

export type FakeS3 = ServerHandle & {
  uploadUrl: string;
  requestLog: string;
  uploadDir: string;
  failNext(failure: FakeS3Failure): Promise<void>;
  reset(): Promise<void>;
};

export async function startFakeS3(options: { rootDir: string }): Promise<FakeS3> {
  const requestLog = path.join(options.rootDir, "fake-s3-requests.ndjson");
  const uploadDir = path.join(options.rootDir, "fake-s3-uploads");
  await ensureDir(uploadDir);
  const failures: FakeS3Failure[] = [];

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/health") {
      writeJson(res, 200, { ok: true });
      return;
    }
    if (url.pathname.startsWith("/control/")) {
      const body = await readRequestJson(req).catch(() => ({}));
      if (url.pathname === "/control/fail-next" && typeof (body as { failure?: unknown }).failure === "string") {
        failures.push((body as { failure: FakeS3Failure }).failure);
        writeJson(res, 200, { ok: true, queued: failures.length });
        return;
      }
      if (url.pathname === "/control/reset") {
        failures.length = 0;
        writeJson(res, 200, { ok: true });
        return;
      }
      writeJson(res, 404, { error: "unknown_control_endpoint" });
      return;
    }
    if (req.method !== "POST" || url.pathname !== "/upload") {
      writeJson(res, 404, { error: "not_found" });
      return;
    }

    const body = await readRequestBody(req);
    const key = extractMultipartField(body, "key") ?? `unknown-${Date.now()}.bin`;
    const safeKey = key.replace(/[^A-Za-z0-9._/-]/g, "_").replace(/\.\./g, "__");
    const target = path.join(uploadDir, safeKey);
    const failure = failures.shift();

    await appendNdjson(requestLog, {
      ts: new Date().toISOString(),
      method: req.method,
      key,
      contentLength: body.length,
      failure,
      jsonlLineCount: countJsonlLines(extractGzipPayload(body)),
    });

    if (failure === "s3ConnectionReset") {
      res.destroy();
      return;
    }
    if (failure === "s3WAFBlock") {
      writeText(res, 403, "<html><body>blocked by AWS WAF</body></html>", {
        "content-type": "text/html; charset=utf-8",
      });
      return;
    }
    if (failure) {
      const error = s3ErrorFor(failure);
      writeText(res, error.status, error.body, { "content-type": "application/xml" });
      return;
    }

    await ensureDir(path.dirname(target));
    await fs.writeFile(target, extractGzipPayload(body) ?? body);
    res.writeHead(204);
    res.end();
  });

  const handle = await listen(server);
  return {
    ...handle,
    uploadUrl: `${handle.origin}/upload`,
    requestLog,
    uploadDir,
    failNext: async (failure) => {
      await fetch(`${handle.origin}/control/fail-next`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ failure }),
      });
    },
    reset: async () => {
      await fetch(`${handle.origin}/control/reset`, { method: "POST", body: "{}" });
    },
  };
}

function s3ErrorFor(failure: FakeS3Failure): { status: number; body: string } {
  switch (failure) {
    case "s3ExpiredToken":
      return xml(403, "ExpiredToken", "Request has expired");
    case "s3KeyAlreadyExists":
      return xml(409, "OperationAborted", "KeyAlreadyExists");
    case "s3SlowDown":
      return xml(503, "SlowDown", "Reduce your request rate");
    case "s3RequestTimeout":
      return xml(400, "RequestTimeout", "Request timeout");
    case "s3EntityTooLarge":
      return xml(400, "EntityTooLarge", "Entity too large");
    case "s3InvalidAccessKey":
      return xml(403, "InvalidAccessKeyId", "Invalid access key");
    case "s3SignatureMismatch":
      return xml(403, "SignatureDoesNotMatch", "Signature mismatch");
    default:
      return xml(500, "InternalError", "Unhandled fake S3 failure");
  }
}

function xml(status: number, code: string, message: string): { status: number; body: string } {
  return {
    status,
    body: `<Error><Code>${code}</Code><Message>${message}</Message></Error>`,
  };
}

function extractMultipartField(body: Buffer, name: string): string | undefined {
  const text = body.toString("latin1");
  const pattern = new RegExp(`name="${escapeRegExp(name)}"\\r?\\n\\r?\\n([^\\r\\n]+)`, "m");
  return pattern.exec(text)?.[1];
}

function extractGzipPayload(body: Buffer): Buffer | undefined {
  for (let i = 0; i < body.length - 2; i += 1) {
    if (body[i] === 0x1f && body[i + 1] === 0x8b) {
      try {
        return zlib.gunzipSync(body.subarray(i));
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

function countJsonlLines(value: Buffer | undefined): number | undefined {
  if (!value) return undefined;
  return value
    .toString("utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim()).length;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
