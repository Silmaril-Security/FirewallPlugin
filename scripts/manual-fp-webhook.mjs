#!/usr/bin/env node
import { createServer } from "node:http";
import { appendFile, mkdir, readFile, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8787;
const DEFAULT_WEBHOOK_PATH = "/webhook";
const MAX_BODY_BYTES = 1024 * 1024;

const command = process.argv[2] ?? "serve";
const capturePath = resolve(
  process.cwd(),
  process.env.FIREWALL_FP_CAPTURE_FILE ?? ".manual/firewall-fp-reports.ndjson",
);

if (command === "captures") {
  await printCaptures();
} else if (command === "clear") {
  await clearCaptures();
} else if (command === "serve") {
  await serve();
} else {
  console.error(`Unknown command: ${command}`);
  console.error("Usage: node scripts/manual-fp-webhook.mjs [serve|captures|clear]");
  process.exitCode = 1;
}

async function serve() {
  const host = process.env.FIREWALL_FP_WEBHOOK_HOST ?? DEFAULT_HOST;
  const port = parsePort(process.env.FIREWALL_FP_WEBHOOK_PORT ?? String(DEFAULT_PORT));
  const webhookPath = normalizePath(process.env.FIREWALL_FP_WEBHOOK_PATH ?? DEFAULT_WEBHOOK_PATH);
  const endpoint = `http://${host}:${port}${webhookPath}`;

  await mkdir(dirname(capturePath), { recursive: true });

  const server = createServer(async (req, res) => {
    const receivedAt = new Date().toISOString();
    const requestUrl = req.url ?? "/";
    const pathname = parsePathname(requestUrl, host, port);

    try {
      const rawBody = await readRequestBody(req);
      const parsedBody = parseJsonBody(rawBody);
      const capture = {
        ts: receivedAt,
        method: req.method ?? "UNKNOWN",
        url: requestUrl,
        path: pathname,
        headers: redactHeaders(req.headers),
        body: parsedBody.ok ? parsedBody.value : undefined,
        rawBody: parsedBody.ok ? undefined : rawBody,
        bodyParseError: parsedBody.ok ? undefined : parsedBody.error,
      };

      await appendFile(capturePath, `${JSON.stringify(capture)}\n`, "utf8");
      printCapture(capture);

      if (pathname !== webhookPath) {
        sendJson(res, 404, { ok: false, error: `expected path ${webhookPath}` });
        return;
      }

      sendJson(res, 200, { ok: true, captured: true, capturePath });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[manual-fp-webhook] request failed: ${message}`);
      sendJson(res, 500, { ok: false, error: message });
    }
  });

  server.on("clientError", (err, socket) => {
    if (err && typeof err === "object" && "code" in err && err.code === "ECONNRESET") {
      return;
    }
    console.error(`[manual-fp-webhook] client error: ${err.message}`);
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  });

  await new Promise((resolveListen) => {
    server.listen(port, host, resolveListen);
  });

  console.log(`[manual-fp-webhook] listening on ${endpoint}`);
  console.log(`[manual-fp-webhook] writing captures to ${capturePath}`);
  console.log("[manual-fp-webhook] no requests captured yet in this process");
  console.log("[manual-fp-webhook] stop with Ctrl+C");

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      console.log(`\n[manual-fp-webhook] received ${signal}; shutting down`);
      server.close(() => process.exit(0));
    });
  }
}

async function printCaptures() {
  try {
    const text = await readFile(capturePath, "utf8");
    if (text.trim().length === 0) {
      console.log(`[manual-fp-webhook] capture file is empty: ${capturePath}`);
      return;
    }
    process.stdout.write(text);
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      console.log(`[manual-fp-webhook] no capture file found at ${capturePath}`);
      return;
    }
    throw err;
  }
}

async function clearCaptures() {
  await rm(capturePath, { force: true });
  console.log(`[manual-fp-webhook] cleared ${capturePath}`);
}

function parsePort(value) {
  const port = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid FIREWALL_FP_WEBHOOK_PORT: ${value}`);
  }
  return port;
}

function normalizePath(value) {
  const trimmed = value.trim();
  if (!trimmed) return DEFAULT_WEBHOOK_PATH;
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function parsePathname(requestUrl, host, port) {
  try {
    return new URL(requestUrl, `http://${host}:${port}`).pathname;
  } catch {
    return requestUrl.split("?")[0] || "/";
  }
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;

    req.on("data", (chunk) => {
      totalBytes += chunk.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        reject(new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("error", reject);
    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
  });
}

function parseJsonBody(rawBody) {
  if (!rawBody) return { ok: true, value: null };
  try {
    return { ok: true, value: JSON.parse(rawBody) };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function redactHeaders(headers) {
  const redacted = {};
  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (["authorization", "cookie", "set-cookie", "x-api-key"].includes(lowerName)) {
      redacted[name] = "[redacted]";
    } else {
      redacted[name] = value;
    }
  }
  return redacted;
}

function printCapture(capture) {
  console.log(`[manual-fp-webhook] ${capture.ts} ${capture.method} ${capture.url}`);
  console.log(JSON.stringify({
    headers: capture.headers,
    body: capture.body,
    rawBody: capture.rawBody,
    bodyParseError: capture.bodyParseError,
  }, null, 2));
}

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
  });
  res.end(`${JSON.stringify(body)}\n`);
}
