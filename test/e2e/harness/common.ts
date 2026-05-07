import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

export type JsonRecord = Record<string, unknown>;

export type ServerHandle = {
  server: http.Server;
  host: string;
  port: number;
  origin: string;
  close(): Promise<void>;
};

export async function getFreePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    await closeServer(server);
    throw new Error("failed to allocate an ephemeral port");
  }
  await closeServer(server);
  return address.port;
}

export async function listen(server: http.Server, port = 0): Promise<ServerHandle> {
  const host = "127.0.0.1";
  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    await closeServer(server);
    throw new Error("server did not bind to a TCP port");
  }
  return {
    server,
    host,
    port: address.port,
    origin: `http://${host}:${address.port}`,
    close: () => closeServer(server),
  };
}

export async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  }).catch((err: unknown) => {
    if (err instanceof Error && /not running/i.test(err.message)) return;
    throw err;
  });
}

export async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

export async function readRequestBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks);
}

export async function readRequestText(req: http.IncomingMessage): Promise<string> {
  return (await readRequestBody(req)).toString("utf8");
}

export async function readRequestJson<T = unknown>(req: http.IncomingMessage): Promise<T> {
  const text = await readRequestText(req);
  return JSON.parse(text) as T;
}

export function writeJson(
  res: http.ServerResponse,
  statusCode: number,
  value: unknown,
  headers: Record<string, string> = {},
): void {
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    ...headers,
  });
  res.end(JSON.stringify(value));
}

export function writeText(
  res: http.ServerResponse,
  statusCode: number,
  value: string | Buffer,
  headers: Record<string, string> = {},
): void {
  res.writeHead(statusCode, headers);
  res.end(value);
}

export async function appendNdjson(file: string, value: unknown): Promise<void> {
  await ensureDir(path.dirname(file));
  await fs.appendFile(file, `${JSON.stringify(value)}\n`, "utf8");
}

export async function readNdjson(file: string): Promise<unknown[]> {
  try {
    const text = await fs.readFile(file, "utf8");
    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line) as unknown);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

export async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  options: { timeoutMs?: number; intervalMs?: number; message?: string } = {},
): Promise<void> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const intervalMs = options.intervalMs ?? 50;
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await predicate()) return;
    await delay(intervalMs);
  }
  throw new Error(options.message ?? `timed out after ${timeoutMs}ms`);
}

export async function waitForNdjsonLines(
  file: string,
  minLines: number,
  options: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<unknown[]> {
  let rows: unknown[] = [];
  await waitFor(
    async () => {
      rows = await readNdjson(file);
      return rows.length >= minLines;
    },
    {
      timeoutMs: options.timeoutMs,
      intervalMs: options.intervalMs,
      message: `timed out waiting for ${minLines} lines in ${file}`,
    },
  );
  return rows;
}

export function redactHeaders(headers: http.IncomingHttpHeaders): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = /authorization|api-key|token|cookie/i.test(key) ? "[redacted]" : value;
  }
  return out;
}

export function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export async function postJson<T = unknown>(url: string, body: unknown): Promise<{
  status: number;
  body: T;
  headers: Headers;
}> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  const parsed = text ? (JSON.parse(text) as T) : (undefined as T);
  return { status: response.status, body: parsed, headers: response.headers };
}

export function repoRootFrom(importMetaUrl: string, levels = 3): string {
  let dir = path.dirname(new URL(importMetaUrl).pathname);
  if (process.platform === "win32" && /^\/[A-Za-z]:\//.test(dir)) {
    dir = dir.slice(1);
  }
  for (let i = 0; i < levels; i += 1) {
    dir = path.dirname(dir);
  }
  return dir;
}

export { delay };
