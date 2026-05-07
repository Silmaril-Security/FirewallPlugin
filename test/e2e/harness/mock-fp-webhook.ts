import http from "node:http";
import path from "node:path";
import {
  appendNdjson,
  delay,
  ensureDir,
  isRecord,
  listen,
  readRequestJson,
  writeJson,
  type ServerHandle,
} from "./common";

export type FpWebhookFailure =
  | "fpWebhook400"
  | "fpWebhook500"
  | "fpWebhookTimeout"
  | "fpWebhookSlow";

export type MockFpWebhook = ServerHandle & {
  webhookUrl: string;
  captureFile: string;
  failNext(failure: FpWebhookFailure): Promise<void>;
  reset(): Promise<void>;
};

export async function startMockFpWebhook(options: { rootDir: string }): Promise<MockFpWebhook> {
  const captureFile = path.join(options.rootDir, "fp-webhook-captures.ndjson");
  await ensureDir(options.rootDir);
  const failures: FpWebhookFailure[] = [];

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/health") {
      writeJson(res, 200, { ok: true });
      return;
    }
    if (url.pathname.startsWith("/control/")) {
      const body = await readRequestJson(req).catch(() => ({}));
      if (url.pathname === "/control/fail-next" && isRecord(body) && typeof body.failure === "string") {
        failures.push(body.failure as FpWebhookFailure);
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
    if (req.method !== "POST" || url.pathname !== "/webhook") {
      writeJson(res, 404, { error: "not_found" });
      return;
    }

    const payload = await readRequestJson(req).catch((err) => ({
      parseError: err instanceof Error ? err.message : String(err),
    }));
    const failure = failures.shift();
    await appendNdjson(captureFile, {
      ts: new Date().toISOString(),
      payload,
      failure,
    });

    if (failure === "fpWebhookTimeout") {
      await delay(60_000);
      return;
    }
    if (failure === "fpWebhookSlow") {
      await delay(30_000);
    }
    if (failure === "fpWebhook400") {
      writeJson(res, 400, { message: "Bad Request" });
      return;
    }
    if (failure === "fpWebhook500") {
      writeJson(res, 500, { message: "Internal server error" });
      return;
    }
    writeJson(res, 202, { ok: true, status: "queued" });
  });

  const handle = await listen(server);
  return {
    ...handle,
    webhookUrl: `${handle.origin}/webhook`,
    captureFile,
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
