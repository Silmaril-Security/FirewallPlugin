import http from "node:http";
import path from "node:path";
import {
  appendNdjson,
  delay,
  ensureDir,
  isRecord,
  listen,
  readRequestText,
  writeJson,
  type JsonRecord,
  type ServerHandle,
} from "./common";

export type TelegramFailure =
  | "tgFlood"
  | "tgParseError"
  | "tgChatNotFound"
  | "tgBlockedByUser"
  | "tgUnauthorized"
  | "tgMessageNotModified"
  | "tgMessageTooLong"
  | "tg500"
  | "tgTimeout";

export type MockTelegram = ServerHandle & {
  apiRoot: string;
  token: string;
  captureFile: string;
  injectUpdate(message: JsonRecord): Promise<void>;
  failNext(method: string, failure: TelegramFailure): Promise<void>;
  reset(): Promise<void>;
};

export async function startMockTelegram(options: {
  rootDir: string;
  token?: string;
}): Promise<MockTelegram> {
  const token = options.token ?? "123456:test-token";
  const captureFile = path.join(options.rootDir, "telegram-out.ndjson");
  await ensureDir(options.rootDir);
  const updates: JsonRecord[] = [];
  const failures: Array<{ method: string; failure: TelegramFailure }> = [];
  let nextMessageId = 1;
  let nextUpdateId = 1000;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname === "/health") {
      writeJson(res, 200, { ok: true });
      return;
    }
    if (url.pathname.startsWith("/control/")) {
      const body = parseJson(await readRequestText(req));
      if (url.pathname === "/control/inject-update" && isRecord(body) && isRecord(body.message)) {
        updates.push({
          update_id: nextUpdateId,
          message: {
            message_id: nextMessageId,
            date: Math.floor(Date.now() / 1000),
            chat: { id: 4242, type: "private", first_name: "Power", username: "poweruser" },
            from: { id: 4242, is_bot: false, first_name: "Power", username: "poweruser" },
            ...body.message,
          },
        });
        nextUpdateId += 1;
        nextMessageId += 1;
        writeJson(res, 200, { ok: true, queued: updates.length });
        return;
      }
      if (url.pathname === "/control/fail-next" && isRecord(body)) {
        failures.push({
          method: String(body.method ?? "*"),
          failure: String(body.failure ?? "tg500") as TelegramFailure,
        });
        writeJson(res, 200, { ok: true, queued: failures.length });
        return;
      }
      if (url.pathname === "/control/reset") {
        updates.length = 0;
        failures.length = 0;
        writeJson(res, 200, { ok: true });
        return;
      }
      writeJson(res, 404, { error: "unknown_control_endpoint" });
      return;
    }

    const method = resolveMethod(url.pathname);
    if (!method) {
      writeJson(res, 404, { ok: false, error_code: 404, description: "Not Found" });
      return;
    }

    const bodyText = await readRequestText(req);
    const body = parseTelegramBody(req.headers["content-type"], bodyText);
    const failureIndex = failures.findIndex((entry) => entry.method === "*" || entry.method === method);
    const failure = failureIndex >= 0 ? failures.splice(failureIndex, 1)[0]?.failure : undefined;
    const response = await telegramResponse({
      method,
      body,
      failure,
      updates,
      nextMessageId: () => nextMessageId++,
    });

    await appendNdjson(captureFile, {
      ts: new Date().toISOString(),
      method,
      body,
      response,
    });

    if (failure === "tgTimeout") {
      await delay(60_000);
      return;
    }
    writeJson(res, response.status, response.body);
  });

  const handle = await listen(server);
  return {
    ...handle,
    apiRoot: handle.origin,
    token,
    captureFile,
    injectUpdate: async (message) => {
      await fetch(`${handle.origin}/control/inject-update`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message }),
      });
    },
    failNext: async (method, failure) => {
      await fetch(`${handle.origin}/control/fail-next`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ method, failure }),
      });
    },
    reset: async () => {
      await fetch(`${handle.origin}/control/reset`, { method: "POST", body: "{}" });
    },
  };
}

async function telegramResponse(params: {
  method: string;
  body: JsonRecord;
  failure?: TelegramFailure;
  updates: JsonRecord[];
  nextMessageId(): number;
}): Promise<{ status: number; body: unknown }> {
  if (params.failure) return failureResponse(params.failure);

  switch (params.method) {
    case "getMe":
      return ok({
        id: 123,
        is_bot: true,
        username: "test_bot",
        first_name: "Test",
      });
    case "getUpdates": {
      const result = params.updates.splice(0, params.updates.length);
      return ok(result);
    }
    case "sendMessage":
    case "editMessageText":
      return ok({
        message_id: params.nextMessageId(),
        chat: { id: Number(params.body.chat_id ?? 4242), type: "private" },
        date: Math.floor(Date.now() / 1000),
        text: String(params.body.text ?? ""),
      });
    case "setMyCommands":
    case "setWebhook":
    case "deleteWebhook":
    case "pinChatMessage":
      return ok(true);
    case "sendPhoto":
    case "sendDocument":
      return ok({
        message_id: params.nextMessageId(),
        chat: { id: Number(params.body.chat_id ?? 4242), type: "private" },
        date: Math.floor(Date.now() / 1000),
      });
    default:
      return ok(true);
  }
}

function failureResponse(failure: TelegramFailure): { status: number; body: unknown } {
  switch (failure) {
    case "tgFlood":
      return error(429, "Too Many Requests: retry after 5", { retry_after: 5 });
    case "tgParseError":
      return error(400, "Bad Request: can't parse entities: Can't find end of the entity");
    case "tgChatNotFound":
      return error(400, "Bad Request: chat not found");
    case "tgBlockedByUser":
      return error(403, "Forbidden: bot was blocked by the user");
    case "tgUnauthorized":
      return error(401, "Unauthorized");
    case "tgMessageNotModified":
      return error(400, "Bad Request: message is not modified");
    case "tgMessageTooLong":
      return error(400, "Bad Request: message is too long");
    case "tg500":
      return error(500, "Internal Server Error");
    case "tgTimeout":
      return error(599, "timeout simulation completed unexpectedly");
  }
}

function ok(result: unknown): { status: number; body: unknown } {
  return { status: 200, body: { ok: true, result } };
}

function error(
  status: number,
  description: string,
  parameters?: Record<string, unknown>,
): { status: number; body: unknown } {
  return {
    status,
    body: {
      ok: false,
      error_code: status,
      description,
      ...(parameters ? { parameters } : {}),
    },
  };
}

function resolveMethod(pathname: string): string | undefined {
  const parts = pathname.split("/").filter(Boolean);
  const last = parts.at(-1);
  if (!last) return undefined;
  if (parts[0]?.startsWith("bot")) return last;
  return last;
}

function parseTelegramBody(contentType: unknown, body: string): JsonRecord {
  if (!body) return {};
  if (String(contentType ?? "").includes("application/json")) {
    const parsed = parseJson(body);
    return isRecord(parsed) ? parsed : {};
  }
  const params = new URLSearchParams(body);
  return Object.fromEntries(params.entries());
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
}
