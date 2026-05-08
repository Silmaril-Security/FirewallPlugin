import http from "node:http";
import path from "node:path";
import {
  appendNdjson,
  delay,
  ensureDir,
  isRecord,
  listen,
  readRequestJson,
  redactHeaders,
  writeJson,
  writeText,
  type JsonRecord,
  type ServerHandle,
} from "./common";

export const TEST_SILMARIL_API_KEY = "test-silmaril-api-key";

export type ClassifierPrediction = "BENIGN" | "MALICIOUS" | "UNKNOWN";

export type ClassifierResult = {
  prediction: ClassifierPrediction;
  score: number;
  primary_outcome: string;
  outcome_scores: Partial<Record<ClassifierPrediction, number>> & { BENIGN: number; MALICIOUS: number };
  detector_scores: Record<string, number>;
  detector_counts: Record<string, number>;
};

export type ForcedClassifierResponse = Partial<ClassifierResult> & {
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
  delayMs?: number;
  malformed?: boolean;
  force429?: boolean;
  forceJSON429NoRetryAfter?: boolean;
  force500?: boolean;
  force403?: boolean;
  forceMalformed?: boolean;
  forceMalformedNonJson?: boolean;
  forceTimeout?: boolean;
  forceWAFBlock?: boolean;
  forceProcessKill?: boolean;
  forceUnknown?: boolean;          // emit prediction="UNKNOWN" with score 0.5
  forceEmptyPrediction?: boolean;  // emit prediction="" (regression guard)
};

export type MatchRule = {
  textPattern?: string;
  hookPattern?: string;
  toolNamePattern?: string;
  urlPattern?: string;
  response: ForcedClassifierResponse;
};

export type MockClassifier = ServerHandle & {
  apiKey: string;
  classifyUrl: string;
  captureFile: string;
  queue(response: ForcedClassifierResponse | ForcedClassifierResponse[]): Promise<void>;
  match(rule: MatchRule): Promise<void>;
  reset(): Promise<void>;
};

export async function startMockClassifier(options: {
  rootDir: string;
  apiKey?: string;
}): Promise<MockClassifier> {
  const apiKey = options.apiKey ?? TEST_SILMARIL_API_KEY;
  const captureFile = path.join(options.rootDir, "mock-classifier-captures.ndjson");
  await ensureDir(options.rootDir);

  const queue: ForcedClassifierResponse[] = [];
  const rules: MatchRule[] = [];
  let outageUntil = 0;
  let defaultDelayMs = 0;

  const server = http.createServer(async (req, res) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");

    try {
      if (req.method === "GET" && requestUrl.pathname === "/health") {
        writeJson(res, 200, { ok: true });
        return;
      }

      if (requestUrl.pathname.startsWith("/control/")) {
        if (req.method !== "POST") {
          writeJson(res, 405, { error: "method_not_allowed" });
          return;
        }
        const body = await readRequestJson<JsonRecord>(req);
        switch (requestUrl.pathname) {
          case "/control/next-response":
            queue.push(readForcedResponse(body));
            writeJson(res, 200, { ok: true, queued: queue.length });
            return;
          case "/control/queue":
            queue.push(...readForcedResponses(body));
            writeJson(res, 200, { ok: true, queued: queue.length });
            return;
          case "/control/match":
            rules.push(readMatchRule(body));
            writeJson(res, 200, { ok: true, rules: rules.length });
            return;
          case "/control/outage":
            outageUntil = Date.now() + readDuration(body.duration, 5_000);
            writeJson(res, 200, { ok: true, outageUntil });
            return;
          case "/control/timeout":
            defaultDelayMs = readDuration(body.delayMs, 12_000);
            writeJson(res, 200, { ok: true, delayMs: defaultDelayMs });
            return;
          case "/control/reset":
            queue.length = 0;
            rules.length = 0;
            outageUntil = 0;
            defaultDelayMs = 0;
            writeJson(res, 200, { ok: true });
            return;
          default:
            writeJson(res, 404, { error: "unknown_control_endpoint" });
            return;
        }
      }

      if (req.method !== "POST" || requestUrl.pathname !== "/classify") {
        writeJson(res, 404, { error: "not_found" });
        return;
      }

      if (req.headers["x-api-key"] !== apiKey) {
        writeJson(res, 401, { message: "Invalid API key" });
        return;
      }

      const caseId = String(req.headers["x-case-id"] ?? `case-${Date.now()}`);
      if (Date.now() < outageUntil) {
        const returned = { status: 503, body: { message: "Classifier outage" } };
        await appendNdjson(captureFile, {
          ts: new Date().toISOString(),
          caseId,
          headers: redactHeaders(req.headers),
          body: undefined,
          returned,
        });
        writeJson(res, returned.status, returned.body, { "x-case-id": caseId });
        return;
      }

      const body = await readRequestJson<JsonRecord>(req);
      const forced = queue.shift() ?? findRuleResponse(rules, body);
      const responseDelay = forced?.delayMs ?? defaultDelayMs;
      if (responseDelay > 0) {
        await delay(responseDelay);
      }

      const returned = await writeClassifierResponse({
        reqBody: body,
        forced,
        caseId,
        res,
      });

      await appendNdjson(captureFile, {
        ts: new Date().toISOString(),
        caseId,
        headers: redactHeaders(req.headers),
        body,
        returned,
        summary: summarize(body, returned.body),
      });
    } catch (err) {
      writeJson(res, 500, {
        message: err instanceof Error ? err.message : String(err),
      });
    }
  });

  const handle = await listen(server);
  const classifyUrl = `${handle.origin}/classify`;

  return {
    ...handle,
    apiKey,
    classifyUrl,
    captureFile,
    queue: async (response) => {
      await fetch(`${handle.origin}/control/queue`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ rules: Array.isArray(response) ? response : [response] }),
      });
    },
    match: async (rule) => {
      await fetch(`${handle.origin}/control/match`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rule),
      });
    },
    reset: async () => {
      await fetch(`${handle.origin}/control/reset`, { method: "POST", body: "{}" });
    },
  };
}

async function writeClassifierResponse(params: {
  reqBody: JsonRecord;
  forced?: ForcedClassifierResponse;
  caseId: string;
  res: http.ServerResponse;
}): Promise<{ status: number; body: unknown }> {
  const { forced, reqBody, res, caseId } = params;
  const headers = { "x-case-id": caseId, ...(forced?.headers ?? {}) };

  if (forced?.forceTimeout) {
    await delay(60_000);
    return { status: 599, body: { message: "timeout simulation completed unexpectedly" } };
  }
  if (forced?.forceProcessKill) {
    res.writeHead(200, { "content-type": "application/json", ...headers });
    res.write("{\"prediction\":");
    res.destroy();
    return { status: 200, body: "partial_body_connection_reset" };
  }
  if (forced?.force429 || forced?.forceJSON429NoRetryAfter) {
    const responseHeaders = forced.forceJSON429NoRetryAfter ? headers : { ...headers, "retry-after": "2" };
    writeJson(res, 429, { message: "Too Many Requests" }, responseHeaders);
    return { status: 429, body: { message: "Too Many Requests" } };
  }
  if (forced?.force500) {
    writeJson(res, 500, { message: "Internal server error" }, headers);
    return { status: 500, body: { message: "Internal server error" } };
  }
  if (forced?.force403) {
    writeJson(res, 403, { message: "Forbidden" }, headers);
    return { status: 403, body: { message: "Forbidden" } };
  }
  if (forced?.forceWAFBlock) {
    const wafBody = "<html><title>403 Forbidden</title><body>Request blocked by AWS WAF</body></html>";
    writeText(res, 403, wafBody, { "content-type": "text/html; charset=utf-8", ...headers });
    return { status: 403, body: wafBody };
  }
  if (forced?.forceMalformed || forced?.malformed) {
    writeJson(res, 200, {}, headers);
    return { status: 200, body: {} };
  }
  if (forced?.forceMalformedNonJson) {
    const html = "<html>500 from CloudFront</html>";
    writeText(res, 200, html, { "content-type": "text/html; charset=utf-8", ...headers });
    return { status: 200, body: html };
  }
  if (typeof forced?.status === "number") {
    const body = forced.body ?? { message: `forced ${forced.status}` };
    writeJson(res, forced.status, body, headers);
    return { status: forced.status, body };
  }

  const body = buildResponseBody(reqBody, forced);
  writeJson(res, 200, body, headers);
  return { status: 200, body };
}

function buildResponseBody(body: JsonRecord, forced?: ForcedClassifierResponse): unknown {
  if (Array.isArray(body.texts)) {
    return {
      predictions: body.texts.map((text, index) => {
        const perTextBody = {
          text,
          hook: Array.isArray(body.hooks) ? body.hooks[index] : body.hook,
          tool_name: Array.isArray(body.tool_names) ? body.tool_names[index] : body.tool_name,
          metadata: Array.isArray(body.metadata) ? body.metadata[index] : body.metadata,
        };
        return forced ? forcedResult(forced) : classify(String(text), perTextBody);
      }),
    };
  }
  return forced ? forcedResult(forced) : classify(String(body.text ?? ""), body);
}

function forcedResult(forced: ForcedClassifierResponse): ClassifierResult {
  if (forced.forceUnknown) {
    return result("UNKNOWN", 0.5, "forced_unknown_prediction");
  }
  if (forced.forceEmptyPrediction) {
    return result("" as ClassifierPrediction, 0, "forced_empty_prediction");
  }
  return result(
    forced.prediction ?? "BENIGN",
    typeof forced.score === "number" ? forced.score : forced.prediction === "MALICIOUS" ? 0.93 : 0.02,
    forced.primary_outcome ?? "forced_control_plane_response",
  );
}

function classify(text: string, body: unknown): ClassifierResult {
  const parsed = tryParseJson(text);
  const hook = String(readField(body, "hook") ?? parsed?.hook ?? "").toLowerCase();
  const toolName = String(readField(body, "tool_name") ?? readField(body, "toolName") ?? parsed?.tool_name ?? "");
  const inspectedText = [
    parsed?.extracted_text,
    parsed?.raw_response_text,
    parsed?.text,
    text,
  ]
    .filter((value): value is string => typeof value === "string")
    .join("\n");

  if (hook === "tool_response" && toolName === "web_fetch") {
    if (
      inspectedText.includes("SYSTEM OVERRIDE") ||
      inspectedText.includes("CANARY_HIDDEN_PROMPT_INJECTION") ||
      inspectedText.includes("CANARY_VISIBLE_TP")
    ) {
      return result("MALICIOUS", 0.97, "prompt_injection_fixture");
    }
    if (inspectedText.includes("Fixture FP-2026") || inspectedText.includes("CANARY_VISIBLE_FP")) {
      return result("MALICIOUS", 0.93, "forced_false_positive_local_fixture");
    }
    if (inspectedText.includes("Fixture TN-2026") || inspectedText.includes("CANARY_VISIBLE_TN")) {
      return result("BENIGN", 0.03, "true_negative_local_fixture");
    }
  }

  if (inspectedText.includes("SYSTEM OVERRIDE") || inspectedText.includes("CANARY_API_KEY_")) {
    return result("MALICIOUS", 0.96, "generic_prompt_injection_text");
  }

  return result("BENIGN", 0.02, "default_benign");
}

function result(prediction: ClassifierPrediction, score: number, reason: string): ClassifierResult {
  return {
    prediction,
    score,
    primary_outcome: reason,
    outcome_scores: {
      BENIGN: prediction === "BENIGN" ? 1 - score : Math.max(0, 1 - score),
      MALICIOUS: score,
    },
    detector_scores: {
      prompt_injection: prediction === "MALICIOUS" ? score : 0,
    },
    detector_counts: {
      prompt_injection: prediction === "MALICIOUS" ? 1 : 0,
    },
  };
}

function readForcedResponses(body: JsonRecord): ForcedClassifierResponse[] {
  const rules = Array.isArray(body.rules) ? body.rules : [body];
  return rules.map((rule) => readForcedResponse(rule));
}

function readForcedResponse(value: unknown): ForcedClassifierResponse {
  if (!isRecord(value)) return {};
  return value as ForcedClassifierResponse;
}

function readMatchRule(value: unknown): MatchRule {
  if (!isRecord(value) || !isRecord(value.response)) {
    throw new Error("match rule requires a response object");
  }
  return {
    textPattern: typeof value.textPattern === "string" ? value.textPattern : undefined,
    hookPattern: typeof value.hookPattern === "string" ? value.hookPattern : undefined,
    toolNamePattern: typeof value.toolNamePattern === "string" ? value.toolNamePattern : undefined,
    urlPattern: typeof value.urlPattern === "string" ? value.urlPattern : undefined,
    response: value.response as ForcedClassifierResponse,
  };
}

function findRuleResponse(rules: MatchRule[], body: JsonRecord): ForcedClassifierResponse | undefined {
  const text = typeof body.text === "string" ? body.text : JSON.stringify(body);
  const parsed = tryParseJson(text);
  const hook = String(body.hook ?? parsed?.hook ?? "");
  const toolName = String(body.tool_name ?? body.toolName ?? parsed?.tool_name ?? "");
  const urlish = String(parsed?.requested_host ?? parsed?.final_host ?? parsed?.requested_url ?? parsed?.final_url ?? "");

  return rules.find((rule) => {
    if (rule.textPattern && !new RegExp(rule.textPattern, "i").test(text)) return false;
    if (rule.hookPattern && !new RegExp(rule.hookPattern, "i").test(hook)) return false;
    if (rule.toolNamePattern && !new RegExp(rule.toolNamePattern, "i").test(toolName)) return false;
    if (rule.urlPattern && !new RegExp(rule.urlPattern, "i").test(urlish)) return false;
    return true;
  })?.response;
}

function summarize(reqBody: JsonRecord, responseBody: unknown): JsonRecord {
  const text = typeof reqBody.text === "string" ? reqBody.text : Array.isArray(reqBody.texts) ? String(reqBody.texts[0] ?? "") : "";
  const parsed = tryParseJson(text);
  const firstResponse = isRecord(responseBody) && Array.isArray(responseBody.predictions)
    ? responseBody.predictions[0]
    : responseBody;
  return {
    hook: reqBody.hook ?? parsed?.hook,
    toolName: reqBody.tool_name ?? reqBody.toolName ?? parsed?.tool_name,
    host: parsed?.requested_host ?? parsed?.final_host,
    prediction: isRecord(firstResponse) ? firstResponse.prediction : undefined,
    score: isRecord(firstResponse) ? firstResponse.score : undefined,
    outcome: isRecord(firstResponse) ? firstResponse.primary_outcome : undefined,
  };
}

function readField(value: unknown, key: string): unknown {
  return isRecord(value) ? value[key] : undefined;
}

function tryParseJson(value: string): JsonRecord | undefined {
  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function readDuration(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback;
}
