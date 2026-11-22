import { appendFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const LIVE_UPSTREAM_TIMEOUT_MS = 10_000;
const ROUTE_FALLBACK_STATUSES = new Set([403, 404, 405]);
export const V2_ROUTE = "/v2/classify";
export const V1_ROUTE = "/classify";

export async function startMockClassifier({ capturePath, maliciousMarkers = [], live } = {}) {
  const requests = [];
  const inFlight = new Set();

  const handle = async (request, response) => {
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
    }

    const rawBody = Buffer.concat(chunks).toString("utf8");
    let body;
    try {
      body = rawBody ? JSON.parse(rawBody) : {};
    } catch {
      body = { rawBody };
    }

    if (capturePath) {
      appendFileSync(
        capturePath,
        `${JSON.stringify({
          at: new Date().toISOString(),
          method: request.method,
          url: request.url,
          body,
          summary: summarizeBody(body),
        })}\n`,
      );
    }

    const record = {
      hook: body.hook,
      eventType: body.metadata?.eventType,
      toolName: body.tool_name,
      markerMatched: classifiedTexts(body).some((text) => containsMarker(text, maliciousMarkers)),
    };
    requests.push(record);

    const startedAt = performance.now();
    const route = new URL(request.url, "http://loopback").pathname.endsWith(V2_ROUTE)
      ? V2_ROUTE
      : V1_ROUTE;
    const reply = live
      ? await forwardLive(live, route, rawBody)
      : { status: 200, payload: buildResponse(route, body, maliciousMarkers) };
    if (live && route === V2_ROUTE && ROUTE_FALLBACK_STATUSES.has(reply.status)) {
      requests.splice(requests.indexOf(record), 1);
    } else {
      Object.assign(record, {
        status: reply.status,
        decision: isBlockDecision(reply.payload) ? "block" : "allow",
        durationMs: Math.round(performance.now() - startedAt),
        ...(live && reply.status === 200 ? { upstream: summarizeUpstream(reply.payload) } : {}),
      });
    }

    response.writeHead(reply.status, { "content-type": "application/json" });
    response.end(JSON.stringify(reply.payload));
  };

  const server = http.createServer((request, response) => {
    const handling = handle(request, response).finally(() => inFlight.delete(handling));
    inFlight.add(handling);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();

  return {
    port,
    url: `http://127.0.0.1:${port}/classify`,
    requests,
    settled: () => Promise.all(inFlight),
    close: () => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(resolve);
    }),
  };
}

export function upstreamRoute(configuredUrl, route) {
  const url = new URL(configuredUrl);
  const base = url.pathname.replace(/\/$/u, "");
  const configuredRoute = [V2_ROUTE, V1_ROUTE].find((known) => base.endsWith(known));
  url.pathname = `${configuredRoute ? base.slice(0, -configuredRoute.length) : base}${route}`;
  return url.href;
}

function forwardLive({ url, key, fetchImpl = fetch }, route, rawBody) {
  return fetchImpl(upstreamRoute(url, route), {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(LIVE_UPSTREAM_TIMEOUT_MS),
    headers: { "content-type": "application/json", "x-api-key": key },
    body: rawBody,
  })
    .then(async (upstream) => ({ status: upstream.status, payload: await upstream.json() }))
    .catch((error) => ({ status: 502, payload: { error: error.name } }));
}

function singleResult(payload) {
  return Array.isArray(payload.results) && payload.results.length === 1
    ? payload.results[0]
    : undefined;
}

function summarizeUpstream(payload) {
  const result = singleResult(payload);
  return result
    ? { action: result.action ?? null, source: result.source ?? null }
    : {
      prediction: payload.prediction ?? null,
      mode: payload.mode ?? null,
      action: payload.governance?.action ?? null,
    };
}

function isBlockDecision(payload) {
  const result = singleResult(payload);
  return result
    ? typeof result.action === "string" && result.action !== "allow"
    : payload.prediction === "MALICIOUS" || payload.governance?.action === "block";
}

function classifiedTexts(body) {
  return Array.isArray(body?.texts) ? body.texts : [body?.text];
}

function containsMarker(text, maliciousMarkers) {
  return maliciousMarkers.some((marker) => String(text ?? "").includes(marker));
}

function buildPrediction(text, maliciousMarkers) {
  const malicious = containsMarker(text, maliciousMarkers);
  return {
    prediction: malicious ? "MALICIOUS" : "BENIGN",
    score: malicious ? 1 : 0,
  };
}

function buildResult(text, maliciousMarkers) {
  const malicious = containsMarker(text, maliciousMarkers);
  return {
    action: malicious ? "block" : "allow",
    source: malicious ? "model" : null,
    confidence: malicious ? "very_high" : null,
    severity: malicious ? "high" : null,
    outcome: malicious ? "control_abuse" : null,
    governance: null,
    model_id: null,
  };
}

function buildResponse(route, body, maliciousMarkers) {
  if (route === V2_ROUTE) {
    return {
      results: classifiedTexts(body).map((text) => buildResult(text, maliciousMarkers)),
    };
  }
  if (Array.isArray(body?.texts)) {
    return {
      predictions: body.texts.map((text) => buildPrediction(text, maliciousMarkers)),
    };
  }

  return buildPrediction(body?.text, maliciousMarkers);
}

function summarizeBody(body) {
  if (!body || typeof body !== "object") {
    return {};
  }

  return {
    hook: body.hook,
    toolName: body.tool_name,
    hooks: body.hooks,
    toolNames: body.tool_names,
    textLength: typeof body.text === "string" ? body.text.length : undefined,
    textCount: Array.isArray(body.texts) ? body.texts.length : undefined,
  };
}

async function runCli() {
  const readyPath = process.env.SILMARIL_CLASSIFIER_READY_PATH;
  const capturePath = process.env.SILMARIL_CLASSIFIER_CAPTURE_PATH ??
    path.join(os.tmpdir(), `silmaril-classifier-captures-${process.pid}.jsonl`);
  const maliciousMarkers = (process.env.SILMARIL_CLASSIFIER_MALICIOUS_MARKERS ?? "")
    .split(",")
    .filter(Boolean);

  const classifier = await startMockClassifier({ capturePath, maliciousMarkers });

  if (readyPath) {
    writeFileSync(
      readyPath,
      JSON.stringify({ port: classifier.port, url: classifier.url, capturePath }),
    );
  }

  console.log(`mock Silmaril classifier listening at ${classifier.url}`);
  console.log(`captures: ${capturePath}`);

  process.on("SIGTERM", () => {
    classifier.close().then(() => process.exit(0));
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await runCli();
}
