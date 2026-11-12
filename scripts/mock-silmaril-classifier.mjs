import { appendFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const LIVE_UPSTREAM_TIMEOUT_MS = 10_000;

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
    const reply = live
      ? await forwardLive(live, rawBody)
      : { status: 200, payload: buildResponse(body, maliciousMarkers) };
    Object.assign(record, {
      status: reply.status,
      decision: isBlockDecision(reply.payload) ? "block" : "allow",
      durationMs: Math.round(performance.now() - startedAt),
      ...(live && reply.status === 200 ? { upstream: summarizeUpstream(reply.payload) } : {}),
    });

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

function forwardLive({ url, key, fetchImpl = fetch }, rawBody) {
  return fetchImpl(url, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(LIVE_UPSTREAM_TIMEOUT_MS),
    headers: { "content-type": "application/json", "x-api-key": key },
    body: rawBody,
  })
    .then(async (upstream) => ({ status: upstream.status, payload: await upstream.json() }))
    .catch((error) => ({ status: 502, payload: { error: error.name } }));
}

function summarizeUpstream(payload) {
  return {
    prediction: payload.prediction ?? null,
    mode: payload.mode ?? null,
    action: payload.governance?.action ?? null,
  };
}

function isBlockDecision(payload) {
  return payload.prediction === "MALICIOUS" || payload.governance?.action === "block";
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

function buildResponse(body, maliciousMarkers) {
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
