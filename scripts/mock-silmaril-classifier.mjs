import { appendFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const readyPath = process.env.SILMARIL_CLASSIFIER_READY_PATH;
const capturePath = process.env.SILMARIL_CLASSIFIER_CAPTURE_PATH ??
  path.join(os.tmpdir(), `silmaril-classifier-captures-${process.pid}.jsonl`);

const server = http.createServer(async (request, response) => {
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

  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify(buildBenignResponse(body)));
});

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") {
    console.error("mock classifier did not receive a TCP port");
    process.exit(1);
  }

  if (readyPath) {
    writeFileSync(
      readyPath,
      JSON.stringify({
        port: address.port,
        url: `http://127.0.0.1:${address.port}/classify`,
        capturePath,
      }),
    );
  }

  console.log(`mock Silmaril classifier listening at http://127.0.0.1:${address.port}/classify`);
  console.log(`captures: ${capturePath}`);
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
});

function buildBenignResponse(body) {
  if (Array.isArray(body?.texts)) {
    return {
      predictions: body.texts.map(() => ({
        prediction: "BENIGN",
        score: 0,
      })),
    };
  }

  return {
    prediction: "BENIGN",
    score: 0,
  };
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
