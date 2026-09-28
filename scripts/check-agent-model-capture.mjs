import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EARLY_EVENT_TYPES = new Set(["before_agent_run", "before_prompt_build"]);
const IN_FLIGHT_EVENT_TYPES = new Set(["before_tool_call", "after_tool_call"]);

export function optionValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) {
    return undefined;
  }
  const next = process.argv[index + 1];
  return next && !next.startsWith("--") ? next : undefined;
}

export async function readCapture(filePath) {
  const raw = await readFile(filePath, "utf8");
  const records = [];
  const errors = [];
  const lines = raw.split(/\n/);
  lines.forEach((line, index) => {
    if (!line.trim()) {
      return;
    }
    try {
      records.push(JSON.parse(line));
    } catch {
      errors.push(`capture line ${index + 1} is not JSON`);
    }
  });
  return { records, errors };
}

export function checkAgentModelCapture(records, { firstModel, secondModel } = {}) {
  const errors = [];
  if (!isModelId(firstModel) || !isModelId(secondModel)) {
    errors.push("firstModel and secondModel must be nonempty trimmed strings");
  } else if (firstModel === secondModel) {
    errors.push("firstModel and secondModel must differ");
  }
  if (!Array.isArray(records)) {
    return { ok: false, errors: ["capture records must be an array"] };
  }

  const posts = [];
  records.forEach((record, index) => {
    const post = classifyPost(record);
    if (post.error) {
      errors.push(`record ${index + 1}: ${post.error}`);
      return;
    }
    if (post.value) {
      posts.push(post.value);
    }
  });
  if (posts.length === 0) {
    errors.push("capture has no classifier POST /classify request");
  }

  for (const post of posts) {
    if (post.eventType === "model_call_started" || post.eventType === "model_call_ended") {
      errors.push(`${post.eventType} produced a classifier POST`);
    }
    if (post.agentModelId !== undefined && !IN_FLIGHT_EVENT_TYPES.has(post.eventType)) {
      errors.push(`${post.eventType ?? "request"} included agent_model_id outside an in-flight model call`);
    }
    if (post.agentModelId !== undefined && post.provenanceHarness !== "openclaw") {
      errors.push(`${post.eventType ?? "request"} agent_model_id is missing openclaw provenance`);
    }
  }

  if (errors.length > 0 && posts.length === 0) {
    return { ok: false, errors };
  }

  const runIds = [];
  for (const post of posts) {
    if (post.runId && !runIds.includes(post.runId)) {
      runIds.push(post.runId);
    }
  }

  const qualifying = [];
  for (const runId of runIds) {
    const runPosts = posts.filter((post) => post.runId === runId);
    const early = runPosts.find((post) => EARLY_EVENT_TYPES.has(post.eventType));
    const tools = runPosts.filter((post) => post.eventType === "before_tool_call");
    if (!early || tools.length === 0) {
      continue;
    }
    const earlyIndex = runPosts.indexOf(early);
    const firstToolIndex = runPosts.indexOf(tools[0]);
    if (earlyIndex > firstToolIndex) {
      errors.push(`run ${runId} classified a tool call before its early prompt`);
    }
    if (early.agentModelId !== undefined) {
      errors.push(`run ${runId} early ${early.eventType} included agent_model_id`);
    }
    const models = [...new Set(tools.map((post) => post.agentModelId))];
    if (models.some((model) => model === undefined)) {
      errors.push(`run ${runId} has a before_tool_call without agent_model_id`);
      continue;
    }
    qualifying.push({ runId, models, runPosts });
  }

  const switched = qualifying.find((run) =>
    run.models.length === 2 && run.models[0] === firstModel && run.models[1] === secondModel
    && toolModelsInOrder(run.runPosts, firstModel, secondModel));
  const firstRun = qualifying.find((run) => run.models.length === 1 && run.models[0] === firstModel);
  const secondRun = qualifying.find((run) => run.models.length === 1 && run.models[0] === secondModel);
  if (!switched && !(firstRun && secondRun && firstRun.runId !== secondRun.runId)) {
    errors.push(`capture did not show ${firstModel} during a model call and ${secondModel} after a switch`);
  }

  if (firstRun && secondRun) {
    const firstToolAt = posts.findIndex((post) =>
      post.runId === firstRun.runId && post.eventType === "before_tool_call");
    const secondEarlyAt = posts.findIndex((post) =>
      post.runId === secondRun.runId && EARLY_EVENT_TYPES.has(post.eventType));
    if (secondEarlyAt < firstToolAt) {
      errors.push("the switched run's early prompt was captured before the first model call");
    }
    if (secondRun.runPosts.some((post) => post.agentModelId === firstModel)) {
      errors.push(`run ${secondRun.runId} reused ${firstModel} after the switch`);
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    observed: {
      qualifyingRuns: qualifying.map((run) => ({ runId: run.runId, models: run.models })),
    },
  };
}

function toolModelsInOrder(runPosts, firstModel, secondModel) {
  const models = runPosts
    .filter((post) => post.eventType === "before_tool_call")
    .map((post) => post.agentModelId);
  const firstAt = models.indexOf(firstModel);
  const secondAt = models.indexOf(secondModel);
  return firstAt >= 0 && secondAt > firstAt;
}

function isModelId(value) {
  return typeof value === "string" && value.trim() === value && value.length > 0;
}

function classifyPost(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return { error: "capture record is not an object" };
  }
  const method = typeof record.method === "string" ? record.method.toUpperCase() : "";
  const url = typeof record.url === "string" ? record.url : "";
  if (method !== "POST" || !url.endsWith("/classify")) {
    return {};
  }
  const body = record.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: "classifier POST body is not an object" };
  }
  if (Array.isArray(body.texts)) {
    return { error: "classifier POST is a batch; agent model checks require one metadata object" };
  }
  if (typeof body.text !== "string") {
    return { error: "classifier POST is missing text" };
  }
  const metadata = body.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return { error: "classifier POST is missing metadata" };
  }
  const silmaril = metadata.silmaril;
  if (!silmaril || typeof silmaril !== "object" || Array.isArray(silmaril)) {
    return { error: "classifier POST is missing metadata.silmaril" };
  }
  if (Object.hasOwn(metadata, "agent_model_id")) {
    return { error: "agent_model_id must be metadata.silmaril.agent_model_id" };
  }
  let agentModelId;
  if (Object.hasOwn(silmaril, "agent_model_id")) {
    if (typeof silmaril.agent_model_id !== "string" || silmaril.agent_model_id.trim() !== silmaril.agent_model_id || !silmaril.agent_model_id) {
      return { error: "metadata.silmaril.agent_model_id must be a trimmed nonempty string" };
    }
    agentModelId = silmaril.agent_model_id;
  }
  const provenance = silmaril.provenance;
  return {
    value: {
      eventType: typeof metadata.eventType === "string" ? metadata.eventType : undefined,
      runId: typeof metadata.runId === "string" ? metadata.runId : undefined,
      agentModelId,
      provenanceHarness: provenance && typeof provenance === "object" ? provenance.harness : undefined,
    },
  };
}

function printHelp() {
  console.log("Usage: node scripts/check-agent-model-capture.mjs --capture <captures.jsonl> --first-model <id> --second-model <id>");
  console.log("");
  console.log("Checks recorded classifier POST bodies for in-flight agent_model_id attribution.");
  console.log("A passing fixture is not an OpenClaw Gateway result.");
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    printHelp();
    return;
  }
  const capture = optionValue("--capture");
  const firstModel = optionValue("--first-model");
  const secondModel = optionValue("--second-model");
  if (!capture || !firstModel || !secondModel) {
    printHelp();
    process.exitCode = 1;
    return;
  }
  const loaded = await readCapture(path.resolve(capture));
  const result = checkAgentModelCapture(loaded.records, { firstModel, secondModel });
  const errors = [...loaded.errors, ...result.errors];
  if (errors.length > 0) {
    for (const error of errors) {
      console.error(error);
    }
    process.exitCode = 1;
    return;
  }
  console.log(JSON.stringify({ ok: true, observed: result.observed }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
