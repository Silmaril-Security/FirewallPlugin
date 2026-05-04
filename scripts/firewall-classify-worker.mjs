#!/usr/bin/env node
import { Firewall } from "@silmaril-security/sdk";

const stdin = await new Promise((resolve, reject) => {
  let data = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    data += chunk;
  });
  process.stdin.on("end", () => resolve(data));
  process.stdin.on("error", reject);
});

try {
  const input = JSON.parse(stdin);
  const apiKey = assertString(input.apiKey, "apiKey");
  const apiUrl = assertString(input.apiUrl, "apiUrl");
  const text = assertString(input.text, "text");
  const hook = assertString(input.hook, "hook");
  const toolName = typeof input.toolName === "string" && input.toolName.trim() ? input.toolName : undefined;
  const metadata = isRecord(input.metadata) ? input.metadata : undefined;

  const firewall = new Firewall({ apiKey, apiUrl });
  const result = await firewall.classify(text, {
    hook,
    ...(toolName ? { toolName } : {}),
    ...(metadata ? { metadata } : {}),
  });

  process.stdout.write(JSON.stringify({
    prediction: result.prediction,
    score: Number(result.score),
  }));
} catch (err) {
  process.stderr.write(err instanceof Error ? err.stack ?? err.message : String(err));
  process.exitCode = 1;
}

function assertString(value, field) {
  if (typeof value !== "string") {
    throw new Error(`Expected ${field} to be a string`);
  }
  return value;
}

function isRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
