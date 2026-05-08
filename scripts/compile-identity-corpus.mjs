#!/usr/bin/env node
// Compile bench/identity-attacks.yaml into a determinism-locked JSON file at
// bench/compiled/identity-attacks-v<version>.lock.json. Resolves
// ${MALICIOUS_PAYLOAD_*} template references against bench/identity-payloads.json.
//
// Usage: node scripts/compile-identity-corpus.mjs

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

function resolveTemplates(value, payloads) {
  if (typeof value === "string") {
    return value.replace(/\$\{MALICIOUS_PAYLOAD_(\w+)\}/g, (_, key) => {
      const lookup =
        payloads.payloads[key] ??
        payloads.payloads[`M_${key}`] ??
        payloads.payloads[`M${key}`];
      if (!lookup) throw new Error(`unknown payload reference: MALICIOUS_PAYLOAD_${key}`);
      return lookup.text;
    });
  }
  if (Array.isArray(value)) return value.map((v) => resolveTemplates(v, payloads));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveTemplates(v, payloads);
    return out;
  }
  return value;
}

const yamlPath = resolve(repoRoot, "bench/identity-attacks.yaml");
const payloadsPath = resolve(repoRoot, "bench/identity-payloads.json");
const corpus = parseYaml(readFileSync(yamlPath, "utf8"));
const payloads = JSON.parse(readFileSync(payloadsPath, "utf8"));

const resolved = resolveTemplates(corpus, payloads);
const compiledDir = resolve(repoRoot, "bench/compiled");
if (!existsSync(compiledDir)) mkdirSync(compiledDir, { recursive: true });
const out = {
  $schema: "https://silmaril.dev/schemas/identity-attacks-lock-v0.1.json",
  generatedAt: new Date().toISOString(),
  source: "bench/identity-attacks.yaml",
  payloadsSource: "bench/identity-payloads.json",
  corpus: resolved,
};
const outPath = resolve(compiledDir, `identity-attacks-v${corpus.suite.version}.lock.json`);
writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.log(`compiled ${resolved.cases.length} cases -> ${outPath}`);
