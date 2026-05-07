// scripts/policy-smoke.mjs
// Loads index.ts and exercises register() with a stub OpenClaw api.
// Verifies plugin wiring without driving the live gateway.

import { fileURLToPath } from "node:url";

const handlers = new Map();
const tools = [];
const providers = [];
const logs = { info: [], warn: [], error: [] };

const stubApi = {
  pluginConfig: { userEmail: process.env.SMOKE_USER_EMAIL ?? "gary@silmaril.dev", apiKey: "stub", silmarilApiKey: "stub", apiUrl: "http://stub" },
  config: {},
  logger: {
    info: (msg) => { logs.info.push(msg); console.log("[info]", msg); },
    warn: (msg) => { logs.warn.push(msg); console.log("[warn]", msg); },
    error: (msg) => { logs.error.push(msg); console.log("[error]", msg); },
  },
  on(event, handler, options) {
    const key = `${event}#${options?.priority ?? 0}`;
    if (!handlers.has(event)) handlers.set(event, []);
    handlers.get(event).push({ handler, priority: options?.priority ?? 0 });
  },
  registerTool(tool, options) {
    tools.push({ tool, options });
  },
  registerWebFetchProvider(provider) {
    providers.push(provider);
  },
};

const indexUrl = new URL("../index.ts", import.meta.url);
const mod = await import(indexUrl.href);
const plugin = mod.default;

if (!plugin || typeof plugin.register !== "function") {
  console.error("FAIL: index.ts default export missing register()");
  process.exit(1);
}

try {
  plugin.register(stubApi);
} catch (err) {
  console.error("FAIL: register() threw:", err.message);
  process.exit(1);
}

console.log("\n--- registration summary ---");
console.log("hooks registered:", [...handlers.keys()]);
console.log("tools registered:", tools.length);
console.log("providers registered:", providers.length);
console.log("info logs:", logs.info.length, "warn logs:", logs.warn.length);
console.log("--- expected log lines ---");
const identityLogged = logs.info.some((m) => /firewall-plugin: identity=/.test(m));
console.log("identity logged:", identityLogged);
console.log("\nSMOKE OK");
