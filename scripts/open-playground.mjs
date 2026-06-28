import os from "node:os";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

const DEFAULT_DEMO_BASE_URL = "https://app.silmaril.dev";
const ROUTES = {
  setup: "/demo/setup-complete",
  playground: "/demo/playground",
};

function hasFlag(name) {
  return process.argv.includes(name);
}

export function optionValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) {
    return undefined;
  }
  const next = process.argv[index + 1];
  return next && !next.startsWith("--") ? next : undefined;
}

function normalizeBaseUrl(value) {
  const raw = (value || "").trim() || DEFAULT_DEMO_BASE_URL;
  return raw.startsWith("http://") || raw.startsWith("https://")
    ? raw
    : `https://${raw}`;
}

function normalizeRoute(value) {
  return value === "playground" ? "playground" : "setup";
}

function routeFromCli() {
  return hasFlag("--playground") ? "playground" : normalizeRoute(optionValue("--route"));
}

export function buildDemoUrl(baseUrl, route = "setup") {
  return new URL(ROUTES[normalizeRoute(route)], normalizeBaseUrl(baseUrl)).href;
}

function openerCommand(url) {
  if (process.platform === "darwin") {
    return { command: "open", args: [url], options: { detached: true, stdio: "ignore" } };
  }

  if (process.platform === "win32") {
    return {
      command: "cmd",
      args: ["/c", "start", "", url],
      options: { detached: true, stdio: "ignore", windowsHide: true },
    };
  }

  return { command: "xdg-open", args: [url], options: { detached: true, stdio: "ignore" } };
}

export async function printOrOpen(url, spawnImpl = spawn) {
  if (hasFlag("--json")) {
    console.log(JSON.stringify({ url }));
  } else {
    console.log(url);
  }

  if (hasFlag("--open")) {
    const { command, args, options } = openerCommand(url);
    try {
      const child = spawnImpl(command, args, options);
      child.on("error", (error) => {
        console.error(`Could not open browser with ${command}: ${error.message}`);
        process.exitCode = 1;
      });
      child.unref();
    } catch (error) {
      console.error(`Could not open browser with ${command}: ${error.message}`);
      process.exitCode = 1;
    }
  }
}

function printHelp() {
  console.log("Usage: node scripts/open-playground.mjs [--open] [--json] [--playground] [--route <setup|playground>]");
  console.log("");
  console.log("Prints the public Silmaril Firewall demo URL.");
  console.log("Override the hosted base URL with SILMARIL_DEMO_BASE_URL for preview validation.");
  console.log("Pass --json to print a machine-readable URL without OpenClaw configuration values.");
  console.log(`Platform: ${os.platform()}`);
}

async function main() {
  if (hasFlag("--help") || hasFlag("-h")) {
    printHelp();
    return;
  }

  const demoBaseUrl = process.env.SILMARIL_DEMO_BASE_URL ?? DEFAULT_DEMO_BASE_URL;
  const route = routeFromCli();
  await printOrOpen(buildDemoUrl(demoBaseUrl, route));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
