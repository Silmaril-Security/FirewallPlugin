// index.ts
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";

const FIREWALL_SYNC_WORKER_PATH = fileURLToPath(new URL("./scripts/firewall-classify-worker.mjs", import.meta.url));

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Adds hook-level Silmaril firewall classification to OpenClaw",
  register(api) {
    const apiKey = readString(api.pluginConfig?.apiKey);
    const apiUrl = readString(api.pluginConfig?.apiUrl);
    if (!apiKey || !apiUrl) {
      api.logger.warn("firewall-plugin: apiKey or apiUrl missing - plugin disabled");
      return;
    }

    const firewall = new Firewall({ apiKey, apiUrl });
    api.logger.info("firewall-plugin: installed");

    api.on("before_prompt_build", async (event) => {
      if (typeof event?.prompt !== "string") return;
      try {
        const result = await firewall.classify(event.prompt, {
          hook: HookLabel.USER_INPUT,
        });
        console.log("[firewall] before_prompt_build result:", JSON.stringify(result));
      } catch (err) {
        console.error("[firewall] before_prompt_build error:", err);
      }
    });

    api.on("before_tool_call", async (event) => {
      try {
        const result = await firewall.classify(JSON.stringify(event?.params ?? {}), {
          hook: HookLabel.TOOL_CALL,
          toolName: readString(event?.toolName),
        });
        console.log("[firewall] before_tool_call result:", JSON.stringify(result));
      } catch (err) {
        console.error("[firewall] before_tool_call error:", err);
      }
    });

    api.on("tool_result_persist", (event) => {
      try {
        console.log("[firewall] tool_result_persist sync classify begin");
        const result = classifyFirewallSync({
          apiKey,
          apiUrl,
          text: extractToolResultText(event),
          hook: HookLabel.TOOL_RESPONSE,
          toolName: readString(event?.toolName),
        });
        console.log("[firewall] tool_result_persist sync result:", JSON.stringify(result));
      } catch (err) {
        console.error("[firewall] tool_result_persist error:", err);
      }
    });
  },
});

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function classifyFirewallSync(params: {
  apiKey: string;
  apiUrl: string;
  text: string;
  hook: string;
  toolName?: string;
}): { prediction: string; score: number } {
  const startedAt = Date.now();
  const child = spawnSync(
    process.execPath,
    [FIREWALL_SYNC_WORKER_PATH],
    {
      input: JSON.stringify(params),
      encoding: "utf8",
      timeout: 5_000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    },
  );
  const elapsedMs = Date.now() - startedAt;

  if (child.error) {
    throw child.error;
  }
  if (child.status !== 0) {
    throw new Error(child.stderr.trim() || `firewall sync worker exited ${child.status ?? "without status"}`);
  }

  const parsed = JSON.parse(child.stdout);
  console.log(`[firewall] sync worker completed in ${elapsedMs}ms`);
  return {
    prediction: String(parsed.prediction),
    score: Number(parsed.score),
  };
}

function extractToolResultText(event: { message?: { content?: unknown } } | undefined): string {
  const content = event?.message?.content;
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .map((part) => {
      if (typeof part === "string") {
        return part;
      }
      if (part && typeof part === "object" && typeof (part as { text?: unknown }).text === "string") {
        return (part as { text: string }).text;
      }
      return "";
    })
    .join("\n");
}
