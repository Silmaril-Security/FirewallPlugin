// index.ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Adds a firewall to OpenClaw",
  register(api) {
    const apiKey = api.pluginConfig?.apiKey;
    const apiUrl = api.pluginConfig?.apiUrl;
    if (!apiKey || !apiUrl) {
      api.logger.warn("firewall-plugin: apiKey or apiUrl missing — plugin disabled");
      return;
    }

    const firewall = new Firewall({ apiKey, apiUrl });

    api.on("before_tool_call", async (event) => {
      try {
        const result = await firewall.classify(JSON.stringify(event.params), {
          hook: HookLabel.TOOL_CALL,
          toolName: event.toolName,
        });
        console.log(`[firewall] before_tool_call result:`, JSON.stringify(result));
      } catch (err) {
        console.error(`[firewall] before_tool_call error:`, err);
      }
    });

    api.on("tool_result_persist", async (event, _ctx) => {
      try {
        const resultText = event?.message?.content
          ?.map((c: { text?: string }) => c.text ?? "")
          .join("\n") ?? "";
        const result = await firewall.classify(resultText, {
          hook: HookLabel.TOOL_RESPONSE,
          toolName: event.toolName,
        });
        console.log(`[firewall] tool_result_persist result:`, JSON.stringify(result));
      } catch (err) {
        console.error(`[firewall] before_tool_call error:`, err);
      }
    });

    api.on("before_prompt_build", async (event) => {
      if (typeof event?.prompt !== "string") return;
      try {
        const result = await firewall.classify(event.prompt, {
          hook: HookLabel.USER_INPUT,
        });
        console.log(`[firewall] before_prompt_build result:`, JSON.stringify(result));
      } catch (err) {
        console.error(`[firewall] before_prompt_build error:`, err);
      }
    });
  },
});
