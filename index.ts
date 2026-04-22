// index.ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Adds a firewall to OpenClaw",
  register(api) {
    const firewall = new Firewall({
      apiKey: "INSERT_KEY",
      apiUrl: "INSERT_URL",
      shadowMode: true
    });

    api.on("before_tool_call", async (event) => {
      try {
        const result = await firewall.classify(JSON.stringify(event.params), {
          hook: HookLabel.TOOL_CALL,
          toolName: event.toolName,
        });
      } catch (err) {
        console.error(`[firewall] before_tool_call error:`, err);
      }
    });

    api.on("tool_result_persist", async (event, _ctx) => {
      try {
        const result = await firewall.classify(JSON.stringify(event.params), {
          hook: HookLabel.TOOL_CALL,
          toolName: event.toolName,
        });
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
      } catch (err) {
        console.error(`[firewall] before_prompt_build error:`, err);
      }
    });
  },
});
