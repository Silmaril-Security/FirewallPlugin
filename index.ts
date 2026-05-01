// index.ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";
import { createFirewallExporter } from "./src/exporter/register-exporter";

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Adds a firewall to OpenClaw",
  register(api) {
    const apiKey = api.pluginConfig?.apiKey;
    const silmarilApiKey = api.pluginConfig?.silmarilApiKey ?? apiKey;
    const apiUrl = api.pluginConfig?.apiUrl;
    if (!apiKey || !apiUrl) {
      api.logger.warn("firewall-plugin: apiKey or apiUrl missing — plugin disabled");
      return;
    }

    const firewall = new Firewall({ apiKey: silmarilApiKey, apiUrl });
    const exporter = createFirewallExporter(api, { apiKey, apiUrl });

    const logExporterWarning = (hook: string, err: unknown) => {
      const message = `[firewall] exporter write failed in ${hook}: ${err instanceof Error ? err.message : String(err)}`;
      api.logger?.warn?.(message);
      console.warn(message);
    };

    api.on("before_tool_call", async (event) => {
      try {
        const result = await firewall.classify(JSON.stringify(event.params), {
          hook: HookLabel.TOOL_CALL,
          toolName: event.toolName,
        });
        console.log(`[firewall] before_tool_call result:`, JSON.stringify(result));
        try {
          await exporter.writeEvent({
            source: "tool_call",
            toolName: event.toolName,
            payload: event.params,
            firewallResult: result,
          });
        } catch (err) {
          logExporterWarning("before_tool_call", err);
        }
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
        try {
          await exporter.writeEvent({
            source: "tool_response",
            toolName: event.toolName,
            payload: {
              text: resultText,
            },
            firewallResult: result,
          });
        } catch (err) {
          logExporterWarning("tool_result_persist", err);
        }
      } catch (err) {
        console.error(`[firewall] before_tool_call error:`, err);
      }
    });

    api.on("before_prompt_build", async (event) => {
      try {
        const text = event?.prompt ?? "";
        if (text) {
          const result = await firewall.classify(text, {
            hook: HookLabel.USER_INPUT,
          });
          console.log(`[firewall] before_prompt_build (USER_INPUT) result:`, JSON.stringify(result));
          try {
            await exporter.writeEvent({
              source: "user_input",
              payload: {
                prompt: event.prompt,
              },
              firewallResult: result,
            });
          } catch (err) {
            logExporterWarning("before_prompt_build", err);
          }
        }
      } catch (err) {
        console.error(`[firewall] before_prompt_build error:`, err);
      }
    });
  },
});
