// index.ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel, type ClassifyOptions } from "@silmaril-security/sdk";
import { createFirewallExporter } from "./src/exporter/register-exporter";
import {
  buildBeforePromptBuildMetadata,
  buildBeforeToolCallMetadata,
  buildToolResultPersistMetadata,
  extractToolResultText,
} from "./metadata.ts";

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

    const logFirewallInput = (
      hookName: string,
      text: string,
      options: ClassifyOptions,
    ) => {
      const toolName = options.toolName ? ` toolName=${options.toolName}` : "";
      console.log(`[firewall] classify input ${hookName} metadata hook=${options.hook}${toolName} textLength=${text.length}`);
      console.log(`[firewall] classify input ${hookName} raw text begin`);
      console.log(text);
      console.log(`[firewall] classify input ${hookName} raw text end`);
    };

    api.on("before_tool_call", async (event, ctx) => {
      const ts = new Date().toISOString();
      try {
        const text = JSON.stringify(event.params);
        const metadata = buildBeforeToolCallMetadata(event, ctx, HookLabel.TOOL_CALL);
        const options: ClassifyOptions = {
          hook: HookLabel.TOOL_CALL,
          toolName: event.toolName,
          metadata,
        };
        logFirewallInput("before_tool_call", text, options);
        const result = await firewall.classify(text, options);
        console.log(`[firewall] before_tool_call result:`, JSON.stringify(result));
        try {
          await exporter.writeEvent({
            source: "tool_call",
            ts,
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

    api.on("tool_result_persist", async (event, ctx) => {
      const ts = new Date().toISOString();
      try {
        const resultText = extractToolResultText(event);
        const toolName = event.toolName ?? ctx?.toolName;
        const metadata = buildToolResultPersistMetadata(event, ctx, HookLabel.TOOL_RESPONSE);
        const options: ClassifyOptions = {
          hook: HookLabel.TOOL_RESPONSE,
          toolName,
          metadata,
        };
        logFirewallInput("tool_result_persist", resultText, options);
        const result = await firewall.classify(resultText, options);
        console.log(`[firewall] tool_result_persist result:`, JSON.stringify(result));
        try {
          await exporter.writeEvent({
            source: "tool_response",
            ts,
            toolName,
            payload: {
              text: resultText,
            },
            firewallResult: result,
          });
        } catch (err) {
          logExporterWarning("tool_result_persist", err);
        }
      } catch (err) {
        console.error(`[firewall] tool_result_persist error:`, err);
      }
    });

    api.on("before_prompt_build", async (event, ctx) => {
      const ts = new Date().toISOString();
      try {
        const text = event?.prompt ?? "";
        if (text) {
          const metadata = buildBeforePromptBuildMetadata(event, ctx, HookLabel.USER_INPUT);
          const options: ClassifyOptions = {
            hook: HookLabel.USER_INPUT,
            metadata,
          };
          logFirewallInput("before_prompt_build", text, options);
          const result = await firewall.classify(text, options);
          console.log(`[firewall] before_prompt_build (USER_INPUT) result:`, JSON.stringify(result));
          try {
            await exporter.writeEvent({
              source: "user_input",
              ts,
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
