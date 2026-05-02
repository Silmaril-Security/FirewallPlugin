// index.ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Firewall, HookLabel } from "@silmaril-security/sdk";
import { createFirewallExporter } from "./src/exporter/register-exporter";
import {
  FALSE_NEGATIVE_TOOL_NAME,
  createFalseNegativeReportTool,
  resolveFalseNegativeReportUrl,
  validateAndBuildFalseNegativeReport,
} from "./src/false-positive-reporting";

export default definePluginEntry({
  id: "firewall-plugin",
  name: "Firewall Plugin",
  description: "Adds a firewall to OpenClaw",
  register(api) {
    const apiKey = api.pluginConfig?.apiKey;
    const silmarilApiKey = api.pluginConfig?.silmarilApiKey ?? apiKey;
    const apiUrl = api.pluginConfig?.apiUrl;
    const falseNegativeReportUrl = resolveFalseNegativeReportUrl(api.pluginConfig?.falsePositiveReportUrl);

    api.registerTool(
      createFalseNegativeReportTool({
        reportUrl: falseNegativeReportUrl,
        logger: api.logger,
      }),
      { optional: true },
    );

    api.on(
      "before_tool_call",
      async (event) => {
        if (event.toolName !== FALSE_NEGATIVE_TOOL_NAME) {
          return;
        }

        const validation = validateAndBuildFalseNegativeReport(event.params);
        if (!validation.ok) {
          return {
            block: true,
            blockReason: `False-negative candidate report blocked: ${validation.errors.join("; ")}`,
          };
        }

        return {
          requireApproval: {
            title: "Submit firewall false-negative candidate",
            description:
              "POST a sanitized suspected_false_negative candidate to the configured firewall review queue. This does not create a ground-truth label.",
            severity: "warning",
            timeoutMs: 60_000,
            timeoutBehavior: "deny",
            pluginId: "firewall-plugin",
            onResolution(decision) {
              api.logger?.info?.(`firewall-plugin: false-negative report approval resolved as ${decision}`);
            },
          },
        };
      },
      { priority: 1000 },
    );

    if (!apiKey || !apiUrl) {
      api.logger.warn("firewall-plugin: apiKey or apiUrl missing - classifier hooks disabled");
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
      options: { hook: HookLabel; toolName?: string },
    ) => {
      const toolName = options.toolName ? ` toolName=${options.toolName}` : "";
      console.log(`[firewall] classify input ${hookName} metadata hook=${options.hook}${toolName} textLength=${text.length}`);
      console.log(`[firewall] classify input ${hookName} raw text begin`);
      console.log(text);
      console.log(`[firewall] classify input ${hookName} raw text end`);
    };

    api.on("before_tool_call", async (event) => {
      if (event.toolName === FALSE_NEGATIVE_TOOL_NAME) {
        return;
      }

      const ts = new Date().toISOString();
      try {
        const text = JSON.stringify(event.params);
        const options = {
          hook: HookLabel.TOOL_CALL,
          toolName: event.toolName,
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

    api.on("tool_result_persist", async (event, _ctx) => {
      const ts = new Date().toISOString();
      try {
        const resultText = event?.message?.content
          ?.map((c: { text?: string }) => c.text ?? "")
          .join("\n") ?? "";
        const options = {
          hook: HookLabel.TOOL_RESPONSE,
          toolName: event.toolName,
        };
        logFirewallInput("tool_result_persist", resultText, options);
        const result = await firewall.classify(resultText, options);
        console.log(`[firewall] tool_result_persist result:`, JSON.stringify(result));
        try {
          await exporter.writeEvent({
            source: "tool_response",
            ts,
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
      const ts = new Date().toISOString();
      try {
        const text = event?.prompt ?? "";
        if (text) {
          const options = {
            hook: HookLabel.USER_INPUT,
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
