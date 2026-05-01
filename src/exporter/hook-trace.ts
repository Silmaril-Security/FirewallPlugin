import { TRACE_HOOKS } from "./types";
import type { ExporterLogger, FirewallExporter, PluginHookName } from "./types";

type PluginApi = {
  on?: (eventName: string, handler: (...args: unknown[]) => Promise<void> | void) => void;
};

const LIFECYCLE_HOOKS = new Set<PluginHookName>(["gateway_start", "gateway_stop"]);

export function registerHookTraceHandlers(
  api: PluginApi,
  exporter: FirewallExporter,
  logger: ExporterLogger,
): void {
  for (const hookName of TRACE_HOOKS) {
    if (LIFECYCLE_HOOKS.has(hookName)) {
      continue;
    }

    try {
      api.on?.(hookName, (event, ctx) => {
        void writeHookTraceEvent(exporter, hookName, event, ctx, logger);
      });
    } catch (err) {
      logger.warn(`failed to register trace exporter hook ${hookName}`, err);
    }
  }
}

export async function writeHookTraceEvent(
  exporter: FirewallExporter,
  hookName: PluginHookName,
  event: unknown,
  ctx: unknown,
  logger: ExporterLogger,
): Promise<void> {
  try {
    await exporter.writeEvent({
      source: "hook_event",
      hookName,
      payload: {
        event,
        ctx,
      },
    });
  } catch (err) {
    logger.warn(`failed to export trace hook ${hookName}`, err);
  }
}
