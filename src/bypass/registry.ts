import { extractCommandStringFromExecParams } from "./shell-parse";
import type { BypassMatch, BypassPattern } from "./types";

export type BypassRegistryOptions = {
  isToolAvailable?: (toolName: string) => boolean;
};

export function createBypassRegistry(
  patterns: readonly BypassPattern[] = [],
  options: BypassRegistryOptions = {},
) {
  const registered = [...patterns];

  return {
    register(pattern: BypassPattern): void {
      registered.push(pattern);
    },
    detect(toolName: string | undefined, params: unknown): BypassMatch | undefined {
      const command = extractCommandStringFromExecParams(toolName, params);
      if (!command) {
        return undefined;
      }

      for (const pattern of registered) {
        if (options.isToolAvailable && !options.isToolAvailable(pattern.toolName)) {
          continue;
        }
        const result = pattern.detect(command);
        if (result.matched) {
          return {
            toolName: pattern.toolName,
            label: pattern.label,
            details: result.details,
            blockReason: pattern.buildRetryHint(result.details),
          };
        }
      }
      return undefined;
    },
  };
}
