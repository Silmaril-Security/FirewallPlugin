const SHELL_TOOL_NAMES = new Set(["bash", "exec", "shell"]);

export function extractCommandStringFromExecParams(
  toolName: string | undefined,
  params: unknown,
): string | undefined {
  if (!toolName || !SHELL_TOOL_NAMES.has(toolName)) {
    return undefined;
  }
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    return undefined;
  }

  const record = params as Record<string, unknown>;
  for (const key of ["command", "cmd", "script"]) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return value;
    }
  }
  return undefined;
}
