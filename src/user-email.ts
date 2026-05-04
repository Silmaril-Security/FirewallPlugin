import type { ClassifyOptions } from "@silmaril-security/sdk";

export const USER_EMAIL_ENV_VAR = "USER_EMAIL" as const;

export function resolveUserEmail(configValue: unknown, env: NodeJS.ProcessEnv = process.env): string | undefined {
  return readNonEmptyString(configValue) ?? readNonEmptyString(env[USER_EMAIL_ENV_VAR]);
}

export function withUserEmailClassifyOptions(
  options: ClassifyOptions,
  userEmail: string | undefined,
): ClassifyOptions {
  if (!userEmail) {
    return options;
  }

  return {
    ...options,
    metadata: {
      ...readMetadata(options.metadata),
      user_email: userEmail,
    },
  };
}

function readNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function readMetadata(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? { ...value } : {};
}
