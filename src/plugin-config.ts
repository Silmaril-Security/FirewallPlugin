import type { Logger } from "./core";

export type ParsedPluginConfig = {
  apiKey?: string;
  silmarilApiKey?: string;
  apiUrl?: string;
  userEmail?: string;
  falsePositiveReportUrl?: string;
  enableWebFetchWrapper: boolean;
  llmFalsePositiveReviewThreshold?: number;
  githubToken?: string;
  google?: {
    clientId: string;
    clientSecret: string;
    refreshToken: string;
  };
  enableGitHubWrappers: {
    issue: boolean;
    pr: boolean;
    prDiff: boolean;
    file: boolean;
    discussion: boolean;
    release: boolean;
  };
  enableGmailWrappers: {
    message: boolean;
    thread: boolean;
    search: boolean;
  };
};

export function parsePluginConfig(raw: unknown, logger?: Logger): ParsedPluginConfig {
  const record = isRecord(raw) ? raw : {};
  const apiKey = readString(record.apiKey);
  const silmarilApiKey = readString(record.silmarilApiKey) ?? apiKey;
  const apiUrl = readString(record.apiUrl);

  if (!silmarilApiKey || !apiUrl) {
    logger?.warn?.("firewall-plugin: apiKey or apiUrl missing from plugin config");
  }

  return {
    apiKey,
    silmarilApiKey,
    apiUrl,
    userEmail: readString(record.userEmail) ?? readString(record.USER_EMAIL),
    falsePositiveReportUrl: readString(record.falsePositiveReportUrl),
    enableWebFetchWrapper: record.enableWebFetchWrapper === true,
    llmFalsePositiveReviewThreshold: readNumberInRange(record.llmFalsePositiveReviewThreshold, 0, 1),
    githubToken: readString(record.githubToken),
    google: readGoogleConfig(record.google),
    enableGitHubWrappers: {
      issue: readBoolean(getNested(record, ["enableGitHubWrappers", "issue"]), true),
      pr: readBoolean(getNested(record, ["enableGitHubWrappers", "pr"]), false),
      prDiff: readBoolean(getNested(record, ["enableGitHubWrappers", "prDiff"]), false),
      file: readBoolean(getNested(record, ["enableGitHubWrappers", "file"]), false),
      discussion: readBoolean(getNested(record, ["enableGitHubWrappers", "discussion"]), false),
      release: readBoolean(getNested(record, ["enableGitHubWrappers", "release"]), false),
    },
    enableGmailWrappers: {
      message: readBoolean(getNested(record, ["enableGmailWrappers", "message"]), false),
      thread: readBoolean(getNested(record, ["enableGmailWrappers", "thread"]), false),
      search: readBoolean(getNested(record, ["enableGmailWrappers", "search"]), false),
    },
  };
}

export function hasCompleteGoogleConfig(config: ParsedPluginConfig): boolean {
  return !!config.google;
}

function readGoogleConfig(value: unknown): ParsedPluginConfig["google"] {
  if (!isRecord(value)) return undefined;
  const clientId = readString(value.clientId);
  const clientSecret = readString(value.clientSecret);
  const refreshToken = readString(value.refreshToken);
  if (!clientId || !clientSecret || !refreshToken) return undefined;
  return { clientId, clientSecret, refreshToken };
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readNumberInRange(value: unknown, min: number, max: number): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  return Math.max(min, Math.min(max, value));
}

function getNested(value: Record<string, unknown>, path: readonly string[]): unknown {
  let current: unknown = value;
  for (const part of path) {
    if (!isRecord(current)) return undefined;
    current = current[part];
  }
  return current;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
