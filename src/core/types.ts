import type { HookLabel } from "@silmaril-security/sdk";

export type SourceLabel =
  | "web_fetch"
  | "github_issue"
  | "github_pr"
  | "github_pr_diff"
  | "github_file"
  | "github_discussion"
  | "github_release"
  | "gmail_message"
  | "gmail_thread"
  | "gmail_search";

export type ContentMarkerKind = "WEB" | "GITHUB" | "GMAIL";

export type Logger = {
  info?: (message: string) => void;
  warn?: (message: string, error?: unknown) => void;
  error?: (message: string, error?: unknown) => void;
};

export type FirewallClassifier = {
  classify: (
    text: string,
    options: {
      hook: HookLabel;
      toolName?: string;
      metadata?: Record<string, unknown>;
    },
  ) => Promise<{ prediction: string; score: number; [key: string]: unknown }>;
};

export type WrapperContext = {
  toolName: string;
  source: SourceLabel;
  markerKind: ContentMarkerKind;
  firewall: FirewallClassifier;
  logger?: Logger;
};
