import type { BypassPattern } from "./types";

export const EMAIL_BYPASS_PATTERNS: readonly BypassPattern[] = [
  createGmailPattern({
    toolName: "gmail_message_read",
    label: "Gmail message direct read",
    requiredTool: "gmail_message_read",
    regex: /gmail\/v1\/users\/me\/messages\/([A-Za-z0-9_-]+)/i,
  }),
  createGmailPattern({
    toolName: "gmail_thread_read",
    label: "Gmail thread direct read",
    requiredTool: "gmail_thread_read",
    regex: /gmail\/v1\/users\/me\/threads\/([A-Za-z0-9_-]+)/i,
  }),
  {
    toolName: "gmail_search",
    label: "Gmail search direct read",
    detect(command) {
      return /gmail\/v1\/users\/me\/messages\?q=/i.test(command)
        ? { matched: true, details: {} }
        : { matched: false };
    },
    buildRetryHint(details) {
      return buildRetryHint("gmail_search", details);
    },
  },
];

function createGmailPattern(params: {
  toolName: string;
  label: string;
  requiredTool: string;
  regex: RegExp;
}): BypassPattern {
  return {
    toolName: params.toolName,
    label: params.label,
    detect(command) {
      const match = params.regex.exec(command);
      return match?.[1] ? { matched: true, details: { id: match[1] } } : { matched: false };
    },
    buildRetryHint(details) {
      return buildRetryHint(params.requiredTool, details);
    },
  };
}

function buildRetryHint(requiredTool: string, details: Record<string, unknown>): string {
  return `
Gmail reads must go through the Silmaril ${requiredTool} wrapper before email content reaches the model.
source: before_tool_call
required_tool: ${requiredTool}
identifier: ${typeof details.id === "string" ? details.id : "unknown"}

Retry by calling ${requiredTool} with equivalent structured parameters.
Do not use curl, wget, shell commands, raw Gmail API calls, or generic browser fetches to read Gmail content.
`.trim();
}
