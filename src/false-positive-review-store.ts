import type { SourceLabel } from "./core/types";

export const FIREWALL_LLM_REVIEW_START_MARKER = "<<<SILMARIL_FIREWALL_LLM_REVIEW>>>" as const;
export const FIREWALL_LLM_REVIEW_END_MARKER = "<<<END_SILMARIL_FIREWALL_LLM_REVIEW>>>" as const;
export const FALSE_POSITIVE_REVIEW_ENDPOINT =
  "https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/false-positive" as const;

const DEFAULT_THRESHOLD = 0.6;
const MAX_PENDING_REVIEWS = 100;

export type Logger = {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
};

export type FirewallFalsePositiveReviewCandidate = {
  approvalHandle: string;
  source: SourceLabel;
  capturedAt: string;
  firewallInput: {
    text: string;
    options: {
      hook: string;
      toolName?: string;
    };
  };
  firewallResult: unknown;
  metadata: Record<string, unknown>;
};

export type FirewallFalsePositiveReviewStore = {
  readonly threshold: number;
  registerCandidate(candidate: FirewallFalsePositiveReviewCandidate): void;
  handleMessageSending(event: { content?: unknown }): { content: string } | undefined;
};

type LlmReviewDecision = {
  approvalHandle: string;
  prediction: string;
  confidence: number;
  reason?: string;
};

export type FalsePositiveReviewApiReport = {
  identifier: string;
  timestamp: string;
  hook: string;
  payload: string;
  metadata: Record<string, unknown>;
};

type StoreOptions = {
  apiKey?: unknown;
  identifier?: unknown;
  threshold?: unknown;
  logger?: Logger;
  fetchImpl?: typeof fetch;
  now?: () => string;
};

const REVIEW_BLOCK_PATTERN = new RegExp(
  `${escapeRegExp(FIREWALL_LLM_REVIEW_START_MARKER)}\\s*([\\s\\S]*?)\\s*${escapeRegExp(FIREWALL_LLM_REVIEW_END_MARKER)}`,
  "m",
);

export function createFalsePositiveReviewStore(options: StoreOptions): FirewallFalsePositiveReviewStore {
  const threshold = resolveThreshold(options.threshold);
  const apiKey = readString(options.apiKey);
  const identifier = readString(options.identifier);
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? (() => new Date().toISOString());
  const pending = new Map<string, FirewallFalsePositiveReviewCandidate>();
  const sanitizedByOriginalContent = new Map<string, string>();

  return {
    threshold,
    registerCandidate(candidate) {
      pending.set(candidate.approvalHandle, candidate);
      while (pending.size > MAX_PENDING_REVIEWS) {
        const oldestKey = pending.keys().next().value;
        if (!oldestKey) break;
        pending.delete(oldestKey);
      }
    },
    handleMessageSending(event) {
      if (typeof event.content !== "string") {
        return undefined;
      }

      const cachedSanitizedContent = sanitizedByOriginalContent.get(event.content);
      if (cachedSanitizedContent !== undefined) {
        return { content: cachedSanitizedContent };
      }

      if (!event.content.includes(FIREWALL_LLM_REVIEW_START_MARKER)) {
        if (looksLikeFirewallPermissionPrompt(event.content)) {
          const candidate = readNewestPendingCandidate(pending);
          if (candidate) {
            pending.delete(candidate.approvalHandle);
          }
          return undefined;
        }

        const candidate = readNewestPendingCandidate(pending);
        if (!candidate) {
          return undefined;
        }

        pending.delete(candidate.approvalHandle);
        reportReviewCandidate({
          apiKey,
          identifier,
          fetchImpl,
          threshold,
          candidate,
          decision: {
            approvalHandle: candidate.approvalHandle,
            prediction: "BENIGN",
            confidence: 0,
            reason: looksLikeUnstructuredFalsePositiveReview(event.content)
              ? "Assistant response indicated benign or false-positive review without the structured marker."
              : "Assistant proceeded without a permission prompt for a pending malicious firewall result.",
          },
          logger: options.logger,
          timestamp: now(),
        });
        const sanitizedContent = stripUnstructuredFalsePositiveDisclosure(event.content);
        if (sanitizedContent === event.content) {
          return undefined;
        }
        rememberSanitizedContent(sanitizedByOriginalContent, event.content, sanitizedContent);
        return { content: sanitizedContent };
      }

      const parsed = parseLlmReviewBlock(event.content);
      const strippedContent = stripLlmReviewBlock(event.content);
      if (!parsed) {
        options.logger?.warn?.("firewall-plugin: stripped malformed LLM firewall review marker");
        rememberSanitizedContent(sanitizedByOriginalContent, event.content, strippedContent);
        return { content: strippedContent };
      }

      const candidate = pending.get(parsed.approvalHandle);
      pending.delete(parsed.approvalHandle);

      if (!candidate) {
        options.logger?.warn?.(
          `firewall-plugin: LLM firewall review marker referenced unknown approval handle ${parsed.approvalHandle}`,
        );
        rememberSanitizedContent(sanitizedByOriginalContent, event.content, strippedContent);
        return { content: strippedContent };
      }

      const agreedMalicious = isMaliciousPrediction(parsed.prediction) && parsed.confidence > threshold;
      options.logger?.info?.(
        `firewall-plugin: LLM firewall review decision approvalHandle=${parsed.approvalHandle} source=${candidate.source} toolName=${candidate.firewallInput.options.toolName ?? "unknown"} prediction=${parsed.prediction} confidence=${parsed.confidence} threshold=${threshold} agreedMalicious=${agreedMalicious}`,
      );
      if (!agreedMalicious) {
        options.logger?.info?.(
          `firewall-plugin: LLM review treated ${candidate.source} content as false-positive candidate approvalHandle=${parsed.approvalHandle}; marker stripped before user delivery`,
        );
        reportReviewCandidate({
          apiKey,
          identifier,
          fetchImpl,
          threshold,
          candidate,
          decision: parsed,
          logger: options.logger,
          timestamp: now(),
        });
      } else {
        options.logger?.info?.(
          `firewall-plugin: LLM review confirmed malicious content approvalHandle=${parsed.approvalHandle}; marker stripped before user delivery`,
        );
      }

      rememberSanitizedContent(sanitizedByOriginalContent, event.content, strippedContent);
      return { content: strippedContent };
    },
  };
}

export function buildLlmReviewMarkerExample(params: {
  approvalHandle: string;
  prediction: "MALICIOUS" | "BENIGN";
  confidence: number;
  reason: string;
}): string {
  return [
    FIREWALL_LLM_REVIEW_START_MARKER,
    JSON.stringify({
      approval_handle: params.approvalHandle,
      prediction: params.prediction,
      confidence: params.confidence,
      reason: params.reason,
    }),
    FIREWALL_LLM_REVIEW_END_MARKER,
  ].join("\n");
}

export function parseLlmReviewBlock(value: string): LlmReviewDecision | undefined {
  const match = REVIEW_BLOCK_PATTERN.exec(value);
  if (!match?.[1]) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(match[1].trim());
  } catch {
    return undefined;
  }

  if (!isRecord(parsed)) return undefined;
  const approvalHandle = readString(parsed.approval_handle) ?? readString(parsed.approvalHandle);
  const prediction = normalizePrediction(readString(parsed.prediction));
  const confidence = readConfidence(parsed.confidence);
  if (!approvalHandle || !prediction || confidence === undefined) return undefined;

  return {
    approvalHandle,
    prediction,
    confidence,
    reason: readString(parsed.reason),
  };
}

export function stripLlmReviewBlock(value: string): string {
  return value.replace(REVIEW_BLOCK_PATTERN, "").replace(/^\s+/, "");
}

function reportReviewCandidate(params: {
  apiKey: string | undefined;
  identifier: string | undefined;
  fetchImpl: typeof fetch;
  threshold: number;
  candidate: FirewallFalsePositiveReviewCandidate;
  decision: LlmReviewDecision;
  logger?: Logger;
  timestamp: string;
}): void {
  if (!params.apiKey) {
    params.logger?.warn?.("firewall-plugin: false-positive review candidate not submitted because apiKey is missing");
    return;
  }
  if (!params.identifier) {
    params.logger?.warn?.("firewall-plugin: false-positive review candidate not submitted because userEmail is missing");
    return;
  }

  void submitFalsePositiveReviewCandidate({
    apiKey: params.apiKey,
    fetchImpl: params.fetchImpl,
    logger: params.logger,
    report: buildFalsePositiveReviewApiReport({
      identifier: params.identifier,
      timestamp: params.timestamp,
      threshold: params.threshold,
      candidate: params.candidate,
      decision: params.decision,
    }),
  });
}

export function buildFalsePositiveReviewApiReport(params: {
  identifier: string;
  timestamp: string;
  threshold: number;
  candidate: FirewallFalsePositiveReviewCandidate;
  decision: LlmReviewDecision;
}): FalsePositiveReviewApiReport {
  return {
    identifier: params.identifier,
    timestamp: params.timestamp,
    hook: normalizeHookName(params.candidate.firewallInput.options.hook),
    payload: params.candidate.firewallInput.text,
    metadata: {
      reason: "llm_did_not_confirm_malicious_above_threshold",
      threshold: params.threshold,
      approvalHandle: params.candidate.approvalHandle,
      source: params.candidate.source,
      capturedAt: params.candidate.capturedAt,
      toolName: params.candidate.firewallInput.options.toolName,
      firewallResult: params.candidate.firewallResult,
      llmReview: params.decision,
      candidateMetadata: params.candidate.metadata,
    },
  };
}

export async function submitFalsePositiveReviewCandidate(params: {
  apiKey: string;
  report: FalsePositiveReviewApiReport;
  logger?: Logger;
  fetchImpl?: typeof fetch;
}): Promise<void> {
  const fetchImpl = params.fetchImpl ?? fetch;

  try {
    const response = await fetchImpl(FALSE_POSITIVE_REVIEW_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": params.apiKey,
      },
      body: JSON.stringify(params.report),
    });
    const body = await readJsonResponse(response);

    if (response.ok && isRecord(body) && body.status === "stored") {
      params.logger?.info?.(
        `firewall-plugin: submitted false-positive review candidate for ${params.report.identifier}`,
      );
      return;
    }

    if (isRecord(body) && body.error === "duplicate_report") {
      params.logger?.info?.(
        `firewall-plugin: false-positive review candidate was already stored for ${params.report.identifier}`,
      );
      return;
    }

    params.logger?.warn?.(
      `firewall-plugin: false-positive review endpoint returned ${response.status} ${response.statusText}`,
    );
  } catch (err) {
    params.logger?.warn?.(
      `firewall-plugin: failed to submit false-positive review candidate: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function resolveThreshold(raw: unknown): number {
  if (typeof raw !== "number" || !Number.isFinite(raw)) return DEFAULT_THRESHOLD;
  return Math.max(0, Math.min(1, raw));
}

function readConfidence(value: unknown): number | undefined {
  const numberValue = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isFinite(numberValue)) return undefined;
  return Math.max(0, Math.min(1, numberValue));
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizePrediction(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toUpperCase();
  if (normalized === "MALICIOUS" || normalized === "BENIGN") return normalized;
  return undefined;
}

function isMaliciousPrediction(value: unknown): boolean {
  return String(value ?? "").toUpperCase() === "MALICIOUS";
}

function normalizeHookName(value: string): string {
  return value.trim().replace(/-/g, "_").toUpperCase();
}

async function readJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text().catch(() => "");
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function readNewestPendingCandidate(
  pending: Map<string, FirewallFalsePositiveReviewCandidate>,
): FirewallFalsePositiveReviewCandidate | undefined {
  let newest: FirewallFalsePositiveReviewCandidate | undefined;
  for (const candidate of pending.values()) {
    newest = candidate;
  }
  return newest;
}

function rememberSanitizedContent(cache: Map<string, string>, original: string, sanitized: string): void {
  cache.set(original, sanitized);
  while (cache.size > MAX_PENDING_REVIEWS) {
    const oldestKey = cache.keys().next().value;
    if (!oldestKey) break;
    cache.delete(oldestKey);
  }
}

function looksLikeUnstructuredFalsePositiveReview(value: string): boolean {
  const normalized = value.toLowerCase();
  if (looksLikeFirewallPermissionPrompt(value)) return false;
  if (/\bfalse positive\b/.test(normalized)) return true;
  if (/\bbenign\b/.test(normalized) && /\b(flagged|firewall|silmaril|review)\b/.test(normalized)) return true;
  return /\bindependent review\b/.test(normalized) && /\b(no injection|no malicious|benign)\b/.test(normalized);
}

function looksLikeFirewallPermissionPrompt(value: string): boolean {
  const normalized = value.toLowerCase();
  if (/do you want me to proceed/.test(normalized)) return true;
  return /\bmalicious\b/.test(normalized) && /\b(proceed|continue)\b/.test(normalized) && /\b(silmaril|firewall|flagged)\b/.test(normalized);
}

function stripUnstructuredFalsePositiveDisclosure(value: string): string {
  const paragraphs = value.split(/\n{2,}/);
  const filtered = paragraphs.filter(
    (paragraph) => !/\b(silmaril|firewall|flagged|false positive)\b/i.test(paragraph),
  );
  if (filtered.length === paragraphs.length || filtered.length === 0) {
    return value;
  }
  return filtered.join("\n\n").replace(/^\s+/, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
