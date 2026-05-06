import type { HookLabel } from "@silmaril-security/sdk";
import {
  buildLlmReviewMarkerExample,
  type FirewallFalsePositiveReviewStore,
} from "../false-positive-review-store";
import { buildApprovalHandle } from "./approval-handle";
import { buildSystemContextBlock, wrapUntrustedContent } from "./markers";
import type { WrapperContext } from "./types";

export type FirewallResult = {
  prediction: string;
  score: number;
  [key: string]: unknown;
};

export type GuardedPayloadInput = {
  ctx: WrapperContext;
  contentText: string;
  contentHash: string;
  urlHash?: string;
  contentNoun: string;
  identityFields: Record<string, unknown>;
  identityLines: readonly string[];
  firewallResult: FirewallResult;
  hook: HookLabel;
  tookMs: number;
  llmReview?: { thresholdValue: number; markerExample: string };
  falsePositiveReview?: {
    store: FirewallFalsePositiveReviewStore;
    firewallInput: {
      text: string;
      options: {
        hook: HookLabel | string;
        toolName?: string;
      };
    };
    metadata?: Record<string, unknown>;
  };
  sanitizedReason?: string;
};

export type BenignPayloadInput = {
  ctx: WrapperContext;
  text: string;
  rawLength: number;
  contentHash: string;
  urlHash?: string;
  identityFields: Record<string, unknown>;
  firewallResult: FirewallResult;
  hook: HookLabel;
  tookMs: number;
  truncated: boolean;
};

export function buildGuardedPayload(input: GuardedPayloadInput): Record<string, unknown> {
  const approvalHandle = buildApprovalHandle(input.ctx.source, input.contentHash);
  const llmReview = input.llmReview ?? buildFalsePositiveReview(input, approvalHandle);
  registerFalsePositiveCandidate(input, approvalHandle);
  const systemContext = buildSystemContextBlock({
    ctx: input.ctx,
    approvalHandle,
    contentHash: input.contentHash,
    urlHash: input.urlHash,
    prediction: input.firewallResult.prediction,
    score: input.firewallResult.score,
    contentNoun: input.contentNoun,
    identityLines: input.identityLines,
    llmReview,
  });
  const untrustedContent = wrapUntrustedContent({
    ctx: input.ctx,
    value: input.contentText,
    approvalHandle,
  });
  const text = `${systemContext}\n\n${untrustedContent}`;

  return {
    ...input.identityFields,
    source: input.ctx.source,
    externalContent: {
      untrusted: false,
      source: "silmaril-firewall",
      wrapped: false,
    },
    firewall: {
      blocked: true,
      inspected: true,
      prediction: input.firewallResult.prediction,
      score: input.firewallResult.score,
      hook: input.hook,
      toolName: input.ctx.toolName,
      sanitizedReason:
        input.sanitizedReason ?? `Firewall classified ${input.contentNoun} as MALICIOUS.`,
      contentHash: input.contentHash,
      ...(input.urlHash ? { urlHash: input.urlHash } : {}),
      rawContentWithheld: true,
      extractedContentIncluded: true,
      approvalStatus: "pending",
      approvalHandle,
      ...(llmReview
        ? {
            llmReviewRequired: true,
            llmReviewThreshold: llmReview.thresholdValue,
          }
        : {}),
    },
    system_context: systemContext,
    truncated: false,
    length: text.length,
    rawLength: input.contentText.length,
    wrappedLength: text.length,
    fetchedAt: new Date().toISOString(),
    tookMs: input.tookMs,
    text,
  };
}

function buildFalsePositiveReview(
  input: GuardedPayloadInput,
  approvalHandle: string,
): { thresholdValue: number; markerExample: string } | undefined {
  const store = input.falsePositiveReview?.store;
  if (!store) {
    return undefined;
  }
  return {
    thresholdValue: store.threshold,
    markerExample: buildLlmReviewMarkerExample({
      approvalHandle,
      prediction: "MALICIOUS",
      confidence: 0.82,
      reason: "Hidden text attempts to override instructions or exfiltrate secrets.",
    }),
  };
}

function registerFalsePositiveCandidate(input: GuardedPayloadInput, approvalHandle: string): void {
  const review = input.falsePositiveReview;
  if (!review) {
    return;
  }

  review.store.registerCandidate({
    approvalHandle,
    source: input.ctx.source,
    capturedAt: new Date().toISOString(),
    firewallInput: {
      text: review.firewallInput.text,
      options: {
        hook: String(review.firewallInput.options.hook),
        toolName: review.firewallInput.options.toolName,
      },
    },
    firewallResult: input.firewallResult,
    metadata: {
      source: input.ctx.source,
      toolName: input.ctx.toolName,
      contentHash: input.contentHash,
      ...(input.urlHash ? { urlHash: input.urlHash } : {}),
      tookMs: input.tookMs,
      ...(review.metadata ?? {}),
    },
  });
}

export function buildBenignPayload(input: BenignPayloadInput): Record<string, unknown> {
  return {
    ...input.identityFields,
    source: input.ctx.source,
    externalContent: {
      untrusted: true,
      source: input.ctx.toolName,
      wrapped: true,
      firewallProvider: "silmaril-firewall",
    },
    firewall: {
      inspected: true,
      prediction: input.firewallResult.prediction,
      score: input.firewallResult.score,
      hook: input.hook,
      toolName: input.ctx.toolName,
      contentHash: input.contentHash,
      ...(input.urlHash ? { urlHash: input.urlHash } : {}),
    },
    truncated: input.truncated,
    length: input.text.length,
    rawLength: input.rawLength,
    wrappedLength: input.text.length,
    fetchedAt: new Date().toISOString(),
    tookMs: input.tookMs,
    text: input.text,
  };
}
