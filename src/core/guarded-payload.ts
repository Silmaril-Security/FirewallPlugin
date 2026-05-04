import type { HookLabel } from "@silmaril-security/sdk";
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
  const systemContext = buildSystemContextBlock({
    ctx: input.ctx,
    approvalHandle,
    contentHash: input.contentHash,
    urlHash: input.urlHash,
    prediction: input.firewallResult.prediction,
    score: input.firewallResult.score,
    contentNoun: input.contentNoun,
    identityLines: input.identityLines,
    llmReview: input.llmReview,
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
      ...(input.llmReview
        ? {
            llmReviewRequired: true,
            llmReviewThreshold: input.llmReview.thresholdValue,
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
