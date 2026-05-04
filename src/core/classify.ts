import type { HookLabel } from "@silmaril-security/sdk";
import type { FirewallClassifier, Logger } from "./types";

export type ClassificationResult = {
  prediction: string;
  score: number;
  [key: string]: unknown;
};

export type RunClassificationInput = {
  firewall: FirewallClassifier;
  text: string;
  hook: HookLabel;
  toolName?: string;
  metadata?: Record<string, unknown>;
  logger?: Logger;
  signal?: AbortSignal;
};

export async function runClassification(input: RunClassificationInput): Promise<ClassificationResult> {
  throwIfAborted(input.signal);

  try {
    return await input.firewall.classify(input.text, {
      hook: input.hook,
      ...(input.toolName ? { toolName: input.toolName } : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    });
  } catch (err) {
    throwIfAbortError(err);
    input.logger?.warn?.("firewall classification failed; treating content as BENIGN for this wrapper call", err);
    return {
      prediction: "BENIGN",
      score: 0,
      classifierFailed: true,
    };
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) {
    return;
  }

  throw signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

function throwIfAbortError(err: unknown): never | void {
  if (err instanceof DOMException && err.name === "AbortError") {
    throw err;
  }

  if (err instanceof Error && err.name === "AbortError") {
    throw err;
  }
}
