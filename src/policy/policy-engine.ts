import type {
  DecisionInput,
  EngineDecision,
} from "./types";
import type { SessionLock } from "./session-lock";

export function decide(input: DecisionInput, lock: SessionLock): EngineDecision {
  if (lock.isLocked(input.sessionId)) {
    return { kind: "block" };
  }

  if (input.isApprovalPrompt) {
    if (input.policyAction === "warn") {
      return { kind: "noop" };
    }
    lock.lock(input.sessionId);
    return { kind: "block" };
  }

  if (!isMalicious(input.classifyResult.prediction)) {
    return { kind: "noop" };
  }

  if (input.policyAction === "warn") {
    return { kind: "warn" };
  }

  lock.lock(input.sessionId);
  return { kind: "block" };
}

function isMalicious(prediction: string): boolean {
  return String(prediction ?? "").toUpperCase() === "MALICIOUS";
}

export interface ToolCallTranslateParams {
  warnDescription: string;
  blockReason: string;
  pluginId: string;
  toolName?: string;
  onApprovalResolution?: (decision: string) => void;
}

export type ToolCallReturn =
  | undefined
  | { block: true; blockReason: string }
  | {
      requireApproval: {
        title: string;
        description: string;
        severity: "warning";
        timeoutMs: number;
        timeoutBehavior: "deny";
        pluginId: string;
        onResolution: (decision: string) => void;
      };
    };

export function translateForToolCall(
  decision: EngineDecision,
  params: ToolCallTranslateParams,
): ToolCallReturn {
  if (decision.kind === "noop") return undefined;
  if (decision.kind === "warn") {
    return {
      requireApproval: {
        title: `Silmaril Firewall: malicious ${params.toolName ?? "tool"} call`,
        description: params.warnDescription,
        severity: "warning",
        timeoutMs: 60_000,
        timeoutBehavior: "deny",
        pluginId: params.pluginId,
        onResolution: params.onApprovalResolution ?? (() => {}),
      },
    };
  }
  return { block: true, blockReason: params.blockReason };
}

export interface ToolResultTranslateParams<TMessage> {
  warnMessage: TMessage;
  blockMessage: TMessage;
}

export type ToolResultReturn<TMessage> = undefined | { message: TMessage };

export function translateForToolResult<TMessage>(
  decision: EngineDecision,
  params: ToolResultTranslateParams<TMessage>,
): ToolResultReturn<TMessage> {
  if (decision.kind === "noop") return undefined;
  if (decision.kind === "warn") return { message: params.warnMessage };
  return { message: params.blockMessage };
}

export interface PromptBuildTranslateParams {
  warnGuard: { appendSystemContext: string; prependContext: string };
  blockGuard: { appendSystemContext: string; prependContext: string };
}

export type PromptBuildReturn =
  | undefined
  | { appendSystemContext: string; prependContext: string };

export function translateForPromptBuild(
  decision: EngineDecision,
  params: PromptBuildTranslateParams,
): PromptBuildReturn {
  if (decision.kind === "noop") return undefined;
  if (decision.kind === "warn") return params.warnGuard;
  return params.blockGuard;
}
