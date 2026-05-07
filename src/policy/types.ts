export type PolicyAction = "warn" | "block";

export interface PolicyResponse {
  action: PolicyAction;
  resolved_role?: string;
}

export type Trigger = "user_input" | "tool_call" | "tool_result";

export interface ClassifyResult {
  prediction: string;
  score: number;
}

export interface DecisionInput {
  policyAction: PolicyAction;
  classifyResult: ClassifyResult;
  sessionId: string | undefined;
  isApprovalPrompt: boolean;
}

export type EngineDecision =
  | { kind: "noop" }
  | { kind: "warn" }
  | { kind: "block" };

export interface IdentityResult {
  email: string | null;
  source: "config" | "env" | "git" | "fallback";
}
