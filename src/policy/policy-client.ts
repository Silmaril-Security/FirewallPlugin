import type { PolicyAction, PolicyResponse } from "./types";

export interface PolicyClient {
  fetchPolicy(email: string | null): Promise<PolicyResponse>;
}

const ADMIN_EMAILS: ReadonlySet<string> = new Set([
  "gary@silmaril.dev",
]);

export function createHardcodedPolicyClient(): PolicyClient {
  return {
    async fetchPolicy(email: string | null): Promise<PolicyResponse> {
      if (email && ADMIN_EMAILS.has(email.toLowerCase())) {
        return { action: "warn", resolved_role: "admin" };
      }
      return { action: "block", resolved_role: "user" };
    },
  };
}

const ALLOWED_ACTIONS: ReadonlySet<PolicyAction> = new Set<PolicyAction>(["warn", "block"]);

// Per the policy-API contract every response — success OR error — has a valid
// PolicyResponse body. We trust the body verbatim regardless of HTTP status:
//   - 200 -> the row's policy (admin/warn or user/block)
//   - 4xx -> {block,user} (deny: bad key, malformed input, etc.)
//   - 5xx -> {warn,fallback} (fail-open per API)
// We only throw when the response is not parseable as a PolicyResponse
// (network failure, non-JSON, missing/invalid action). PolicyCache catches
// those throws and synthesizes its own {warn,fallback}.
export function createHttpPolicyClient(
  endpoint: string,
  apiKey: string,
  fetchImpl: typeof fetch = fetch,
): PolicyClient {
  if (!endpoint) throw new Error("createHttpPolicyClient: endpoint is required");
  if (!apiKey) throw new Error("createHttpPolicyClient: apiKey is required");

  return {
    async fetchPolicy(email: string | null): Promise<PolicyResponse> {
      const response = await fetchImpl(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
        },
        body: JSON.stringify({ email }),
        redirect: "error",
      });

      let parsed: unknown;
      try {
        parsed = await response.json();
      } catch (err) {
        throw new Error(
          `policy endpoint returned non-JSON body (HTTP ${response.status}): ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (!parsed || typeof parsed !== "object") {
        throw new Error(`policy endpoint returned non-object body (HTTP ${response.status})`);
      }
      const body = parsed as { action?: unknown; resolved_role?: unknown };
      if (typeof body.action !== "string" || !ALLOWED_ACTIONS.has(body.action as PolicyAction)) {
        throw new Error(
          `policy endpoint returned invalid action (HTTP ${response.status}): ${String(body.action)}`,
        );
      }
      const result: PolicyResponse = { action: body.action as PolicyAction };
      if (typeof body.resolved_role === "string" && body.resolved_role.length > 0) {
        result.resolved_role = body.resolved_role;
      }
      return result;
    },
  };
}
