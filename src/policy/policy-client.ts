import type { PolicyResponse } from "./types";

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
