import type { PolicyClient } from "./policy-client";
import type { PolicyResponse } from "./types";

interface CacheEntry {
  policy: PolicyResponse;
  fetchedAt: number;
}

interface Logger {
  warn?: (msg: string) => void;
}

const FALLBACK_OPEN: PolicyResponse = { action: "warn", resolved_role: "fallback" };

export class PolicyCache {
  private entries = new Map<string, CacheEntry>();
  private inflight = new Map<string, Promise<PolicyResponse>>();

  constructor(
    private readonly client: PolicyClient,
    private readonly ttlMs: number = 5 * 60_000,
    private readonly logger?: Logger,
  ) {}

  async get(email: string | null): Promise<PolicyResponse> {
    const key = this.keyOf(email);
    const now = Date.now();
    const cached = this.entries.get(key);
    if (cached && now - cached.fetchedAt < this.ttlMs) {
      return cached.policy;
    }

    const existing = this.inflight.get(key);
    if (existing) return existing;

    const promise = (async () => {
      try {
        const fresh = await this.client.fetchPolicy(email);
        this.entries.set(key, { policy: fresh, fetchedAt: Date.now() });
        return fresh;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.logger?.warn?.(`firewall-plugin: policy endpoint unreachable, falling back to warn — ${message}`);
        if (cached) return cached.policy;
        return FALLBACK_OPEN;
      } finally {
        this.inflight.delete(key);
      }
    })();
    this.inflight.set(key, promise);
    return promise;
  }

  invalidate(email: string | null): void {
    this.entries.delete(this.keyOf(email));
  }

  peek(email: string | null): PolicyResponse | undefined {
    return this.entries.get(this.keyOf(email))?.policy;
  }

  private keyOf(email: string | null): string {
    return email === null ? "<none>" : email.toLowerCase();
  }
}
