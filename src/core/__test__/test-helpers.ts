import assert from "node:assert/strict";
import type { HookLabel } from "@silmaril-security/sdk";
import type { ContentMarkerKind, FirewallClassifier, Logger, SourceLabel } from "../types";

export type FirewallCapture = {
  calls: Array<{
    text: string;
    options: {
      hook: HookLabel;
      toolName?: string;
      metadata?: Record<string, unknown>;
    };
  }>;
};

export function createFakeFirewall(params: {
  prediction?: string;
  score?: number;
  capture?: FirewallCapture;
  throwError?: unknown;
} = {}): FirewallClassifier {
  return {
    async classify(text, options) {
      params.capture?.calls.push({ text, options });
      if (params.throwError) {
        throw params.throwError;
      }
      return {
        prediction: params.prediction ?? "BENIGN",
        score: params.score ?? 0.1,
      };
    },
  };
}

export type FetchFixture = {
  matchUrl: string | RegExp;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  body: unknown;
  url?: string;
};

export function createFakeFetch(fixtures: readonly FetchFixture[]): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const urlText = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;
    const fixture = fixtures.find((candidate) =>
      typeof candidate.matchUrl === "string"
        ? candidate.matchUrl === urlText
        : candidate.matchUrl.test(urlText),
    );
    if (!fixture) {
      throw new Error(`No fake fetch fixture matched ${urlText}`);
    }

    const body = typeof fixture.body === "string" ? fixture.body : JSON.stringify(fixture.body);
    return new Response(body, {
      status: fixture.status ?? 200,
      statusText: fixture.statusText ?? "OK",
      headers: fixture.headers,
    });
  }) as typeof fetch;
}

export function createFakeLogger(): { logger: Logger; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    logger: {
      info(message) {
        calls.push(`info:${message}`);
      },
      warn(message, err) {
        calls.push(`warn:${message}${err ? ` ${String(err)}` : ""}`);
      },
      error(message, err) {
        calls.push(`error:${message}${err ? ` ${String(err)}` : ""}`);
      },
    },
  };
}

export function withFixedDate<T>(iso: string, fn: () => T): T {
  const RealDate = Date;
  const fixedMs = RealDate.parse(iso);
  class FixedDate extends RealDate {
    constructor(...args: ConstructorParameters<DateConstructor>) {
      if (args.length === 0) {
        super(fixedMs);
      } else {
        super(...args);
      }
    }

    static now(): number {
      return fixedMs;
    }
  }

  globalThis.Date = FixedDate as DateConstructor;
  let restoreLater = false;
  try {
    const result = fn();
    if (isPromiseLike(result)) {
      restoreLater = true;
      return result.finally(() => {
        globalThis.Date = RealDate;
      }) as T;
    }
    globalThis.Date = RealDate;
    return result;
  } finally {
    if (!restoreLater && globalThis.Date === FixedDate) {
      globalThis.Date = RealDate;
    }
  }
}

export async function withGlobalFetch<T>(fetchImpl: typeof fetch, fn: () => Promise<T>): Promise<T> {
  const previous = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await fn();
  } finally {
    globalThis.fetch = previous;
  }
}

export function expectGuardedPayload(
  payload: Record<string, unknown>,
  expected: { source: SourceLabel; markerKind: ContentMarkerKind },
): void {
  assert.equal(readNested(payload, ["firewall", "blocked"]), true);
  assert.match(String(readNested(payload, ["firewall", "approvalHandle"])), /^silmaril-[a-z-]+-[0-9a-f]{16}$/);
  assert.equal(readNested(payload, ["firewall", "approvalStatus"]), "pending");
  assert.equal(readNested(payload, ["firewall", "prediction"]), "MALICIOUS");
  const text = String(payload.text ?? "");
  assert.match(text, /<<<OPENCLAW_FIREWALL_SYSTEM_CONTEXT/);
  assert.match(text, new RegExp(`<<<UNTRUSTED_FETCHED_${expected.markerKind}_CONTENT`));
  assert.ok(text.includes(expected.source.split("_")[0]) || text.includes(String(payload.source ?? "")));
}

export function expectBenignPayload(
  payload: Record<string, unknown>,
  expected: { source: SourceLabel; minLength?: number },
): void {
  assert.equal(readNested(payload, ["firewall", "inspected"]), true);
  assert.notEqual(readNested(payload, ["firewall", "blocked"]), true);
  assert.equal(readNested(payload, ["firewall", "prediction"]), "BENIGN");
  const externalSource = String(readNested(payload, ["externalContent", "source"]) ?? payload.source);
  assert.ok(
    externalSource === expected.source || externalSource.startsWith(`${expected.source}_`),
    `unexpected external source ${externalSource}`,
  );
  assert.ok(String(payload.text ?? "").length >= (expected.minLength ?? 1));
}

export function expectNoSecretsInLog(calls: readonly string[], secrets: readonly string[]): void {
  const text = calls.join("\n");
  for (const secret of secrets) {
    assert.equal(text.includes(secret), false, `log output leaked ${secret}`);
  }
}

function readNested(value: unknown, path: readonly string[]): unknown {
  let current = value;
  for (const key of path) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function isPromiseLike<T>(value: T | Promise<T>): value is Promise<T> {
  return !!value && typeof value === "object" && "finally" in value && typeof value.finally === "function";
}
