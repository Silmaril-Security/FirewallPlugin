import assert from "node:assert/strict";
import test from "node:test";
import { createFakeFirewall, expectBenignPayload, expectGuardedPayload, withFixedDate, withGlobalFetch } from "../core/__test__/test-helpers";
import { createFirewallWebFetchTool } from "./web-fetch";

const HTML = "<!doctype html><title>Report</title><h1>Quarterly vendor report</h1><p>Revenue increased 12%.</p>";

test("web_fetch returns wrapped benign content", async () => {
  const result = await runWebFetch({ prediction: "BENIGN" });
  expectBenignPayload(result.json as Record<string, unknown>, { source: "web_fetch" });
});

test("web_fetch returns guarded malicious content", async () => {
  const result = await runWebFetch({ prediction: "MALICIOUS" });
  expectGuardedPayload(result.json as Record<string, unknown>, { source: "web_fetch", markerKind: "WEB" });
});

test("web_fetch returns structured error for fetch failures", async () => {
  const fetchImpl = (async () => new Response("missing", { status: 404, statusText: "Not Found" })) as typeof fetch;
  const result = await withGlobalFetch(fetchImpl, () =>
    createFirewallWebFetchTool({ firewall: createFakeFirewall() }).execute("1", { url: "https://example.com/missing" }),
  );

  assert.equal(result.json.error, true);
  assert.equal(result.json.firewall.inspected, false);
});

test("web_fetch returns structured error for invalid params", async () => {
  const result = await createFirewallWebFetchTool({ firewall: createFakeFirewall() }).execute("1", {});

  assert.equal(result.json.error, true);
  assert.match(String(result.json.message), /url is required/);
});

test("web_fetch registers false-positive review candidate on malicious content", async () => {
  const candidates: unknown[] = [];
  await runWebFetch({
    prediction: "MALICIOUS",
    falsePositiveReviewStore: {
      threshold: 0.7,
      registerCandidate(candidate) {
        candidates.push(candidate);
      },
      handleMessageSending() {
        return undefined;
      },
    },
  });

  assert.equal(candidates.length, 1);
  assert.match(JSON.stringify(candidates[0]), /web_fetch/);
});

async function runWebFetch(params: {
  prediction: "BENIGN" | "MALICIOUS";
  falsePositiveReviewStore?: Parameters<typeof createFirewallWebFetchTool>[0]["falsePositiveReviewStore"];
}) {
  const fetchImpl = (async () =>
    new Response(HTML, {
      status: 200,
      headers: { "content-type": "text/html" },
    })) as typeof fetch;

  return withFixedDate("2026-05-03T00:00:00.000Z", () =>
    withGlobalFetch(fetchImpl, () =>
      createFirewallWebFetchTool({
        firewall: createFakeFirewall({
          prediction: params.prediction,
          score: params.prediction === "MALICIOUS" ? 0.9 : 0.1,
        }),
        falsePositiveReviewStore: params.falsePositiveReviewStore,
        fetchConfig: { maxChars: 20_000 },
      }).execute("1", { url: "https://example.com/report?token=secret" }),
    ),
  );
}
