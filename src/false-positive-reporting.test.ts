import assert from "node:assert/strict";
import test from "node:test";
import { createFalsePositiveReportTool } from "./false-positive-reporting";

test("firewall_report_false_positive posts candidate payload to generic endpoints", async () => {
  const calls: FetchCall[] = [];
  const tool = createFalsePositiveReportTool({
    reportUrl: "http://127.0.0.1:8787/webhook",
    apiKey: "report-key",
    fetchImpl: captureFetch(calls),
  });

  const result = await tool.execute("test", validParams());

  assert.equal(result.details.submitted, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.url, "http://127.0.0.1:8787/webhook");
  assert.deepEqual(calls[0]?.init.headers, {
    "content-type": "application/json",
    "x-api-key": "report-key",
  });
  const body = JSON.parse(String(calls[0]?.init.body));
  assert.equal(body.source, "openclaw");
  assert.equal(body.label, "suspected_false_positive");
  assert.equal(body.event_id, "fw-alert-test-001");
});

test("firewall_report_false_positive uses AWS review queue shape for firewall-export endpoint", async () => {
  const calls: FetchCall[] = [];
  const tool = createFalsePositiveReportTool({
    reportUrl:
      "https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/false-positive",
    apiKey: "report-key",
    identifier: "user@example.com",
    fetchImpl: captureFetch(calls),
  });

  const result = await tool.execute("test", validParams());

  assert.equal(result.details.submitted, true);
  assert.equal(calls.length, 1);
  const body = JSON.parse(String(calls[0]?.init.body));
  assert.equal(body.identifier, "user@example.com");
  assert.equal(body.timestamp, "2026-05-04T00:00:00.000Z");
  assert.equal(body.hook, "TOOL_RESPONSE");
  assert.equal(typeof body.payload, "string");
  assert.equal(JSON.parse(body.payload).event_id, "fw-alert-test-001");
  assert.equal(body.metadata.submitted_via, "firewall_report_false_positive");
  assert.equal(body.metadata.label, "suspected_false_positive");
});

test("firewall_report_false_positive treats duplicate queue responses as non-fatal", async () => {
  const tool = createFalsePositiveReportTool({
    reportUrl:
      "https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/false-positive",
    apiKey: "report-key",
    identifier: "user@example.com",
    fetchImpl: async () => new Response(JSON.stringify({ error: "duplicate_report" }), { status: 409 }),
  });

  const result = await tool.execute("test", validParams());

  assert.equal(result.details.submitted, true);
  assert.equal(result.details.status, "duplicate");
});

function validParams() {
  return {
    event_id: "fw-alert-test-001",
    reason: "Synthetic suspected false-positive candidate for reporting tests.",
    confidence: 0.72,
    evidence: {
      rule_id: "tool_response / web_fetch",
      timestamp: "2026-05-04T00:00:00.000Z",
      blocked_action: "synthetic hashed docs fetch",
      expected_task: "verify firewall false positive reporting endpoint wiring",
      repeatability: "same sanitized request shape was blocked twice",
      blocked_url_hash: "sha256:9d5c3b0d1e2f4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233",
      sanitized_context: "Synthetic canary only; no raw URL, private content, credentials, or customer data.",
    },
  };
}

type FetchCall = {
  url: string;
  init: RequestInit;
};

function captureFetch(calls: FetchCall[]): typeof fetch {
  return async (url, init) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(JSON.stringify({ status: "stored" }), { status: 200 });
  };
}
