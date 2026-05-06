import assert from "node:assert/strict";
import test from "node:test";
import {
  FALSE_POSITIVE_REVIEW_ENDPOINT,
  buildFalsePositiveReviewApiReport,
  buildLlmReviewMarkerExample,
  createFalsePositiveReviewStore,
  parseLlmReviewBlock,
  submitFalsePositiveReviewCandidate,
  stripLlmReviewBlock,
  type FirewallFalsePositiveReviewCandidate,
} from "./false-positive-review-store";

test("parseLlmReviewBlock reads the model's structured review marker", () => {
  const marker = buildLlmReviewMarkerExample({
    approvalHandle: "silmaril-web-fetch-abc123",
    prediction: "MALICIOUS",
    confidence: 0.72,
    reason: "Hidden instructions try to exfiltrate secrets.",
  });

  assert.deepEqual(parseLlmReviewBlock(`${marker}\nVisible message`), {
    approvalHandle: "silmaril-web-fetch-abc123",
    prediction: "MALICIOUS",
    confidence: 0.72,
    reason: "Hidden instructions try to exfiltrate secrets.",
  });
});

test("stripLlmReviewBlock removes the bookkeeping marker from user-visible content", () => {
  const marker = buildLlmReviewMarkerExample({
    approvalHandle: "silmaril-web-fetch-abc123",
    prediction: "BENIGN",
    confidence: 0.31,
    reason: "Business report text is safe to summarize.",
  });

  assert.equal(stripLlmReviewBlock(`${marker}\nThe page says revenue increased.`), "The page says revenue increased.");
});

test("buildFalsePositiveReviewApiReport sends the full firewall input payload", () => {
  const report = buildFalsePositiveReviewApiReport({
    identifier: "user@example.com",
    timestamp: "2026-05-03T23:10:00.000Z",
    threshold: 0.6,
    candidate: candidate("silmaril-web-fetch-low-confidence"),
    decision: {
      approvalHandle: "silmaril-web-fetch-low-confidence",
      prediction: "BENIGN",
      confidence: 0.44,
      reason: "No active instruction-following risk found.",
    },
  });

  assert.equal(report.identifier, "user@example.com");
  assert.equal(report.timestamp, "2026-05-03T23:10:00.000Z");
  assert.equal(report.hook, "TOOL_RESPONSE");
  assert.equal(report.payload, '{"source":"openclaw","raw_response_text":"full payload"}');
  assert.equal(report.metadata.threshold, 0.6);
  assert.equal(report.metadata.approvalHandle, "silmaril-web-fetch-low-confidence");
});

test("store submits full firewall input when LLM does not confidently agree with malicious result", async () => {
  const calls: FetchCall[] = [];
  const store = createFalsePositiveReviewStore({
    apiKey: "api-key",
    identifier: "user@example.com",
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
    now: () => "2026-05-03T23:10:00.000Z",
  });
  store.registerCandidate(candidate("silmaril-web-fetch-low-confidence"));

  const marker = buildLlmReviewMarkerExample({
    approvalHandle: "silmaril-web-fetch-low-confidence",
    prediction: "BENIGN",
    confidence: 0.44,
    reason: "No active instruction-following risk found.",
  });
  const result = store.handleMessageSending({ content: `${marker}\nSummary text.` });

  assert.equal(result?.content, "Summary text.");
  await flushPromises();

  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.url, FALSE_POSITIVE_REVIEW_ENDPOINT);
  assert.equal(calls[0]?.init.method, "POST");
  assert.deepEqual(calls[0]?.init.headers, {
    "content-type": "application/json",
    "x-api-key": "api-key",
  });
  const body = JSON.parse(String(calls[0]?.init.body));
  assert.equal(body.identifier, "user@example.com");
  assert.equal(body.timestamp, "2026-05-03T23:10:00.000Z");
  assert.equal(body.hook, "TOOL_RESPONSE");
  assert.equal(body.payload, '{"source":"openclaw","raw_response_text":"full payload"}');
  assert.equal(body.metadata.llmReview.prediction, "BENIGN");
});

test("store does not submit when LLM agrees malicious above threshold", async () => {
  const calls: FetchCall[] = [];
  const store = createFalsePositiveReviewStore({
    apiKey: "api-key",
    identifier: "user@example.com",
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
  });
  store.registerCandidate(candidate("silmaril-web-fetch-high-confidence"));

  const marker = buildLlmReviewMarkerExample({
    approvalHandle: "silmaril-web-fetch-high-confidence",
    prediction: "MALICIOUS",
    confidence: 0.88,
    reason: "The page contains prompt-injection instructions.",
  });
  const result = store.handleMessageSending({ content: `${marker}\nDo you want me to proceed?` });

  assert.equal(result?.content, "Do you want me to proceed?");
  await flushPromises();
  assert.equal(calls.length, 0);
});

test("store submits unstructured false-positive assistant review for newest pending candidate", async () => {
  const calls: FetchCall[] = [];
  const store = createFalsePositiveReviewStore({
    apiKey: "api-key",
    identifier: "user@example.com",
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
  });
  store.registerCandidate(candidate("silmaril-web-fetch-older"));
  store.registerCandidate(candidate("silmaril-web-fetch-newer"));

  const result = store.handleMessageSending({
    content:
      "Silmaril flagged this, but my independent review finds it benign. Likely a false positive.\n\nSummary text.",
  });

  assert.equal(result?.content, "Summary text.");
  await flushPromises();
  assert.equal(calls.length, 1);
  const body = JSON.parse(String(calls[0]?.init.body));
  assert.equal(body.metadata.llmReview.approvalHandle, "silmaril-web-fetch-newer");
  assert.equal(body.metadata.llmReview.prediction, "BENIGN");
  assert.equal(body.metadata.reason, "llm_did_not_confirm_malicious_above_threshold");
});

test("store reuses sanitized false-positive text after pending candidate is consumed", async () => {
  const calls: FetchCall[] = [];
  const store = createFalsePositiveReviewStore({
    apiKey: "api-key",
    identifier: "user@example.com",
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
  });
  store.registerCandidate(candidate("silmaril-web-fetch-repeat"));

  const content =
    "Silmaril flagged this, but my independent review finds it benign. Likely a false positive.\n\nSummary text.";
  assert.equal(store.handleMessageSending({ content })?.content, "Summary text.");
  assert.equal(store.handleMessageSending({ content })?.content, "Summary text.");
  await flushPromises();
  assert.equal(calls.length, 1);
});

test("store does not submit unstructured permission prompts", async () => {
  const calls: FetchCall[] = [];
  const store = createFalsePositiveReviewStore({
    apiKey: "api-key",
    identifier: "user@example.com",
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
  });
  store.registerCandidate(candidate("silmaril-web-fetch-high-confidence"));

  const result = store.handleMessageSending({
    content:
      "Silmaril marked this page as MALICIOUS. Do you want me to proceed with the flagged content despite the MALICIOUS firewall result?",
  });

  assert.equal(result, undefined);

  const followup = store.handleMessageSending({ content: "Understood. I will not summarize that content." });
  assert.equal(followup, undefined);
  await flushPromises();
  assert.equal(calls.length, 0);
});

test("store submits normal assistant output for still-pending flagged fetch", async () => {
  const calls: FetchCall[] = [];
  const store = createFalsePositiveReviewStore({
    apiKey: "api-key",
    identifier: "user@example.com",
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
  });
  store.registerCandidate(candidate("silmaril-web-fetch-normal-output"));

  const result = store.handleMessageSending({
    content:
      "Harbor lantern maintenance memo: all batteries passed inspection and the next routine check is Tuesday at 09:30.",
  });

  assert.equal(result, undefined);
  await flushPromises();
  assert.equal(calls.length, 1);
  const body = JSON.parse(String(calls[0]?.init.body));
  assert.equal(body.metadata.llmReview.approvalHandle, "silmaril-web-fetch-normal-output");
  assert.equal(body.metadata.llmReview.prediction, "BENIGN");
  assert.equal(
    body.metadata.llmReview.reason,
    "Assistant proceeded without a permission prompt for a pending malicious firewall result.",
  );
});

test("store fails open without api key or identifier", async () => {
  const calls: FetchCall[] = [];
  const warnings: string[] = [];
  const store = createFalsePositiveReviewStore({
    threshold: 0.6,
    fetchImpl: captureFetch(calls),
    logger: {
      warn(message) {
        warnings.push(message);
      },
    },
  });
  store.registerCandidate(candidate("silmaril-web-fetch-no-config"));

  const marker = buildLlmReviewMarkerExample({
    approvalHandle: "silmaril-web-fetch-no-config",
    prediction: "BENIGN",
    confidence: 0.2,
    reason: "No active instruction-following risk found.",
  });

  assert.equal(store.handleMessageSending({ content: `${marker}\nSummary text.` })?.content, "Summary text.");
  await flushPromises();
  assert.equal(calls.length, 0);
  assert.match(warnings.join("\n"), /apiKey is missing/);
});

test("submitFalsePositiveReviewCandidate treats duplicate reports as non-fatal", async () => {
  const infos: string[] = [];

  await submitFalsePositiveReviewCandidate({
    apiKey: "api-key",
    report: {
      identifier: "user@example.com",
      timestamp: "2026-05-03T23:10:00.000Z",
      hook: "USER_INPUT",
      payload: "payload",
      metadata: {},
    },
    logger: {
      info(message) {
        infos.push(message);
      },
    },
    fetchImpl: async () => new Response(JSON.stringify({ error: "duplicate_report" }), { status: 409 }),
  });

  assert.match(infos.join("\n"), /already stored/);
});

test("submitFalsePositiveReviewCandidate swallows network errors", async () => {
  const warnings: string[] = [];

  await submitFalsePositiveReviewCandidate({
    apiKey: "api-key",
    report: {
      identifier: "user@example.com",
      timestamp: "2026-05-03T23:10:00.000Z",
      hook: "USER_INPUT",
      payload: "payload",
      metadata: {},
    },
    logger: {
      warn(message) {
        warnings.push(message);
      },
    },
    fetchImpl: async () => {
      throw new Error("network down");
    },
  });

  assert.match(warnings.join("\n"), /network down/);
});

function candidate(approvalHandle: string): FirewallFalsePositiveReviewCandidate {
  return {
    approvalHandle,
    source: "web_fetch",
    capturedAt: "2026-05-03T00:00:00.000Z",
    firewallInput: {
      text: '{"source":"openclaw","raw_response_text":"full payload"}',
      options: {
        hook: "TOOL_RESPONSE",
        toolName: "web_fetch",
      },
    },
    firewallResult: {
      prediction: "MALICIOUS",
      score: 0.91,
    },
    metadata: {
      contentHash: "abc123",
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
    return new Response(
      JSON.stringify({
        status: "stored",
        identifier: "user@example.com",
        timestamp: "2026-05-03T23:10:00.000Z",
      }),
      { status: 200, statusText: "OK" },
    );
  };
}

async function flushPromises(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}
