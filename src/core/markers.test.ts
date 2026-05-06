import assert from "node:assert/strict";
import test from "node:test";

import {
  GUARDED_MARKER_KINDS,
  buildSystemContextBlock,
  isGuardedResultText,
  wrapUntrustedContent,
} from "./markers";
import type { ContentMarkerKind, WrapperContext } from "./types";

const exhaustiveKinds: Record<ContentMarkerKind, true> = {
  WEB: true,
  GITHUB: true,
  GMAIL: true,
};

const ctx: WrapperContext = {
  toolName: "github_issue_read",
  source: "github_issue",
  markerKind: "GITHUB",
  firewall: {
    async classify() {
      return { prediction: "BENIGN", score: 0 };
    },
  },
};

test("GUARDED_MARKER_KINDS covers every marker kind", () => {
  assert.deepEqual(
    Object.fromEntries(GUARDED_MARKER_KINDS.map((kind) => [kind, true])),
    exhaustiveKinds,
  );
});

test("buildSystemContextBlock emits a simple approval block", () => {
  const block = buildSystemContextBlock({
    ctx,
    approvalHandle: "silmaril-github-issue-abcdef1234567890",
    contentHash: "c".repeat(64),
    urlHash: "u".repeat(64),
    prediction: "MALICIOUS",
    score: 0.91,
    contentNoun: "GitHub issue content",
    identityLines: ["repository: owner/repo", "issue_number: 3"],
  });

  assert.match(block, /^<<<OPENCLAW_FIREWALL_SYSTEM_CONTEXT/);
  assert.match(block, /source: github_issue/);
  assert.match(block, /repository: owner\/repo/);
  assert.match(block, /Tell the user that Silmaril marked the GitHub issue content as MALICIOUS/);
  assert.doesNotMatch(block, /llm_secondary_review_required/);
});

test("buildSystemContextBlock emits the LLM-review variant only when requested", () => {
  const block = buildSystemContextBlock({
    ctx: { ...ctx, toolName: "web_fetch", source: "web_fetch", markerKind: "WEB" },
    approvalHandle: "silmaril-web-fetch-abcdef1234567890",
    contentHash: "c".repeat(64),
    urlHash: "u".repeat(64),
    prediction: "MALICIOUS",
    score: 0.91,
    contentNoun: "fetched page content",
    identityLines: ["host: example.com"],
    llmReview: {
      thresholdValue: 0.6,
      markerExample: "<<<OPENCLAW_FIREWALL_LLM_REVIEW>{}</OPENCLAW_FIREWALL_LLM_REVIEW>>>",
    },
  });

  assert.match(block, /llm_secondary_review_required: true/);
  assert.match(block, /confidence greater than 0.6/);
  assert.match(block, /OPENCLAW_FIREWALL_LLM_REVIEW/);
});

test("wrapUntrustedContent uses marker kind and tool name", () => {
  assert.match(wrapUntrustedContent({ ctx: { ...ctx, markerKind: "WEB" }, value: "page", approvalHandle: "h" }), /UNTRUSTED_FETCHED_WEB_CONTENT source="github_issue_read"/);
  assert.match(wrapUntrustedContent({ ctx, value: "issue", approvalHandle: "h" }), /UNTRUSTED_FETCHED_GITHUB_CONTENT source="github_issue_read"/);
  assert.match(wrapUntrustedContent({ ctx: { ...ctx, markerKind: "GMAIL" }, value: "email", approvalHandle: "h" }), /UNTRUSTED_FETCHED_GMAIL_CONTENT source="github_issue_read"/);
});

test("isGuardedResultText requires both system and matching content markers", () => {
  const guarded = `${buildSystemContextBlock({
    ctx,
    approvalHandle: "silmaril-github-issue-abcdef1234567890",
    contentHash: "c".repeat(64),
    prediction: "MALICIOUS",
    score: 0.91,
    contentNoun: "GitHub issue content",
    identityLines: [],
  })}\n\n${wrapUntrustedContent({ ctx, value: "issue text", approvalHandle: "silmaril-github-issue-abcdef1234567890" })}`;

  assert.equal(isGuardedResultText(guarded, "GITHUB"), true);
  assert.equal(isGuardedResultText(guarded, "WEB"), false);
  assert.equal(isGuardedResultText("<<<OPENCLAW_FIREWALL_SYSTEM_CONTEXT>>>", "GITHUB"), false);
  assert.equal(isGuardedResultText("plain text", "GITHUB"), false);
});
