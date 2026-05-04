import assert from "node:assert/strict";
import test from "node:test";
import { parsePluginConfig } from "./plugin-config";

test("parsePluginConfig parses minimal valid config", () => {
  const config = parsePluginConfig({
    apiKey: "key",
    apiUrl: "https://api.example",
    falsePositiveReportApiKey: "report-key",
  });

  assert.equal(config.apiKey, "key");
  assert.equal(config.silmarilApiKey, "key");
  assert.equal(config.apiUrl, "https://api.example");
  assert.equal(config.falsePositiveReportApiKey, "report-key");
  assert.equal(config.enableGitHubWrappers.issue, true);
  assert.equal(config.enableGitHubWrappers.pr, false);
  assert.equal(config.enableGmailWrappers.message, false);
});

test("parsePluginConfig warns and safely omits missing api credentials", () => {
  const warnings: string[] = [];
  const config = parsePluginConfig({}, { warn: (message) => warnings.push(message) });

  assert.equal(config.silmarilApiKey, undefined);
  assert.equal(config.apiUrl, undefined);
  assert.equal(warnings.length, 1);
});

test("parsePluginConfig coerces bad types to undefined safely", () => {
  const config = parsePluginConfig({
    apiKey: 123,
    silmarilApiKey: [],
    apiUrl: {},
    githubToken: false,
    google: { clientId: "id" },
    enableGitHubWrappers: { issue: "yes", pr: true },
    enableGmailWrappers: { message: true, search: "no" },
  });

  assert.equal(config.apiKey, undefined);
  assert.equal(config.silmarilApiKey, undefined);
  assert.equal(config.apiUrl, undefined);
  assert.equal(config.githubToken, undefined);
  assert.equal(config.google, undefined);
  assert.equal(config.enableGitHubWrappers.issue, true);
  assert.equal(config.enableGitHubWrappers.pr, true);
  assert.equal(config.enableGmailWrappers.message, true);
  assert.equal(config.enableGmailWrappers.search, false);
});

test("parsePluginConfig applies partial GitHub and Gmail wrapper defaults", () => {
  const config = parsePluginConfig({
    apiKey: "key",
    apiUrl: "url",
    enableGitHubWrappers: { issue: false, file: true },
    enableGmailWrappers: { thread: true },
  });

  assert.equal(config.enableGitHubWrappers.issue, false);
  assert.equal(config.enableGitHubWrappers.pr, false);
  assert.equal(config.enableGitHubWrappers.file, true);
  assert.equal(config.enableGmailWrappers.message, false);
  assert.equal(config.enableGmailWrappers.thread, true);
});

test("parsePluginConfig parses complete Google config", () => {
  const config = parsePluginConfig({
    apiKey: "key",
    apiUrl: "url",
    google: {
      clientId: "client",
      clientSecret: "secret",
      refreshToken: "refresh",
    },
  });

  assert.deepEqual(config.google, {
    clientId: "client",
    clientSecret: "secret",
    refreshToken: "refresh",
  });
});
