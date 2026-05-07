# Silmaril Firewall Power-User E2E Test Bed

This directory contains an additive E2E harness for exercising the firewall plugin against an isolated OpenClaw gateway. It does not use the user's production gateway, production `~/.openclaw` state, the live Silmaril API, AWS export endpoints, GitHub, Gmail, or real Telegram.

## Run

From the plugin repo:

```bash
pnpm install
pnpm test:e2e
pnpm test:e2e:powr-user
pnpm test:e2e:power-user
```

The harness expects a built OpenClaw repo. By default it uses the sibling checkout:

```bash
OPENCLAW_E2E_REPO=../openclaw-clean
```

Each scenario creates its own temp `HOME`, `USERPROFILE`, `OPENCLAW_CONFIG_PATH`, and `OPENCLAW_STATE_DIR`. The suite setup snapshots the real `~/.openclaw` recursive max mtime before and after each Vitest run and fails if it changed.

## What Starts Per Scenario

- isolated OpenClaw gateway on an ephemeral localhost port
- local fixture content server
- local Silmaril classifier mock with `/control/*` failure injection
- local false-positive webhook mock
- local fake S3 server for presigned POST uploads
- undici `MockAgent` for the hardcoded upload-lease and FP-review endpoints
- optional local Telegram Bot API mock for Telegram-channel tests

The gateway and agent CLI processes get `NODE_OPTIONS=--import test/e2e/harness/api-interceptor-preload.mjs`, which installs the same hardcoded endpoint interception inside child Node processes. The pre-suite no-egress smoke checks that `fetch("https://example.com")` is blocked in the test process. OpenAI and Anthropic API hosts are left reachable because the model itself is intentionally real; Silmaril, AWS export/review, GitHub, Google, and Telegram are not.

## Useful Environment

- `OPENCLAW_E2E_REPO`: path to the OpenClaw repo to spawn.
- `OPENCLAW_E2E_MODEL`: default model for non-matrix scenarios.
- `ANTHROPIC_API_KEY`: required for Anthropic model runs.
- `OPENAI_API_KEY`: required for OpenAI model matrix runs.
- `FIREWALL_E2E_CLASSIFIER_URL`: optional live Silmaril classifier URL. If unset, tests use the local mock classifier.
- `FIREWALL_E2E_CLASSIFIER_API_KEY`: optional live Silmaril classifier API key. Must be set with `FIREWALL_E2E_CLASSIFIER_URL`.
- `FIREWALL_E2E_ASSERT_PROD_UNTOUCHED=0`: disables the production `~/.openclaw` mtime assertion.

## Scenarios In This Round

Tier 1 is implemented under `test/e2e/scenarios/01-*.e2e.test.ts` through `10-*.e2e.test.ts`:

1. raw vs extracted HTML scanning
2. parallel flagged fetches
3. approval-handle collision
4. Telegram delivery
5. restart mid-turn
6. bypass path coverage matrix
7. sensitive-data canary audit
8. classifier/export failure matrix
9. stale approval handling
10. model matrix marker protocol

Tier 2 scenarios are intentionally deferred; add them as new numbered scenario files once the first ten are stable.

## Failure Artifacts

Each scenario writes artifacts under its temp root, including:

- `gateway.stdout.log`
- `gateway.stderr.log`
- `mock-classifier-captures.ndjson`
- `telegram-out.ndjson`
- `fp-webhook-captures.ndjson`
- `fp-review-uploads.ndjson`
- `fake-s3-requests.ndjson`
- per-agent CLI stdout/stderr logs

Use these files for root cause analysis. The canary audit helper also sweeps temp OpenClaw session JSONL, exporter spool files, mock captures, Telegram output, gateway logs, and fake S3 uploads.
