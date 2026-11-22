# Release notes

## Unreleased

## 1.3.0

- Move to `@silmaril-security/sdk` 1.0.0, which calls `/v2/classify`, returns
  the Firewall decision instead of a score, and falls back to `/classify` on
  deployments without the new route. Plugin configuration is unchanged.
- Decide on the SDK result's `action`: anything other than `allow` is a policy
  candidate. A block whose `source` is `governance` keeps the governance risk
  label and its benign recorded prediction.
- Record the decision's `confidence` and `severity` in local evidence when the
  Firewall reports a value the receipt schema knows, and stop writing
  `modelScore` and `modelThreshold`. The event schema version and every other
  field are unchanged.
- Log `action` and `source` in place of `prediction`.
- Serve `/v2/classify` with a version 2 body and `/classify` with a version 1
  body from the mock classifier, and relay each route to the matching customer
  route in live native acceptance.

## 1.2.12

- Observe `subagent_progress` without returning a block, cancel, or replacement.
- Correlate spawn, progress, and terminal child events through
  `childSessionKey` and `targetSessionKey` while retaining
  `requesterSessionKey` as separate parent identity.
- Bound lifecycle classification text and preserve observer-only Block
  candidates as native action `unavailable`.
- Align onboarding with capability review, live plugin application,
  conditional restart, deep Gateway status, and native callback verification.

## 1.2.11

- Keep the SDK's per-attempt classifier timeout unchanged while applying the
  same value as a plugin-owned deadline over all retries, backoff, and body
  handling.
- Give OpenClaw hook callbacks a bounded 1000 ms cleanup margin, so
  maximum-deadline classifier failures can settle fail-open before the native
  gate budget expires.
- Preserve OpenClaw's hook-specific and plugin-wide operator timeout precedence;
  no failure-mode override is registered.
- Raise the supported OpenClaw security floor to 2026.8.2 and record current
  2026.11.2 SDK and registration qualification.
- Route exact registry installation through
  `npm:@silmaril-security/firewall-plugin@1.2.11`.

## 1.2.10

Ships package and runtime attribution with `@silmaril-security/sdk` 0.8.2 in
the public registry and the [`v1.2.10` GitHub release](https://github.com/Silmaril-Security/FirewallPlugin/releases/tag/v1.2.10).
Native hook, enforcement, fail-open, local-evidence, provenance, and governance
behavior remain unchanged.

## 1.2.8

Prompt-build warning evidence records the user_input boundary, matching the
classifier and macOS evidence consumer. Reproducible npm, archive, and GitHub
installation references follow this package version.

## 1.2.7

Aligned the packaged timeoutMs guide with the host manifest: a JSON integer
from 250 through 10000 milliseconds, with a default of 2500.
