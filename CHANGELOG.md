# Release notes

## Unreleased

No additional changes.

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
