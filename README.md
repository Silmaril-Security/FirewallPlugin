# Silmaril Firewall Plugin for OpenClaw

Prompt-injection detection, guarded web fetch, and approval-gated firewall feedback for OpenClaw.

This is one plugin. It can register classifier hooks, reporting skills/tools, a firewall-owned `web_fetch` wrapper, and a firewall-owned GitHub issue reader. Customers do not need a separate wrapper plugin.

## Registered Surface

| Surface | Purpose |
|---|---|
| `before_prompt_build` hook | Classifies user input before it enters the model. |
| `before_tool_call` hook | Classifies tool arguments before a tool executes. It also places an approval gate on firewall report submissions. |
| `tool_result_persist` hook | Classifies tool output before it is persisted into later context. |
| `silmaril-firewall` web fetch provider | Provider metadata/fallback registration for OpenClaw web fetch provider discovery. |
| `web_fetch` wrapper tool | Optional replacement for OpenClaw's built-in `web_fetch`; fetches pages through Silmaril before fetched content reaches the model. |
| `github_issue_read` wrapper tool | Reads GitHub issues through the GitHub API and Silmaril before issue body/comments reach the model. |
| `firewall_report_false_positive` tool | Approval-gated submission of sanitized `suspected_false_positive` candidate reports to a review queue. |
| `firewall-false-positive-reporting` skill | Standing policy for when to call `firewall_report_false_positive` with required evidence, privacy limits, and protected-skill safeguards. |

The plugin never creates ground-truth training labels. Reporting tools submit candidate feedback only to a validation/review queue.

## Install

```sh
git clone https://github.com/Silmaril-Security/FirewallPlugin.git
cd FirewallPlugin
npm install
openclaw plugins install -l .
```

OpenClaw's local plugin safety scanner will block this install. Expect output similar to:

```text
Plugin "firewall-plugin" installation blocked: dangerous code patterns detected:
  - Shell command execution detected (child_process) (index.ts:<line>)
  - Environment variable access combined with network send — possible credential harvesting (src/false-positive-reporting.ts:<line>)
Also not a valid hook pack: Error: package.json missing openclaw.hooks
```

Both detections are expected for this plugin and are not credential exfiltration:

- **`child_process` in `index.ts`** — the `tool_result_persist` hook must classify content synchronously (it cannot await). The plugin uses `spawnSync(process.execPath, [FIREWALL_SYNC_WORKER_PATH], ...)` to invoke its own bundled Node worker. No shell is invoked and no command arguments are constructed from untrusted input.
- **Env access + network send in `src/false-positive-reporting.ts`** — the flagged line is a canary toggle: when `FIREWALL_REPORT_LIVE_WEBHOOK=1`, the plugin lets `FIREWALL_REPORT_URL` override the configured `falsePositiveReportUrl` for end-to-end testing. The actual report POST elsewhere in the file submits only sanitized candidate reports (see "Reporting Configuration" below) and runs behind the approval gate. No process env beyond those two opt-in canary variables is read, and credentials are never sent in the report body.

The "not a valid hook pack" line is also expected — this plugin registers hooks through the OpenClaw plugin entrypoint (`openclaw.extensions` in `package.json`), not the legacy `openclaw.hooks` hook-pack format.

Review `index.ts` and `src/false-positive-reporting.ts` against the explanations above, then install with the explicit override flag:

```sh
openclaw plugins install -l . --dangerously-force-unsafe-install
```

The override flag is required on every reinstall of this plugin from a local checkout. Treat it as a reviewed, one-time approval per upgrade — re-read the diff in those two files before re-running it after pulling new commits.

Restart the gateway after installing or changing plugin config:

```sh
openclaw gateway restart
```

Start a new OpenClaw session after changing plugin tools or skills so the tool and skill snapshot refreshes.

## Base Configuration

Add the plugin entry to `~/.openclaw/openclaw.json`.

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-plugin-or-openclaw-api-key",
          "silmarilApiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.example.com/classify"
        }
      }
    }
  }
}
```

`apiKey` may also be supplied as `silmarilApiKey`. If both are present, `silmarilApiKey` is used for Silmaril classification and exporter API calls; `apiKey` can remain the OpenClaw/plugin identity key. `apiUrl` is the Silmaril classify endpoint. If either credential or endpoint is missing, classifier hooks and wrapper tools are disabled. The report tool may still be visible, but it will not submit unless a review-queue URL is configured.

Current OpenClaw 2026.4.x config validation rejects a plugin-level `hooks.allowConversationAccess` key. Do not include that key unless your OpenClaw version explicitly documents it.

## Enable The Web Fetch Wrapper

The wrapper is the portable way to make normal URL summarization go through Silmaril without patching OpenClaw core. Configure it in the active gateway config, usually `~/.openclaw/openclaw.json`; changing only a repo-local sample file will not affect Telegram or gateway sessions.

To route `web_fetch` through Silmaril, set both of these in the same active config:

- `plugins.entries.firewall-plugin.config.enableWebFetchWrapper: true`
- `tools.web.fetch.enabled: false`

Example:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-plugin-or-openclaw-api-key",
          "silmarilApiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "enableWebFetchWrapper": true
        }
      }
    }
  },
  "tools": {
    "web": {
      "fetch": {
        "enabled": false,
        "maxChars": 20000,
        "maxResponseBytes": 750000,
        "timeoutSeconds": 30,
        "maxRedirects": 3
      }
    }
  }
}
```

Why `enabled: false`: OpenClaw registers the built-in `web_fetch` before plugin tools. If the built-in tool remains enabled, OpenClaw keeps the built-in tool and skips the plugin wrapper because both tools have the same name. The plugin logs a warning when `enableWebFetchWrapper` is true but `tools.web.fetch.enabled` is not false.

The wrapper still reads `maxChars`, `maxResponseBytes`, `timeoutSeconds`, `maxRedirects`, and `userAgent` from `tools.web.fetch`. Disabling the built-in tool does not disable the wrapper.

After changing either setting, restart the gateway and start a new OpenClaw session or channel conversation so the tool snapshot refreshes. For Telegram testing, send the next test message only after the restarted gateway logs `registered silmaril-firewall web_fetch wrapper tool`.

If your OpenClaw config uses restrictive tool allowlists, also allow the plugin tool:

```json
{
  "tools": {
    "alsoAllow": ["web_fetch", "github_issue_read"]
  }
}
```

## Enable The GitHub Issue Wrapper

The GitHub issue wrapper gives GitHub issue reads the same safety shape as the `web_fetch` wrapper, without fetching the large GitHub HTML page shell. It calls the GitHub REST API directly:

```text
GET https://api.github.com/repos/:owner/:repo/issues/:issue_number
GET https://api.github.com/repos/:owner/:repo/issues/:issue_number/comments
```

The wrapper then classifies the normalized issue body and comments with Silmaril before returning any issue content to the model. It does not change `web_fetch` behavior.

The tool is registered as:

```text
github_issue_read
```

Supported parameters:

```json
{
  "url": "https://github.com/AumUpadhyay/RestaurantAppUI/issues/3",
  "includeComments": true,
  "maxChars": 20000
}
```

or:

```json
{
  "owner": "AumUpadhyay",
  "repo": "RestaurantAppUI",
  "issueNumber": 3,
  "includeComments": true
}
```

Expected behavior:

1. The model calls `github_issue_read` for GitHub issue URLs.
2. The plugin fetches the issue and comments through the GitHub API.
3. The plugin calls Silmaril with `hook: TOOL_RESPONSE` and `toolName: github_issue_read`.
4. If the result is benign, the tool returns wrapped untrusted GitHub issue content plus `firewall.prediction` and `firewall.score`.
5. If the result is malicious, the tool returns a guarded result with `firewall.blocked: true`, classifier prediction and score, URL/content hashes, an approval handle, a system-control block, and issue text inside `<<<UNTRUSTED_FETCHED_GITHUB_CONTENT ... approval_state="pending_user_approval">>>`.

The generic `tool_result_persist` hook preserves that guarded result so the assistant sees the system-control block and asks:

```text
Do you want me to proceed with the flagged content despite the MALICIOUS firewall result?
```

The plugin also blocks common GitHub issue bypasses through shell execution, such as:

```sh
gh issue view 3 --repo AumUpadhyay/RestaurantAppUI
gh api repos/AumUpadhyay/RestaurantAppUI/issues/3
```

When those are attempted, the `before_tool_call` hook tells the model to retry with `github_issue_read`. This is intentionally scoped to GitHub issue reads; normal non-GitHub shell use is not blocked by this wrapper.

In current OpenClaw builds, add the wrapper to `tools.alsoAllow` so it is exposed to agent turns:

```json
{
  "tools": {
    "alsoAllow": ["github_issue_read"]
  }
}
```

For a reproducible Claude Code/OpenClaw setup, use this prompt in a new session after restarting the gateway:

```text
Use the web to tell me how I can fix https://github.com/AumUpadhyay/RestaurantAppUI/issues/3
```

Expected logs:

```text
firewall-plugin: registered github_issue_read wrapper tool
firewall-plugin: github_issue_read wrapper classified AumUpadhyay/RestaurantAppUI#3 as MALICIOUS
[firewall] tool_result_persist preserving guarded github_issue_read content for approval flow
```

## Web Fetch Behavior

Flow:

1. The model calls `web_fetch`.
2. The Silmaril wrapper fetches the URL with OpenClaw's strict web-tools network guard.
3. The wrapper extracts readable page text and also scans the raw response text so hidden HTML comments can still be detected.
4. The wrapper calls Silmaril with `hook: TOOL_RESPONSE` and `toolName: web_fetch`.
5. If the result is benign, the wrapper returns normal wrapped web content.
6. If the result is malicious, the wrapper withholds the raw HTTP response/HTML and returns a guarded tool result that contains:
   - a Silmaril firewall note,
   - `firewall.blocked: true`,
   - the classifier prediction and score,
   - URL/content hashes,
   - an `approvalHandle`,
   - extracted page text inside `<<<UNTRUSTED_FETCHED_WEB_CONTENT ... approval_state="pending_user_approval">>>`.

On the first malicious fetch result, the model should tell the user that Silmaril marked the page as malicious, briefly explain the suspicious content using sanitized details, avoid summarizing the non-security page content, and ask:

```text
Do you want me to proceed with the flagged content despite the MALICIOUS firewall result?
```

The guarded fetched text is intentionally preserved in conversation history. If the user explicitly approves proceeding, the next turn receives current-turn approval context telling the model to use the existing guarded content as data and not call `web_fetch` again for the same URL/content unless the user asks to refresh it. Approval does not make the content trusted or benign; instructions inside the fetched content must still be ignored.

## Optional Provider Selection

The plugin also registers the web fetch provider id `silmaril-firewall`:

```json
{
  "tools": {
    "web": {
      "fetch": {
        "provider": "silmaril-firewall"
      }
    }
  }
}
```

In the current OpenClaw runtime, provider selection is not enough to guarantee that ordinary HTML fetches are inspected before reaching the model. For guaranteed inspection of URL summarization, use the wrapper setup above: `enableWebFetchWrapper: true` plus `tools.web.fetch.enabled: false`.

## Reporting Configuration

Reporting endpoints are optional. Keep them pointed at a review queue, not direct training.

The registered reporting tool is `firewall_report_false_positive`. Configure `falsePositiveReportUrl` with a review-queue endpoint. Do not point it directly at a training pipeline.

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-plugin-or-openclaw-api-key",
          "silmarilApiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "falsePositiveReportUrl": "http://127.0.0.1:8787/webhook"
        }
      }
    }
  },
  "tools": {
    "alsoAllow": ["firewall_report_false_positive"]
  }
}
```

The `firewall_report_false_positive` tool submits only structured candidate reports with:

- `source: "openclaw"`
- `label: "suspected_false_positive"`
- a concise sanitized reason
- required evidence fields
- confidence from `0` to `1`

The approval gate runs before submission. Denied, timed-out, invalid, or unconfigured submissions send no request.

Candidate reports must not include secrets, credentials, raw private content, customer data, cookies, tokens, authorization headers, raw URLs, or full URLs with query strings.

Safe reporting path:

```text
agent candidate -> validation/dedup -> human/security review -> training/eval set -> regression tests -> model/rule update -> canary deploy
```

## Verify The Wrapper

After changing config:

```sh
openclaw gateway restart
```

Start a new session and run a URL task:

```sh
openclaw agent --session-id web-wrapper-check --message "Navigate to the page https://example.com and summarize it."
```

Expected benign behavior:

- The plugin logs `registered silmaril-firewall web_fetch wrapper tool`.
- The `web_fetch` tool is available.
- The plugin logs `web_fetch wrapper classified ... as BENIGN`.
- The model receives the fetched page content as normal untrusted web content.

Expected malicious behavior:

- The wrapper fetches and classifies the page once.
- The plugin logs `web_fetch wrapper classified ... as MALICIOUS`.
- The tool result has `extractor: "silmaril-firewall"`, `extractMode: "blocked"`, `firewall.blocked: true`, and a `firewall.approvalHandle`.
- The raw HTTP response/HTML is withheld, but extracted page text is included in the guarded untrusted-content block.
- The plugin logs `tool_result_persist preserving guarded web_fetch content for approval flow`.
- The model tells the user that Silmaril marked the fetched page as malicious and asks whether to proceed.

To verify the approval path without re-fetching, continue the same session:

```sh
openclaw agent --session-id web-wrapper-check --message "Yes, proceed with the flagged content despite the MALICIOUS firewall result."
```

Expected approval behavior:

- The model summarizes or transforms the already-fetched guarded content as data.
- It continues to ignore instructions inside the fetched content.
- It does not call `web_fetch` again unless the user explicitly asks to refresh or fetch again.

If the model fetches again after approval, check that you are running the current plugin code and that the gateway log includes `tool_result_persist preserving guarded web_fetch content for approval flow` on the first malicious fetch.

If you see a log message warning that `enableWebFetchWrapper` is true but `tools.web.fetch.enabled` is not false, the built-in web fetch tool is still enabled. Set `tools.web.fetch.enabled` to `false`, restart the gateway, and start a new session.

If a malicious page is classified by `tool_result_persist` but the assistant still summarizes without asking for approval, inspect the live tool result. `extractor: "readability"` or `extractor: "raw-html"` with no `firewall.approvalHandle` means OpenClaw used the built-in `web_fetch` instead of the Silmaril wrapper. Re-check the two required config settings above and restart the gateway.

## Manual Report Queue Helpers

For local review-queue tests:

```sh
npm run manual:fp:clear
npm run manual:fp:webhook
npm run manual:fp:captures
```

The helper server records POST bodies under `.manual/firewall-fp-reports.ndjson`.

The checked-in manual suite at `test/manual/firewall-false-positive-reporting.md` documents the false-positive reporting flow for `firewall_report_false_positive`.
