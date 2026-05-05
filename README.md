# Silmaril Firewall Plugin for OpenClaw

Prompt-injection detection, guarded web fetch, and approval-gated firewall feedback for OpenClaw.

This is one plugin. It can register classifier hooks, reporting skills/tools, a firewall-owned `web_fetch` wrapper, GitHub content wrappers, and Gmail read-only wrappers. Customers do not need a separate wrapper plugin.

## Registered Surface

| Surface | Purpose |
|---|---|
| `before_prompt_build` hook | Classifies user input before it enters the model. |
| `before_tool_call` hook | Classifies tool arguments before a tool executes. It also places an approval gate on firewall report submissions. |
| `tool_result_persist` hook | Classifies tool output before it is persisted into later context. |
| `silmaril-firewall` web fetch provider | Provider metadata/fallback registration for OpenClaw web fetch provider discovery. |
| `web_fetch` wrapper tool | Optional replacement for OpenClaw's built-in `web_fetch`; fetches pages through Silmaril before fetched content reaches the model. |
| `github_issue_read`, `github_pr_read`, `github_pr_diff_read`, `github_file_read`, `github_discussion_read`, `github_release_read` | Optional GitHub wrappers that read repository content through GitHub APIs and Silmaril before it reaches the model. |
| `gmail_message_read`, `gmail_thread_read`, `gmail_search` | Optional Gmail wrappers that read Gmail content through the Gmail API and Silmaril before message content reaches the model. |
| `firewall_report_false_positive` tool | Approval-gated submission of sanitized `suspected_false_positive` candidate reports to a review queue. |
| `firewall-false-positive-reporting` skill | Standing policy for when to call `firewall_report_false_positive` with required evidence, privacy limits, and protected-skill safeguards. |

The plugin never creates ground-truth training labels. Reporting tools submit candidate feedback only to a validation/review queue.

## Runtime Tool Visibility

The manifest lists every surface the plugin can provide, but OpenClaw only exposes tools that are registered for the active gateway config and allowed by the active tool policy.

A wrapper is active for a session only when all of these are true:

- its plugin config flag enables it
- its credentials/prerequisites are complete
- the gateway was restarted after the config change
- the OpenClaw session started after the gateway restart
- custom wrapper tools are present in `tools.alsoAllow` if the OpenClaw profile uses restrictive tool policy

`web_fetch` is the exception because the wrapper reuses OpenClaw's built-in tool name. For that one, disable the built-in web fetch and enable the plugin wrapper as described below.

The bypass registry follows the same rule. It blocks shell/API bypasses only for wrapper tools that have actually registered. This avoids a dead-end where OpenClaw blocks `gh pr view` and tells the model to retry with `github_pr_read` when `github_pr_read` is disabled or unavailable. The tradeoff is intentional: if a wrapper is disabled or not allowed in the session, the matching direct-read bypass is not a complete security control.

After any tool config change, verify the live session rather than relying on the manifest:

```sh
openclaw gateway restart
openclaw agent --message "/tools verbose"
```

Expected visible tools should include every wrapper you intend to use, for example `web_fetch`, `github_issue_read`, `github_pr_read`, `gmail_message_read`, and `firewall_report_false_positive`.

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
  - Environment variable access combined with network send — possible credential harvesting (src/false-positive-reporting.ts:<line> or src/user-email.ts:<line>)
  - OAuth/token endpoint usage (src/auth/google-oauth.ts:<line>) if Gmail wrappers are enabled
Also not a valid hook pack: Error: package.json missing openclaw.hooks
```

Both detections are expected for this plugin and are not credential exfiltration:

- **`child_process` in `index.ts`** — the `tool_result_persist` hook must classify content synchronously (it cannot await). The plugin uses `spawnSync(process.execPath, [FIREWALL_SYNC_WORKER_PATH], ...)` to invoke its own bundled Node worker. No shell is invoked and no command arguments are constructed from untrusted input.
- **Env access + network send** — `src/false-positive-reporting.ts` reads canary toggles: when `FIREWALL_REPORT_LIVE_WEBHOOK=1`, the plugin lets `FIREWALL_REPORT_URL` override the configured `falsePositiveReportUrl` for end-to-end testing. `src/user-email.ts` reads optional `USER_EMAIL` account metadata for classification/export attribution. The actual report POST submits only sanitized candidate reports (see "Reporting Configuration" below) and runs behind the approval gate. Credentials are never sent in the report body.
- **Google OAuth endpoint** — Gmail wrappers use the OAuth refresh-token flow against `https://oauth2.googleapis.com/token` and keep access tokens in memory only. `google.clientSecret` and `google.refreshToken` are read from plugin config and are marked sensitive in the manifest.

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
          "userEmail": "user@example.com",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "falsePositiveReportUrl": "https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/false-positive",
          "falsePositiveReportApiKey": "your-report-queue-api-key"
        }
      }
    }
  }
}
```

`apiKey` may also be supplied as `silmarilApiKey`. If both are present, `silmarilApiKey` is used for Silmaril classification and exporter API calls; `apiKey` can remain the OpenClaw/plugin identity key. `apiUrl` is the Silmaril classify endpoint. If either credential or endpoint is missing, classifier hooks and wrapper tools are disabled. The report tool may still be visible, but it will not submit unless a review-queue URL is configured. `falsePositiveReportApiKey` is optional; set it when the false-positive review queue uses a different API Gateway key than the classifier API. If omitted, the plugin falls back to `silmarilApiKey`, then `apiKey`.

### Configure User Email

`userEmail` is optional account metadata used for Silmaril classification/export attribution. Prefer setting it directly in the active OpenClaw config because gateway, Telegram, and scheduled-task launches may not inherit environment variables from your interactive shell:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "userEmail": "user@example.com"
        }
      }
    }
  }
}
```

If `userEmail` is omitted from plugin config, the plugin reads `USER_EMAIL` from the gateway process environment. For a one-off local PowerShell run:

```powershell
$env:USER_EMAIL = "user@example.com"
openclaw gateway restart
```

For persistent Windows shells:

```powershell
setx USER_EMAIL "user@example.com"
```

Then restart the terminal, gateway, or service that launches OpenClaw so the gateway process sees the new environment. If OpenClaw is launched by a Windows scheduled task or service, configure `USER_EMAIL` in that launch environment or use the `userEmail` plugin config instead.

The configured `userEmail` value takes precedence over `USER_EMAIL`. The plugin sends this value as `metadata.user_email` on Silmaril classification requests and as exporter attribution metadata; do not put secrets in it. Restart the gateway after changing either setting.

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
          "userEmail": "user@example.com",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "enableWebFetchWrapper": true,
          "llmFalsePositiveReviewThreshold": 0.6
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

When Silmaril flags fetched web content as malicious, the wrapper now requires a secondary model review before interrupting the user. The guarded tool result tells the active OpenClaw model to classify the fetched content as `MALICIOUS` or `BENIGN` with a confidence score:

- If the model also says `MALICIOUS` with confidence greater than `llmFalsePositiveReviewThreshold` (default `0.6`), the user gets the existing confirmation prompt.
- Otherwise, the plugin strips the model's bookkeeping marker before delivery, lets the model continue with the user's original request, and submits the exact payload sent to Silmaril to the false-positive review API:

```text
POST https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/false-positive
```

The request uses the resolved Silmaril API key (`silmarilApiKey`, falling back to `apiKey`) as `x-api-key`, and `userEmail` as `identifier`. If the API key, `userEmail`, the network, or the endpoint fails, the plugin fails open: it logs the issue and does not affect the assistant response. Duplicate reports from the endpoint are treated as non-fatal. The submitted payload can contain the full text sent to the firewall, including raw fetched page text after wrapper truncation; configure `userEmail` and handle endpoint access accordingly.

After changing either setting, restart the gateway and start a new OpenClaw session or channel conversation so the tool snapshot refreshes. For Telegram testing, send the next test message only after the restarted gateway logs `registered silmaril-firewall web_fetch wrapper tool`.

If your OpenClaw config uses restrictive tool allowlists, also allow any custom plugin tools you need in the same active config:

```json
{
  "tools": {
    "alsoAllow": ["github_issue_read", "firewall_report_false_positive"]
  }
}
```

`web_fetch` usually does not need to be listed in `alsoAllow` because the wrapper reuses OpenClaw's built-in tool name after `tools.web.fetch.enabled` is set to `false`. Custom plugin tools such as `github_issue_read`, Gmail wrappers, and `firewall_report_false_positive` do need to be present in the session tool policy when you want the model to call them.

## Enable GitHub Wrappers

GitHub wrappers give repository reads the same safety shape as the `web_fetch` wrapper, without fetching the large GitHub HTML page shell. Existing customers keep the current behavior: `github_issue_read` defaults on, and every new GitHub wrapper defaults off until enabled.

With no `enableGitHubWrappers` block, only `github_issue_read` is enabled by default. That means pull requests, PR diffs, files, discussions, and releases are implemented by the plugin but are not registered in the live OpenClaw session.

For full GitHub read coverage, enable every wrapper you want and expose the matching tool names:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "githubToken": "github_pat_...",
          "enableGitHubWrappers": {
            "issue": true,
            "pr": true,
            "prDiff": true,
            "file": true,
            "discussion": true,
            "release": true
          }
        }
      }
    }
  },
  "tools": {
    "alsoAllow": [
      "github_issue_read",
      "github_pr_read",
      "github_pr_diff_read",
      "github_file_read",
      "github_discussion_read",
      "github_release_read"
    ]
  }
}
```

`githubToken` is optional for public content but recommended for private repositories and rate limits. Use a fine-grained token scoped to the minimum repositories and permissions required: Contents Read, Pull requests Read, Issues Read, Discussions Read, and Metadata Read. For classic PATs, use `repo` only when needed for private repositories.

If you enable only part of the GitHub wrapper set, only that part is source-wrapped. For example, with the default config OpenClaw can use `github_issue_read`, but `github_pr_read` is not visible and the plugin will not block `gh pr view` with a retry hint to an unavailable tool.

Wrapped tools:

| Tool | Reads |
|---|---|
| `github_issue_read` | Issue body and comments. |
| `github_pr_read` | Pull request metadata/body and issue comments. |
| `github_pr_diff_read` | Pull request diff text. |
| `github_file_read` | Text file contents from `repos/:owner/:repo/contents/:path?ref=...`; binary files are rejected. |
| `github_discussion_read` | Discussion body, answer, and comments through GraphQL. |
| `github_release_read` | Latest or tagged release notes. |

Example `github_issue_read` parameters:

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

1. The model calls the matching GitHub wrapper for GitHub URLs or structured GitHub requests.
2. The plugin fetches through GitHub REST or GraphQL APIs.
3. The plugin calls Silmaril with `hook: TOOL_RESPONSE` and the wrapper `toolName`.
4. If benign, the tool returns wrapped untrusted GitHub content plus `firewall.prediction` and `firewall.score`.
5. If malicious, the tool returns a guarded result with `firewall.blocked: true`, classifier prediction and score, hashes, an approval handle, a system-control block, and content inside `<<<UNTRUSTED_FETCHED_GITHUB_CONTENT ... approval_state="pending_user_approval">>>`.

The generic `tool_result_persist` hook preserves that guarded result so the assistant sees the system-control block and asks:

```text
Do you want me to proceed with the flagged content despite the MALICIOUS firewall result?
```

The plugin also blocks common GitHub bypasses through shell execution, such as:

```sh
gh issue view 3 --repo AumUpadhyay/RestaurantAppUI
gh api repos/AumUpadhyay/RestaurantAppUI/issues/3
gh pr view 42 --repo owner/repo
gh pr diff 42 --repo owner/repo
curl https://raw.githubusercontent.com/owner/repo/main/README.md
```

When those are attempted and the matching wrapper is registered, the `before_tool_call` hook tells the model to retry with that wrapper. Patterns require a specific identifier such as an issue number, PR number, file path, discussion number, or release path; broad commands like `gh pr list`, `gh repo view`, and `git log` are not blocked.

GitHub paths that are not fully covered unless you enable the matching wrapper include:

- `gh pr view` and GitHub PR HTML/API URLs: enable `github_pr_read`
- `gh pr diff`, `.diff`, and `.patch` URLs: enable `github_pr_diff_read`
- `raw.githubusercontent.com` and repository contents API reads: enable `github_file_read`
- GitHub Discussions reads: enable `github_discussion_read`
- GitHub Releases reads: enable `github_release_read`

Other OpenClaw GitHub integrations, MCP servers, browser sessions, cloned local repositories, and ad hoc shell commands can still introduce repository content outside these source wrappers. The plugin's generic hooks still classify prompts, tool arguments, and persisted tool results, but `tool_result_persist` cannot stop raw tool output from reaching the model in the same turn. Use source wrappers for content you need inspected before model exposure.

GitHub wrappers currently use the guarded approval flow directly when Silmaril returns `MALICIOUS`. The secondary LLM false-positive review path is implemented for `web_fetch`; if a GitHub wrapper looks like a false positive, use `firewall_report_false_positive` after the approval gate and include sanitized evidence.

## Enable Gmail Wrappers

Gmail wrappers are default-off and read-only. They require a Google OAuth desktop-client refresh token with scope:

```text
https://www.googleapis.com/auth/gmail.readonly
```

Setup:

1. In Google Cloud, create or select a project, enable the Gmail API, create OAuth 2.0 Desktop client credentials, and add the Gmail account as a test user if the app is in testing mode.
2. Get a refresh token with either Google's OAuth Playground or the bundled helper:

```sh
GOOGLE_CLIENT_ID="...apps.googleusercontent.com" GOOGLE_CLIENT_SECRET="GOCSPX-..." node scripts/manual-google-oauth-bootstrap.mjs
```

3. Add config and tool allowlist:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "google": {
            "clientId": "...apps.googleusercontent.com",
            "clientSecret": "GOCSPX-...",
            "refreshToken": "1//..."
          },
          "enableGmailWrappers": {
            "message": true,
            "thread": true,
            "search": true
          }
        }
      }
    }
  },
  "tools": {
    "alsoAllow": ["gmail_message_read", "gmail_thread_read", "gmail_search"]
  }
}
```

Gmail tools:

| Tool | Parameters |
|---|---|
| `gmail_message_read` | `{ "messageId": "..." }` |
| `gmail_thread_read` | `{ "threadId": "..." }` |
| `gmail_search` | `{ "query": "from:vendor@example.com newer_than:30d", "maxResults": 10 }` |

Gmail wrapper behavior matches GitHub wrappers: content is decoded, normalized, classified, and then returned as wrapped benign content or guarded malicious content. Multipart MIME decoding prefers text/plain, falls back to HTML text extraction, ignores attachments, and caps forwarded/multipart recursion. Access tokens are cached in memory and concurrent refreshes are deduplicated.

Gmail wrappers register only when both conditions are true: the wrapper flag is enabled and `google.clientId`, `google.clientSecret`, and `google.refreshToken` are all configured. If a wrapper is enabled but Google config is incomplete, the gateway logs a warning and that tool is not available in the session.

The plugin blocks direct Gmail API reads through shell commands only when the matching Gmail wrapper is registered. It then tells the model to retry with `gmail_message_read`, `gmail_thread_read`, or `gmail_search`. If the Gmail wrapper is disabled, missing credentials, or omitted from `tools.alsoAllow`, OpenClaw may still have other ways to read email content that are not source-wrapped by this plugin.

Gmail wrappers currently use the guarded approval flow directly when Silmaril returns `MALICIOUS`. The secondary LLM false-positive review path is implemented for `web_fetch`; if a Gmail result looks like a false positive, use `firewall_report_false_positive` after the approval gate and include sanitized evidence.

## Log Exporter

When `silmarilApiKey` and `apiUrl` are configured, the plugin starts a durable firewall log exporter. Exporter failures are fail-open: they are logged locally and do not block OpenClaw prompts, tool calls, wrapper execution, or report submissions.

For the hosted AWS exporter, the upload-lease request is:

```http
POST https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/upload-lease
content-type: application/json
x-api-key: <silmarilApiKey>
```

```json
{
  "host": "local-hostname"
}
```

The lease response controls the destination S3 prefix. In the current Silmaril alpha deployment, exported logs land under:

```text
openclaw-firewall/v1/logs/<tenant-path-id>/yyyy/mm/dd/hh/<uuid>.jsonl.gz
```

Use the first path segment from your classify API host as a practical tenant/path id check. For example, `https://1of9epawm2.execute-api.us-west-2.amazonaws.com/alpha/classify` corresponds to exported log paths under `openclaw-firewall/v1/logs/1of9epawm2/...`.

Local exporter state lives under:

```text
~/.openclaw/firewall-plugin/export
```

Useful verification points:

- `checkpoint.json` should advance `uploadedThroughSeq`
- `spool/*.ready` should drain after successful upload
- `logs/exporter.log` should show exporter startup and no current upload-lease failures

If upload leases return `403 Forbidden`, check that the exporter is using the Silmaril/classifier API key as `x-api-key`. The false-positive review queue may use a different key; that key is not necessarily valid for export upload leases.

## Manual Smoke Checks

The smoke scripts use real network fetches with a fake benign classifier, so they verify wrapper fetch/parsing/return shape without requiring Silmaril or Google credentials:

```sh
npm run manual:web-fetch:smoke
npm run manual:github:smoke
```

The web smoke defaults to `https://example.com`. The GitHub smoke defaults to `octocat/Hello-World#1`; override it with:

```sh
npm run manual:github:smoke -- owner repo 123
```

For a reproducible Claude Code/OpenClaw GitHub setup, use this prompt in a new session after restarting the gateway:

```text
Use the web to tell me how I can fix https://github.com/AumUpadhyay/RestaurantAppUI/issues/3
```

Expected logs:

```text
firewall-plugin: registered github_issue_read wrapper tool
firewall-plugin: github_issue_read wrapper classified AumUpadhyay/RestaurantAppUI#3 as MALICIOUS
[firewall] tool_result_persist preserving guarded github_issue_read content for approval flow
```

## E2E Failure Harness

The power-user E2E harness in `test/e2e` runs isolated OpenClaw gateways with mocked Silmaril, false-positive review, S3 export, GitHub/Gmail egress, and optional Telegram delivery. It is designed to catch the kinds of OpenClaw orchestration failures that unit tests miss: disabled wrapper bypasses, stale approval state, false-positive review routing, exporter failure behavior, and model-marker handling.

Run it from the plugin repo:

```sh
npm run test:e2e
npm run test:e2e:power-user
```

The harness expects an OpenClaw checkout, defaulting to `../openclaw-clean`:

```sh
OPENCLAW_E2E_REPO=../openclaw-clean npm run test:e2e
```

It creates isolated temp `HOME`, `USERPROFILE`, `OPENCLAW_CONFIG_PATH`, and `OPENCLAW_STATE_DIR` values per scenario and asserts the real `~/.openclaw` tree was not modified. See `test/e2e/README.md` for model-key requirements, failure artifacts, and the scenario list.

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
   - a required LLM secondary-review marker that the plugin strips before user delivery,
   - extracted page text inside `<<<UNTRUSTED_FETCHED_WEB_CONTENT ... approval_state="pending_user_approval">>>`.

On the first malicious fetch result, the model must independently review the untrusted content and give its own malicious/benign confidence score in the plugin marker. If it agrees that the content is malicious above the configured threshold, it should tell the user that Silmaril marked the page as malicious, briefly explain the suspicious content using sanitized details, avoid summarizing the non-security page content, and ask:

```text
Do you want me to proceed with the flagged content despite the MALICIOUS firewall result?
```

If the model does not agree above the threshold, the plugin submits the firewall input payload to the false-positive review API as a candidate false positive and the model proceeds with the requested task while still treating fetched content as untrusted data.

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

The registered reporting tool is `firewall_report_false_positive`. Configure `falsePositiveReportUrl` with a review-queue endpoint and expose the tool through `tools.alsoAllow`. Do not point it directly at a training pipeline.

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-plugin-or-openclaw-api-key",
          "silmarilApiKey": "your-silmaril-api-key",
          "userEmail": "user@example.com",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "falsePositiveReportUrl": "https://v6x0guucsb.execute-api.us-west-2.amazonaws.com/prod/v1/openclaw/firewall-export/false-positive",
          "falsePositiveReportApiKey": "your-report-queue-api-key"
        }
      }
    }
  },
  "tools": {
    "alsoAllow": ["firewall_report_false_positive"]
  }
}
```

The tool is optional and approval-gated. If `firewall_report_false_positive` is missing from `tools.alsoAllow`, the `firewall-false-positive-reporting` skill can still teach the model how to format a candidate report, but the model cannot submit it.

The AWS review queue expects:

```http
POST /prod/v1/openclaw/firewall-export/false-positive
content-type: application/json
x-api-key: <falsePositiveReportApiKey or silmarilApiKey>
```

The request body uses:

```json
{
  "identifier": "user@example.com",
  "timestamp": "2026-05-03T23:10:00.000Z",
  "hook": "TOOL_RESPONSE",
  "payload": "{\"event_id\":\"...\",\"source\":\"openclaw\",\"label\":\"suspected_false_positive\"}",
  "metadata": {
    "submitted_via": "firewall_report_false_positive"
  }
}
```

For local mock webhooks such as `http://127.0.0.1:8787/webhook`, the tool posts the original structured candidate body directly so the manual suite stays easy to inspect.

Candidate reports contain:

- `source: "openclaw"`
- `label: "suspected_false_positive"`
- a concise sanitized reason
- required evidence fields
- confidence from `0` to `1`

The approval gate runs before submission. Denied, timed-out, invalid, or unconfigured submissions send no request.

Candidate reports must not include secrets, credentials, raw private content, customer data, cookies, tokens, authorization headers, raw URLs, or full URLs with query strings.

After changing `tools.alsoAllow` or plugin config, restart OpenClaw and start a new session so the model receives a fresh tool snapshot:

```sh
openclaw gateway restart
openclaw agent --message "/tools verbose"
```

Expected visible tools include `firewall_report_false_positive`, plus any enabled wrapper tools such as `github_issue_read`.

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
