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
          "apiUrl": "https://your-endpoint.example.com/classify"
        }
      }
    }
  }
}
```

`apiKey` may also be supplied as `silmarilApiKey`. If both are present, `silmarilApiKey` is used for Silmaril classification and exporter API calls; `apiKey` can remain the OpenClaw/plugin identity key. `apiUrl` is the Silmaril classify endpoint. If either credential or endpoint is missing, classifier hooks and wrapper tools are disabled. The report tool may still be visible, but it will not submit unless a review-queue URL is configured.

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

If your OpenClaw config uses restrictive tool allowlists, also allow the plugin tool:

```json
{
  "tools": {
    "alsoAllow": ["web_fetch", "github_issue_read"]
  }
}
```

## Enable GitHub Wrappers

GitHub wrappers give repository reads the same safety shape as the `web_fetch` wrapper, without fetching the large GitHub HTML page shell. Existing customers keep the current behavior: `github_issue_read` defaults on, and every new GitHub wrapper defaults off until enabled.

Optional config:

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
            "file": false,
            "discussion": false,
            "release": false
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

When those are attempted, the `before_tool_call` hook tells the model to retry with the matching wrapper. Patterns require a specific identifier such as an issue number, PR number, file path, discussion number, or release path; broad commands like `gh pr list`, `gh repo view`, and `git log` are not blocked.

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

The plugin blocks direct Gmail API reads through shell commands and tells the model to retry with `gmail_message_read`, `gmail_thread_read`, or `gmail_search`.

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
          "userEmail": "user@example.com",
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
