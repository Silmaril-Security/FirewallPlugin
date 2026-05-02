# Silmaril Firewall Plugin for OpenClaw

Prompt-injection detection, guarded web fetch, and approval-gated firewall feedback for OpenClaw.

This is one plugin. It can register classifier hooks, reporting skills/tools, and a firewall-owned `web_fetch` wrapper. Customers do not need a separate wrapper plugin.

## Registered Surface

| Surface | Purpose |
|---|---|
| `before_prompt_build` hook | Classifies user input before it enters the model. |
| `before_tool_call` hook | Classifies tool arguments before a tool executes. It also places an approval gate on firewall report submissions. |
| `tool_result_persist` hook | Classifies tool output before it is persisted into later context. |
| `silmaril-firewall` web fetch provider | Provider metadata/fallback registration for OpenClaw web fetch provider discovery. |
| `web_fetch` wrapper tool | Optional replacement for OpenClaw's built-in `web_fetch`; fetches pages through Silmaril before fetched content reaches the model. |
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
          "apiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.example.com/classify"
        },
        "hooks": {
          "allowConversationAccess": true
        }
      }
    }
  }
}
```

`apiKey` may also be supplied as `silmarilApiKey`. `apiUrl` is the Silmaril classify endpoint. If either credential or endpoint is missing, classifier hooks and the web fetch wrapper are disabled. The report tool may still be visible, but it will not submit unless a review-queue URL is configured.

## Enable The Web Fetch Wrapper

The wrapper is the portable way to make normal URL summarization go through Silmaril without patching OpenClaw core.

To route `web_fetch` through Silmaril, set `enableWebFetchWrapper: true` in the plugin config and disable OpenClaw's built-in web fetch tool:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "enableWebFetchWrapper": true
        },
        "hooks": {
          "allowConversationAccess": true
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

If your OpenClaw config uses restrictive tool allowlists, also allow the plugin tool:

```json
{
  "tools": {
    "alsoAllow": ["web_fetch"]
  }
}
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
          "apiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.example.com/classify",
          "falsePositiveReportUrl": "http://127.0.0.1:8787/webhook"
        },
        "hooks": {
          "allowConversationAccess": true
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

## Manual Report Queue Helpers

For local review-queue tests:

```sh
npm run manual:fp:clear
npm run manual:fp:webhook
npm run manual:fp:captures
```

The helper server records POST bodies under `.manual/firewall-fp-reports.ndjson`.

The checked-in manual suite at `test/manual/firewall-false-positive-reporting.md` documents the false-positive reporting flow for `firewall_report_false_positive`.
