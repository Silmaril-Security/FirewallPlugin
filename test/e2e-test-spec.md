# Shadow/Enforcement E2E Test Spec

By default this plugin is pass-through shadow mode. It sends OpenClaw hook
payloads to the configured Silmaril classify endpoint, logs classifier results,
and does not change OpenClaw behavior. Optional enforcement is limited to
`before_tool_call` and requires both `shadowMode: false` and
`blockMalicious: true`.

## Expected Plugin Shape

`openclaw --no-color plugins inspect firewall-plugin --runtime` should show:

```text
Status: loaded
Format: openclaw
Shape: hook-only
Typed hooks:
gateway_start
before_agent_run
before_tool_call
tool_result_persist
message_sending
reply_payload_sending
message_sent
```

The plugin must not register wrapper tools, false-positive tools, exporters,
queues, approval handles, or `before_message_write`.

## Required Config

Configure:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "hooks": {
          "allowConversationAccess": true
        },
        "config": {
          "silmarilApiKey": "<silmaril-api-key>",
          "apiUrl": "https://<api-id>.execute-api.<region>.amazonaws.com/alpha/classify",
          "timeoutMs": 2500,
          "shadowMode": true,
          "blockMalicious": false
        }
      }
    },
    "allow": ["firewall-plugin"]
  }
}
```

`apiKey` remains accepted as a legacy fallback for `silmarilApiKey`.

## Smoke Flow

1. Start OpenClaw with the plugin configured.
2. Send a normal user prompt.
3. Send a prompt that uses at least one tool.
4. Inspect gateway logs.

Expected logs:

```text
firewall-plugin: installed
[firewall] before_agent_run result:
[firewall] before_tool_call result:
[firewall] tool_result_persist result:
```

If classifier config is missing, the plugin should warn once and log skipped
classifications with `missing_config`.

## Enforcement Smoke Flow

Configure `shadowMode: false` and `blockMalicious: true`, then run a tool call
that the classifier returns as malicious. Expected behavior:

- `before_tool_call` returns `{ "block": true, "blockReason": "..." }`.
- The block reason includes a readable surface and risk label.
- The block reason does not include raw prompt text, tool parameters, or tool
  result text.
- `tool_result_persist` still returns `undefined`.

## Invariants

The plugin must not emit or create:

- `firewall-plugin: Silmaril is in shadow mode`
- `[firewall] before_prompt_build risk cached:`
- `[firewall] before_message_write risk cache consumed:`
- prompt, system, or developer context mutation fields
- wrapper tools such as `web_fetch` or `github_issue_read`
- false-positive reporting tools
- local exporter state such as `inbox`, `spool`, `checkpoint`, or `upload-lease`

Classifier failures are fail-open: errors are logged, and OpenClaw execution
continues.
