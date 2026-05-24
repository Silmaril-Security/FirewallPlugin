# Pass-Through E2E Test Spec

This plugin is currently pass-through only. It sends OpenClaw hook payloads to
the configured Silmaril classify endpoint, logs classifier results, and does not
change OpenClaw behavior.

## Expected Plugin Shape

`openclaw --no-color plugins inspect firewall-plugin --runtime` should show:

```text
Status: loaded
Format: openclaw
Shape: hook-only
Typed hooks:
gateway_start
before_prompt_build
before_tool_call
tool_result_persist
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
        "config": {
          "silmarilApiKey": "<silmaril-api-key>",
          "apiUrl": "https://<api-id>.execute-api.<region>.amazonaws.com/alpha/classify",
          "timeoutMs": 2500
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
[firewall] before_prompt_build result:
[firewall] before_tool_call result:
[firewall] tool_result_persist result:
```

If classifier config is missing, the plugin should warn once and log skipped
classifications with `missing_config`.

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
