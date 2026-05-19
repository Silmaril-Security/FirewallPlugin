# Silmaril Firewall Plugin for OpenClaw

Silmaril classification for OpenClaw plugin hooks.

The plugin observes OpenClaw prompt, tool-call, and tool-result hook payloads,
sends them to a Silmaril classify endpoint, and logs the returned prediction and
score. Runtime behavior is fail-open: classifier errors and sync-worker failures
are logged, then OpenClaw execution continues.

## Runtime Hooks

| OpenClaw hook | Silmaril label | Classified content |
|---|---|---|
| `before_prompt_build` | `USER_INPUT` | User prompt text |
| `before_tool_call` | `TOOL_CALL` | JSON-serialized tool parameters |
| `tool_result_persist` | `TOOL_RESPONSE` | Tool result text being persisted into context |

`before_prompt_build` and `before_tool_call` call the Silmaril SDK directly.
`tool_result_persist` is handled through
`scripts/firewall-classify-worker.mjs`, a short-lived Node worker. The worker
lets the plugin classify persisted tool output while keeping the hook handler
synchronous.

## Files

| Path | Purpose |
|---|---|
| `index.ts` | OpenClaw plugin entrypoint and hook registration |
| `openclaw.plugin.json` | Plugin metadata and config schema |
| `package.json` | Package metadata, dependency list, and OpenClaw extension metadata |
| `scripts/firewall-classify-worker.mjs` | Synchronous classification worker for `tool_result_persist` |
| `scripts/mock-silmaril-classifier.mjs` | Local classifier stub for manual smoke testing |

## Configuration

Add the plugin entry to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.execute-api.us-west-2.amazonaws.com/alpha/classify"
        }
      }
    }
  }
}
```

`apiUrl` should be the full classify endpoint URL. The plugin reads both values
from `api.pluginConfig` during registration.

## Shadow Mode

Shadow mode is controlled by the optional `SILMARIL_FIREWALL_SHADOW_MODE`
environment variable. It defaults to `true`.

With shadow mode enabled, the plugin classifies hook payloads and logs the
results without changing the model context or surfacing a user-facing warning.
Benign and malicious classifications keep the user experience unchanged.

When `SILMARIL_FIREWALL_SHADOW_MODE=false`, a malicious `before_prompt_build`
classification prepends a strict advisory to the model's system context for
that turn. That advisory asks the model to begin the user-facing response with:

```text
Silmaril's Firewall found this to be suspicious. Please proceed carefully.
```

The strict advisory tells the model not to proceed with the latest user request.
It should not complete the requested task, follow the latest input, or call
tools on behalf of that input. Benign classifications keep the user experience
unchanged in both modes.

Accepted false values are `false`, `0`, `no`, and `off`. Accepted true values
are `true`, `1`, `yes`, and `on`.

## Install

From the repository root:

```sh
npm install
openclaw plugins install -l .
openclaw plugins enable firewall-plugin
openclaw gateway restart
```

Inspect the installed plugin:

```sh
openclaw --no-color plugins inspect firewall-plugin
```

Expected shape:

```text
Status: loaded
Format: openclaw
Shape: hook-only
Typed hooks:
before_prompt_build
before_tool_call
tool_result_persist
```

Run diagnostics:

```sh
openclaw --no-color plugins doctor
```

## Manual Smoke Test

For a local smoke test, start the mock classifier:

```sh
node scripts/mock-silmaril-classifier.mjs
```

Set the plugin `apiUrl` to the mock classifier URL printed by the script, set
any non-empty test API key, then restart OpenClaw:

```sh
openclaw gateway restart
```

Send a normal OpenClaw message, then send a message that uses at least one tool.
Check the gateway logs for the install confirmation and classification entries:

```text
firewall-plugin: installed
[firewall] before_prompt_build result:
[firewall] before_tool_call result:
[firewall] tool_result_persist sync classify begin
[firewall] tool_result_persist sync result:
```

The mock classifier writes captured requests to the path printed on startup.
Those captures should show the hook label, tool name when available, and the
classified text length.
