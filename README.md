# Silmaril Firewall Plugin for OpenClaw

Silmaril classification for OpenClaw plugin hooks.

The plugin observes OpenClaw prompt, tool-call, and tool-result hook payloads,
sends them to a Silmaril classify endpoint, and logs the returned prediction and
score. Runtime behavior is fail-open: classifier errors are logged, then
OpenClaw execution continues. Optional enforcement is available only for the
pre-execution `before_tool_call` hook. It requires both `shadowMode: false` and
`blockMalicious: true`; all other hooks remain pass-through.

The plugin targets OpenClaw plugin API `2026.5.18` and newer. Its manifest
declares startup activation for hook capability loading, and the runtime entry
registers typed Gateway hooks with `api.on(...)`.

## Runtime Hooks

| OpenClaw hook | Silmaril label | Classified content |
|---|---|---|
| `gateway_start` | n/a | Logs plugin installation when the Gateway starts |
| `before_prompt_build` | `USER_INPUT` | User prompt text |
| `before_tool_call` | `TOOL_CALL` | JSON-serialized tool parameters; can return `{ "block": true, "blockReason": "..." }` when enforcement is explicitly enabled |
| `tool_result_persist` | `TOOL_RESPONSE` | Tool result text being persisted into context |

Hook registration is unconditional, so OpenClaw can discover and invoke the
Gateway hooks even before classifier settings are validated. Classifier config
is resolved inside each hook call.

`before_prompt_build` and `before_tool_call` await the Silmaril SDK directly
with a plugin-owned timeout. `tool_result_persist` is a synchronous OpenClaw
hook, so the plugin starts a fail-open classification request and returns
immediately. The result is logged when the classifier call completes.
Image-only and other empty tool results are skipped. Logs include hook label,
event type, tool/correlation identifiers when available, prediction, score,
threshold, and primary outcome. Raw prompts, tool parameters, and tool results
are not printed to logs or returned in block reasons.

## Files

| Path | Purpose |
|---|---|
| `index.ts` | OpenClaw plugin entrypoint and hook registration |
| `openclaw.plugin.json` | Plugin metadata and config schema |
| `package.json` | Package metadata, dependency list, and OpenClaw extension metadata |
| `scripts/build.mjs` | Builds `dist/index.js` for CLI plugin installation |
| `scripts/mock-silmaril-classifier.mjs` | Local classifier stub for manual smoke testing |
| `scripts/open-playground.mjs` | Opens or prints the public Silmaril Firewall demo URL |
| `dist/index.js` | Built plugin entrypoint used by OpenClaw's CLI install path |

## Source Checkout Configuration

Register this source checkout directly in `~/.openclaw/openclaw.json`. Preserve
the rest of the user's OpenClaw config and add the absolute repository path to
`plugins.load.paths`:

```json
{
  "plugins": {
    "load": {
      "paths": [
        "/absolute/path/to/FirewallPlugin"
      ]
    },
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": "your-plugin-or-legacy-silmaril-api-key",
          "silmarilApiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.execute-api.us-west-2.amazonaws.com/alpha/classify",
          "timeoutMs": 2500,
          "shadowMode": true,
          "blockMalicious": false
        }
      }
    },
    "allow": [
      "firewall-plugin"
    ]
  }
}
```

`apiUrl` should be the full classify endpoint URL. The plugin reads these values
from OpenClaw plugin config during hook execution. `silmarilApiKey` is preferred
for Silmaril classification when present; `apiKey` remains supported as the
legacy fallback and may otherwise be used as a plugin or OpenClaw identity key.

`timeoutMs` is optional. It defaults to `2500` and bounds each classifier
request.

`shadowMode` defaults to `true` and preserves pass-through behavior. To enable
pre-tool blocking, set both `shadowMode: false` and `blockMalicious: true`.
Blocking uses OpenClaw's documented `before_tool_call` decision shape and never
retroactively blocks persisted tool results.

Do not set `plugins.entries.firewall-plugin.hooks.allowPromptInjection=false`.
OpenClaw treats `before_prompt_build` as a prompt-mutation-capable hook, and
that setting blocks the hook registration.

By default the plugin is pass-through only. It does not cache classifier
results, add prompt/system/developer context, change assistant output, or
register wrapper tools.

Configuration precedence is intentionally OpenClaw-native: hook execution reads
`plugins.entries.firewall-plugin.config` from OpenClaw at runtime. The launcher
can read the same object from `OPENCLAW_FIREWALL_PLUGIN_CONFIG` for JSON status,
but the runtime does not use environment variables for classifier credentials.
Do not commit API keys or write them into URLs.

## Install

This repository supports direct source loading and two CLI install styles.

OpenClaw does not automatically discover or pull this repository by plugin id.
Start by cloning the repository onto the machine where OpenClaw runs:

```sh
git clone https://github.com/Silmaril-Security/FirewallPlugin.git
cd FirewallPlugin
```

The `package.json` metadata tells OpenClaw how to load the plugin after it has
access to the package. It does not publish or advertise a download location. To
install by package name, such as `openclaw plugins install
@silmaril/firewall-plugin`, the package must first be published to an npm
registry that the machine can access.

For the source checkout flow, use the `plugins.load.paths` configuration above.
The repository ships a built `dist/index.js`, so a fresh checkout can be loaded
directly. Install dependencies before starting OpenClaw, and rebuild after
editing `index.ts`:

```sh
npm install
npm run build
openclaw gateway restart
```

For OpenClaw's linked local plugin install path, build the package and install
it from the repository root:

```sh
npm install
npm run build
openclaw plugins install -l .
openclaw plugins enable firewall-plugin
openclaw gateway restart
```

For a clean installable archive, build and pack the plugin, then install the
generated tarball:

```sh
npm install
npm run build
npm pack
openclaw plugins install ./silmaril-firewall-plugin-1.0.0.tgz
openclaw plugins enable firewall-plugin
openclaw gateway restart
```

Use `plugins.load.paths` when you want OpenClaw to load this checkout directly.
Use `openclaw plugins install -l .` when you want OpenClaw to register this
checkout as a linked local plugin. Use the `.tgz` flow when you want the
installer to consume only the packaged files listed by `package.json`. All flows
use the same plugin id, `firewall-plugin`, and the same
`plugins.entries.firewall-plugin.config` settings.

Inspect the installed plugin:

```sh
openclaw --no-color plugins inspect firewall-plugin --runtime
```

Expected shape:

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

Run diagnostics:

```sh
openclaw --no-color plugins doctor
```

## Public Demo

The demo launcher opens the hosted Silmaril Firewall UI at
`https://app.silmaril.dev/demo/setup-complete`. It does not serve a local UI,
start a credential proxy, or put the Silmaril API key in the URL, chat, or
launcher output.

Run it from the repository root:

```sh
node scripts/open-playground.mjs
node scripts/open-playground.mjs --open
node scripts/open-playground.mjs --route playground --json
```

For preview validation, override the hosted base URL:

```sh
SILMARIL_DEMO_BASE_URL="http://localhost:3001" node scripts/open-playground.mjs
```

To show whether local OpenClaw plugin config is complete without printing the
secret key or classifier endpoint, pass the plugin config as JSON:

```sh
OPENCLAW_FIREWALL_PLUGIN_CONFIG='{"apiUrl":"https://.../classify","silmarilApiKey":"..."}' \
  node scripts/open-playground.mjs --json
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
[firewall] tool_result_persist result:
```

The mock classifier writes captured requests to the path printed on startup.
Those captures should show the hook label, tool name when available, and the
classified text length.

## License

This plugin is licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
