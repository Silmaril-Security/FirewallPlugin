# Silmaril Firewall Plugin for OpenClaw

Silmaril classification and native blocked-decision visibility for OpenClaw
plugin hooks.

The plugin observes OpenClaw agent, tool, message, delivery, and subagent
lifecycle payloads, sends them to a Silmaril classify endpoint, and renders
blocked decisions as readable text or native `MessagePresentation` payloads
where OpenClaw supports them. Runtime behavior is fail-open: classifier errors
are logged, then OpenClaw execution continues. Optional enforcement applies at
every boundary this external plugin can control: `before_agent_run` stops unsafe
model submissions, `before_tool_call` blocks pending tool calls,
`message_sending` cancels malicious outbound assistant messages, and
`reply_payload_sending` replaces unsafe delivery payloads with a safe status
notice. It requires both `shadowMode: false` and `blockMalicious: true`.

The plugin requires OpenClaw plugin API `2026.5.28` or newer and is tested with
OpenClaw `2026.7.1-2`. Its manifest declares startup activation for hook
capability loading, and the runtime entry registers typed Gateway hooks with
`api.on(...)`.

## Runtime Hooks

| OpenClaw hook | Silmaril label | Classified content |
|---|---|---|
| `gateway_start` | n/a | Logs plugin installation when the Gateway starts |
| `before_agent_run` | `USER_INPUT` | Final agent prompt/message payload before model submission; can return OpenClaw's native block shape with a readable message |
| `before_tool_call` | `TOOL_CALL` | Tool parameters; can return `{ "block": true, "blockReason": "..." }` when enforcement is explicitly enabled |
| `after_tool_call` | `TOOL_RESPONSE` | Tool result text immediately after execution, including child-agent tool calls |
| `tool_result_persist` | `TOOL_RESPONSE` | Tool result text being persisted into context; observe-only because external OpenClaw plugins cannot replace tool results |
| `message_sending` | `LLM_OUTPUT` | Final outbound assistant message text; can return `{ "cancel": true, "content": "..." }` with a safe replacement summary when enforcement is explicitly enabled |
| `reply_payload_sending` | `LLM_OUTPUT` | Normalized delivery payload; can replace unsafe payloads with readable text plus native `MessagePresentation` |
| `message_sent` | n/a | Logs content-free delivery telemetry; does not reclassify delivered content |
| `subagent_delivery_target` | `USER_INPUT` | Subagent delivery routing payload; observe-only compatibility hook |
| `subagent_spawned` | `USER_INPUT` | Subagent spawn lifecycle payload; observe-only in OpenClaw |
| `subagent_ended` | `LLM_OUTPUT` | Subagent completion payload; observe-only in OpenClaw |

Hook registration is unconditional, so OpenClaw can discover and invoke the
Gateway hooks even before classifier settings are validated. Classifier config
is resolved inside each hook call.

Enforceable hooks await Silmaril SDK 0.5.0 with a plugin-owned timeout.
`tool_result_persist` and subagent lifecycle hooks classify for visibility but
do not claim to block because OpenClaw exposes them as observer or compatibility
surfaces. `message_sending` and `reply_payload_sending` share a short-lived,
content-sensitive result so duplicate callbacks make one SDK request; changed
content is classified separately. Image-only and other empty payloads are
skipped. Only `prediction === "MALICIOUS"` is enforceable. User-visible and
model-visible feedback never includes raw classifier JSON, numeric scores or
thresholds, detector maps, metadata dumps, or the original sensitive payload.

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
        "hooks": {
          "allowConversationAccess": true
        },
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

OpenClaw requires `hooks.allowConversationAccess: true` for a non-bundled
plugin to receive `before_agent_run`. Without that host permission, OpenClaw
loads the remaining hooks but skips prompt classification and reports a plugin
diagnostic.

`timeoutMs` is optional. It defaults to `2500` and bounds each classifier
request.

`shadowMode` defaults to `true` and preserves pass-through behavior. To enable
blocking at every supported boundary, set both `shadowMode: false` and
`blockMalicious: true`. Blocking uses OpenClaw's documented native decision
shapes for agent prompts, tool calls, assistant messages, and delivery payload
replacement. The external plugin cannot retroactively block or replace persisted
tool results, and OpenClaw's `subagent_spawned`, `subagent_ended`, and
`subagent_delivery_target` hooks are observer or routing hooks. Child-agent tool
calls and tool results still pass through `before_tool_call`/`after_tool_call`
inside the child execution path and are scanned there.

By default the plugin is pass-through only. Apart from the bounded outbound
delivery deduplication window, it does not cache classifier results, add
prompt/system/developer context, or register wrapper tools.

Configuration precedence is intentionally OpenClaw-native: hook execution reads
`plugins.entries.firewall-plugin.config` from OpenClaw at runtime. The launcher
prints only the public demo URL and does not read or echo classifier
configuration values. Do not commit API keys or write them into URLs.

## Local protection evidence

Flagged Block and Shadow decisions emit one bounded
`LocalProtectionEventV1` JSON file for the local Silmaril app. Set
`SILMARIL_LOCAL_EVENT_DIR` to override the spool directory; otherwise files go
to `~/Library/Application Support/Silmaril/Evidence/incoming`.

Publication uses a private temporary file followed by an atomic rename. The
directory is mode `0700` and event files are mode `0600`. Emission is
best-effort: filesystem failures never change the native OpenClaw decision.

Events contain hashes, bounded risk metadata, classifier diagnostics, policy,
and the action returned to OpenClaw. They never contain raw prompts, inputs,
outputs, tool arguments, or credential values. Because the plugin does not
independently observe downstream execution, it reports
`evidenceTruth: plugin_reported` and `outcome: not_observed`; a native block
response is not represented as independently verified prevention.

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
openclaw plugins install ./silmaril-firewall-plugin-1.1.1.tgz
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
before_agent_run
before_tool_call
after_tool_call
tool_result_persist
message_sending
reply_payload_sending
message_sent
subagent_delivery_target
subagent_spawned
subagent_ended
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

For machine-readable automation output, pass `--json`:

```sh
node scripts/open-playground.mjs --json
```

The JSON output intentionally contains only the public demo URL and no OpenClaw
configuration status, classifier endpoint, or API key fields.

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
[firewall] before_agent_run result:
[firewall] before_tool_call result:
[firewall] after_tool_call result:
[firewall] tool_result_persist result:
[firewall] message_sending result:
[firewall] reply_payload_sending result:
[firewall] message_sent observed:
[firewall] subagent_delivery_target result:
[firewall] subagent_spawned result:
[firewall] subagent_ended result:
```

The mock classifier writes captured requests to the path printed on startup.
Those captures should show the hook label, tool name when available, and the
classified text length.

## License

This plugin is licensed under Apache-2.0. See `LICENSE` and `NOTICE`.
