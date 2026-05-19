# Silmaril Firewall Plugin for OpenClaw

Silmaril classification for OpenClaw plugin hooks.

The plugin observes OpenClaw prompt, tool-call, and tool-result hook payloads,
sends them to a Silmaril classify endpoint, and logs the returned prediction and
score. Runtime behavior is fail-open: classifier errors are logged, then
OpenClaw execution continues.

## Runtime Hooks

| OpenClaw hook | Silmaril label | Classified content |
|---|---|---|
| `before_prompt_build` | `USER_INPUT` | User prompt text |
| `before_tool_call` | `TOOL_CALL` | JSON-serialized tool parameters |
| `tool_result_persist` | `TOOL_RESPONSE` | Tool result text being persisted into context |

`before_prompt_build` and `before_tool_call` await the Silmaril SDK directly.
`tool_result_persist` is a synchronous OpenClaw hook, so the plugin starts a
fail-open classification request and returns immediately. The result is logged
when the classifier call completes.

## Files

| Path | Purpose |
|---|---|
| `index.ts` | OpenClaw plugin entrypoint and hook registration |
| `openclaw.plugin.json` | Plugin metadata and config schema |
| `package.json` | Package metadata, dependency list, and OpenClaw extension metadata |
| `scripts/build.mjs` | Builds `dist/index.js` for CLI plugin installation |
| `scripts/mock-silmaril-classifier.mjs` | Local classifier stub for manual smoke testing |
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
          "apiKey": "your-silmaril-api-key",
          "apiUrl": "https://your-endpoint.execute-api.us-west-2.amazonaws.com/alpha/classify"
        }
      }
    },
    "allow": [
      "firewall-plugin"
    ]
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

This repository supports direct source loading and two CLI install styles.

OpenClaw does not automatically discover or pull this repository by plugin id.
Start by cloning the repository onto the machine where OpenClaw runs:

```sh
git clone https://github.com/Silmaril-Security/FirewallPlugin.git
cd FirewallPlugin
git checkout simplified-dev
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
[firewall] tool_result_persist classify begin
[firewall] tool_result_persist result:
```

The mock classifier writes captured requests to the path printed on startup.
Those captures should show the hook label, tool name when available, and the
classified text length.
