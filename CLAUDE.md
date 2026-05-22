# Claude Code Onboarding Notes

This repository is an OpenClaw plugin. Use this file when onboarding the plugin
into an OpenClaw setup.

## Operating Boundary

During onboarding, do not modify plugin source code, generated package files, or
core OpenClaw files. Treat onboarding as an install, configuration, and
verification task only.

Allowed onboarding changes:

- install npm dependencies for this repository
- build this repository with `npm run build`
- clone or update this repository
- register this source checkout through `plugins.load.paths` in the user's
  OpenClaw config
- install this repository through `openclaw plugins install -l .`; this is the
  default Claude Code onboarding path
- create an npm package tarball with `npm pack` when the user wants a clean
  installable archive
- add or update the `firewall-plugin` entry in the user's OpenClaw config
- run OpenClaw diagnostics, inspect commands, gateway restarts, and manual smoke
  tests

Do not edit files under the OpenClaw CLI installation, OpenClaw stock extension
directories, OpenClaw package files, this plugin's source files, this plugin's
build files, or this plugin's runtime scripts while onboarding. If onboarding
exposes a code defect, stop after collecting evidence and suggest the smallest
source change instead of making it.

Do not add wrappers, exporters, queues, enforcement behavior, test harnesses,
mock infrastructure, or repository scripts as part of onboarding unless the
user explicitly asks for source changes.

## Current Plugin Shape

Plugin id: `firewall-plugin`

Source file: `index.ts`

OpenClaw runtime entrypoint: `dist/index.js`

Runtime behavior:

- the manifest declares Gateway startup activation for OpenClaw hook capability
  loading
- `gateway_start` logs `firewall-plugin: installed` when the Gateway invokes
  startup hooks
- `before_prompt_build` sends user prompt text as `USER_INPUT`
- `before_message_write` consumes a cached user-input risk record for the
  matching assistant message after inference
- `before_tool_call` sends JSON-serialized tool parameters as `TOOL_CALL`
- `tool_result_persist` starts a fail-open classification request for persisted
  tool result text as `TOOL_RESPONSE` and logs the result when the request
  completes
- hook registration is unconditional; classifier config is resolved when each
  hook runs
- shadow mode defaults to on: unset `SILMARIL_FIREWALL_SHADOW_MODE` behaves the
  same as `SILMARIL_FIREWALL_SHADOW_MODE=true`
- malicious `before_prompt_build` classifications are cached as short-lived
  in-memory risk records instead of being added to model context or assistant
  output
- cached risk records use exact keys when available (`runId`, `traceId`,
  `idempotencyKey`, and scoped run combinations), plus an
  `agentId`/`sessionKey` FIFO fallback for current `before_message_write`
  contexts that do not expose `runId`; TTL and the global record cap bound
  memory
- `before_message_write` consumes the matching cached risk record and logs the
  cache consumption; it does not mutate the assistant message
- no warning, stub, prompt, system, or developer context is added in either mode
- `SILMARIL_FIREWALL_SHADOW_MODE` is parsed only for startup logging; when it
  is enabled, `gateway_start` logs `firewall-plugin: Silmaril is in shadow mode`
- benign `before_prompt_build` classifications do not populate the risk cache
- classifier errors fail open

Configuration fields:

- `silmarilApiKey`: preferred Silmaril classifier API key
- `apiKey`: legacy Silmaril API key fallback; may remain the plugin identity key
  when `silmarilApiKey` is present
- `apiUrl`: full Silmaril classify endpoint URL, ending in `/classify`
- `timeoutMs`: optional classifier timeout in milliseconds; default `2500`
- `toolResultMaxInFlight`: optional asynchronous tool-result classification
  concurrency limit; default `8`

Do not set `plugins.entries.firewall-plugin.hooks.allowPromptInjection=false`.
OpenClaw treats `before_prompt_build` as a prompt-mutation-capable hook, and
that setting blocks the hook registration.

## Fresh OpenClaw Setup

Use these steps when OpenClaw is not already configured and this repository is
not already cloned.

Default install rule for Claude Code: after cloning and building this repository,
run `openclaw plugins install -l .` from the repository root. Do not choose the
manual `plugins.load.paths` source checkout flow unless the user explicitly asks
for direct source loading or the CLI install path is unavailable.

1. Verify prerequisites:

   ```sh
   git --version
   node --version
   npm --version
   ```

2. Install the OpenClaw CLI if it is not available:

   ```sh
   npm install -g openclaw
   openclaw --version
   ```

3. Initialize OpenClaw local state:

   ```sh
   openclaw setup
   openclaw onboard
   ```

   Follow the prompts to configure the gateway, default workspace, model
   provider, and credentials. Keep provider credentials in OpenClaw's config or
   secrets storage; do not write secrets into this repository.

4. Clone this repository and select the simplified branch:

   ```sh
   git clone https://github.com/Silmaril-Security/FirewallPlugin.git
   cd FirewallPlugin
   git checkout simplified-dev
   ```

5. Install repository dependencies:

   ```sh
   npm install
   npm run build
   ```

6. Install the plugin with OpenClaw's linked local plugin flow.

   Run these commands from the repository root. This is the normal onboarding
   path for Claude Code:

   ```sh
   openclaw plugins install -l .
   openclaw plugins enable firewall-plugin
   ```

   The `-l` flag links the local checkout instead of copying it. OpenClaw reads
   this repository's `package.json`, then loads the built entrypoint at
   `dist/index.js`.

7. Add or update the plugin config in the user's OpenClaw config.

   Preserve unrelated OpenClaw config. Do not hand-edit
   `plugins.installs`. Add `firewall-plugin` to `plugins.allow` when that list
   exists, and add or update the `plugins.entries.firewall-plugin` entry:

   ```json
   {
     "plugins": {
       "entries": {
         "firewall-plugin": {
           "enabled": true,
           "config": {
             "apiKey": "<PLUGIN_OR_LEGACY_SILMARIL_API_KEY>",
             "silmarilApiKey": "<SILMARIL_API_KEY>",
             "apiUrl": "https://<api-id>.execute-api.<region>.amazonaws.com/alpha/classify",
             "timeoutMs": 2500,
             "toolResultMaxInFlight": 8
           }
         }
       },
       "allow": [
         "firewall-plugin"
       ]
     }
   }
   ```

8. Alternative install flows.

   Use these only when the user explicitly asks for a different install style or
   when `openclaw plugins install -l .` is unavailable.

   Direct source checkout flow: register the checkout through
   `plugins.load.paths` instead of using the CLI install command.

   ```json
   {
     "plugins": {
       "load": {
         "paths": [
           "/absolute/path/to/FirewallPlugin"
         ]
       }
     }
   }
   ```

   Clean archive flow: pack the plugin and install the generated tarball:

   ```sh
   npm pack
   openclaw plugins install ./silmaril-firewall-plugin-1.0.0.tgz
   openclaw plugins enable firewall-plugin
   ```

   The source checkout flow, linked plugin flow, and archive flow all use the
   same plugin id and the same `plugins.entries.firewall-plugin.config` values.
   Do not remove an existing source checkout registration unless the user
   explicitly asks to switch install styles.

9. Restart the gateway:

   ```sh
   openclaw gateway restart
   ```

10. Verify plugin load:

   ```sh
   openclaw --no-color plugins inspect firewall-plugin --runtime
   openclaw --no-color plugins doctor
   openclaw --no-color gateway status
   ```

   Expected inspect output includes:

   ```text
   Status: loaded
   Format: openclaw
   Shape: hook-only
   Typed hooks:
   gateway_start
   before_prompt_build
   before_message_write
   before_tool_call
   tool_result_persist
   ```

11. Run a manual smoke test:

    ```sh
    openclaw agent --agent main --message "Reply with FIREWALL_PLUGIN_SMOKE_OK."
    ```

    Then run a tool-using prompt appropriate for the user's configured agent and
    inspect gateway logs for the install confirmation and firewall
    classification lines:

    ```text
    firewall-plugin: installed
    firewall-plugin: Silmaril is in shadow mode
    [firewall] before_prompt_build result:
    [firewall] before_prompt_build risk cached:
    [firewall] before_message_write risk cache consumed:
    [firewall] before_tool_call result:
    [firewall] tool_result_persist classify begin
    [firewall] tool_result_persist result:
    ```

## Failure Handling

If installation or verification fails, collect:

- the exact command
- exit code
- relevant `openclaw --no-color plugins inspect firewall-plugin` output
- relevant `openclaw --no-color plugins doctor` output
- relevant gateway log lines

Do not patch plugin code or OpenClaw
core files during onboarding.
