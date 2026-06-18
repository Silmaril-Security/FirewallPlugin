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
- open or print the hosted Silmaril Firewall demo URL with
  `node scripts/open-playground.mjs`
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
- `before_tool_call` sends JSON-serialized tool parameters as `TOOL_CALL`
- `before_tool_call` can return `{ block: true, blockReason }` only when
  `shadowMode=false` and `blockMalicious=true`
- `tool_result_persist` starts a fail-open classification request for persisted
  tool result text as `TOOL_RESPONSE` and logs the result when the request
  completes
- `scripts/open-playground.mjs` opens or prints the hosted Silmaril Firewall
  demo URL without serving local UI or printing the API key
- hook registration is unconditional; classifier config is resolved when each
  hook runs
- no classifier result is cached or consumed later
- no warning, stub, prompt, system, or developer context is added
- assistant output is not changed
- no wrapper tools, exporters, queues, or post-execution enforcement behavior
  are registered
- classifier errors fail open
- raw prompt, tool input, and tool output text is not logged or returned in
  block reasons

Configuration fields:

- `silmarilApiKey`: preferred Silmaril classifier API key
- `apiKey`: legacy Silmaril API key fallback; may remain the plugin identity key
  when `silmarilApiKey` is present
- `apiUrl`: full Silmaril classify endpoint URL, ending in `/classify`
- `timeoutMs`: optional classifier timeout in milliseconds; default `2500`
- `shadowMode`: optional pass-through mode; default `true`
- `blockMalicious`: optional malicious `before_tool_call` blocking; default
  `false`; only effective when `shadowMode=false`

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

4. Clone this repository:

   ```sh
   git clone https://github.com/Silmaril-Security/FirewallPlugin.git
   cd FirewallPlugin
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
    before_tool_call
    tool_result_persist
   ```

11. Optional hosted demo walkthrough:

    ```sh
    node scripts/open-playground.mjs --open
    ```

    The launcher prints or opens
    `https://app.silmaril.dev/demo/setup-complete`. It does not put credentials
    in the URL or output. Use the user's configured `silmarilApiKey` only in
    the demo page fields during an authorized setup flow.

12. Run a manual smoke test:

    ```sh
    openclaw agent --agent main --message "Reply with FIREWALL_PLUGIN_SMOKE_OK."
    ```

    Then run a tool-using prompt appropriate for the user's configured agent and
    inspect gateway logs for the install confirmation and firewall
    classification lines:

    ```text
    firewall-plugin: installed
    [firewall] before_prompt_build result:
    [firewall] before_tool_call result:
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
