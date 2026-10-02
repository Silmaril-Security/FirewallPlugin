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
- `before_prompt_build` classifies prompt text as `USER_INPUT`. Warn mode can
  return `{ prependContext }` with one fixed content-free warning. Block mode
  leaves this hook unchanged and does not record `blockUnavailable` here
- `before_agent_run` classifies the final agent prompt as `USER_INPUT`. When
  the effective mode is `block` and `prediction === "MALICIOUS"`, it can return
  `{ outcome: "block", reason }`
- `before_prompt_build` and `before_agent_run` share one content-sensitive
  classification for five seconds
- `before_tool_call` sends JSON-serialized tool parameters as `TOOL_CALL` and
  can return `{ block: true, blockReason }` under that same block rule
- `after_tool_call` classifies tool result text as `TOOL_RESPONSE` and does not
  block. A malicious Block-mode result records native action `unavailable` and
  `blockUnavailable: true`
- `tool_result_persist` starts a fail-open classification request for persisted
  tool result text as `TOOL_RESPONSE` and logs the result when the request
  completes; this external hook is observe-only and cannot replace tool results.
  A malicious Block-mode result records the same unavailable action
- `message_sending` classifies final outbound assistant message text as
  `LLM_OUTPUT`. Block mode can return `{ cancel: true, cancelReason }` with no
  replacement content field
- `reply_payload_sending` classifies normalized delivery payload text as
  `LLM_OUTPUT`. Block mode can return `{ cancel: true }` and leaves the payload
  unchanged
- `message_sending` and `reply_payload_sending` share one content-sensitive
  classification for five seconds; changed content is classified separately
- `message_sent` emits content-free delivery telemetry without a classifier call
- `subagent_delivery_target`, `subagent_spawned`, and `subagent_ended` classify
  lifecycle text for visibility and log sanitized summaries without enforcement.
  A malicious Block-mode result records native action `unavailable`
- `scripts/open-playground.mjs` opens or prints the hosted Silmaril Firewall
  demo URL without serving local UI or reading or printing classifier config
- hook registration is unconditional; classifier config is resolved when each
  hook runs
- Shadow adds no agent-visible context. Warn can prepend the fixed
  `before_prompt_build` warning. The plugin adds no system or developer context
- no wrapper tools, exporters, or queues are registered
- classifier errors fail open and OpenClaw execution continues
- raw prompt, tool input, and tool output text is not logged or returned in
  block reasons. Block text is `Silmaril Firewall blocked this request: <risk label>. Continue without using the blocked content.`

Configuration fields:

- `silmarilApiKey`: preferred Silmaril classifier API key
- `apiKey`: legacy Silmaril API key fallback; may remain the plugin identity key
  when `silmarilApiKey` is present
- `apiUrl`: full Silmaril classify endpoint URL, ending in `/classify`
- `endpointId`: optional canonical UUID v4. Invalid values are ignored.
  Classifier requests still include harness provenance. On macOS that provenance
  can include the local computer name, and classification does not wait for the
  lookup
- `timeoutMs`: optional classifier timeout in milliseconds. Finite numbers,
  including numeric strings, are truncated toward zero and then kept when that
  integer is from `250` through `10000`. Omitted, non-finite, or out-of-range
  values use `2500`
- `mode`: optional `shadow`, `warn`, or `block` override. A set value wins over
  the legacy booleans below and over `mode` on the classifier response
- `shadowMode`: legacy flag. `true` forces Shadow, including when
  `blockMalicious` is `true`. The schema does not default this field
- `blockMalicious`: legacy flag. `true` selects Block only when `mode` is unset
  and `shadowMode` is not `true`. `shadowMode: false` with `blockMalicious`
  omitted or `false` stays Shadow

Omitting `mode` and both legacy flags leaves the plugin mode unset. The
effective mode is then the classifier response mode, or Shadow when the
response has no mode. Only an exact `prediction === "MALICIOUS"` is enforceable.

The plugin entry must also set `hooks.allowConversationAccess=true`; OpenClaw
otherwise blocks `before_agent_run` for non-bundled plugins.

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
           "hooks": {
             "allowConversationAccess": true
           },
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

   This example sets the legacy flags to Shadow. Set `mode` to `warn` or
   `block` when that override should win over the legacy flags.

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
   openclaw plugins install ./silmaril-security-firewall-plugin-1.2.4.tgz
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

   `openclaw plugins inspect firewall-plugin --runtime` loads the module in the
   inspecting CLI and reports `Status: loaded` plus the typed hooks registered
   in `index.ts`. Runtime inspection verifies those registrations in the CLI
   process. An actual hook event, such as `firewall-plugin: installed` in the
   smoke test below, is the running Gateway proof.

11. Optional hosted demo walkthrough:

    ```sh
    node scripts/open-playground.mjs --open
    ```

    The launcher prints or opens
    `https://app.silmaril.dev/demo/setup-complete`. It does not put credentials
    or classifier endpoints in the URL or output. Use the user's configured
    `silmarilApiKey` only in the demo page fields during an authorized setup
    flow.

12. Run a manual smoke test:

    ```sh
    openclaw agent --agent main --message "Reply with FIREWALL_PLUGIN_SMOKE_OK."
    ```

    Then run a tool-using prompt appropriate for the user's configured agent.
    The plugin emits these lines when the corresponding hook classifies.
    `before_prompt_build` and `before_agent_run` share the prompt cache, and
    `message_sending` and `reply_payload_sending` share the outbound cache. The
    same classified text and conversation within five seconds reuses that
    classification when the stable event id matches, or when neither hook has
    one, and does not emit a second `result:` line. Hook
    registration and a running Gateway event such as `firewall-plugin: installed`
    stay independent of those cache hits.

    ```text
    firewall-plugin: installed
    [firewall] before_prompt_build result:
    [firewall] before_agent_run result:
    [firewall] before_tool_call result:
    [firewall] after_tool_call result:
    [firewall] tool_result_persist result:
    [firewall] message_sending result:
    [firewall] reply_payload_sending result:
    [firewall] message_sent observed:
    ```

    Subagent lifecycle lines are emitted only when those hooks run. Lines ending
    in `blocked:` appear when the effective mode is `block` and the classifier
    returns `prediction` `MALICIOUS`.

## Failure Handling

If installation or verification fails, collect:

- the exact command
- exit code
- relevant `openclaw --no-color plugins inspect firewall-plugin --runtime` output
- relevant metadata-only `openclaw --no-color plugins inspect firewall-plugin`
  output when registry status is needed; that cold inspect reports enabled,
  disabled, or error and does not report `Status: loaded`
- relevant `openclaw --no-color plugins doctor` output
- relevant gateway log lines

Do not patch plugin code or OpenClaw
core files during onboarding.
