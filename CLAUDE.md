# Claude Code Onboarding Notes

This repository is an OpenClaw plugin. Use this file when onboarding the plugin
into an OpenClaw setup.

## Operating Boundary

During onboarding, do not modify plugin source code, generated package files, or
core OpenClaw files. Treat onboarding as an install, configuration, and
verification task only.

Allowed onboarding changes:

- install npm dependencies for this repository
- clone or update this repository
- install or enable the plugin through the OpenClaw CLI
- add or update the `firewall-plugin` entry in the user's OpenClaw config
- run OpenClaw diagnostics, inspect commands, gateway restarts, and manual smoke
  tests

Do not edit files under the OpenClaw CLI installation, OpenClaw stock extension
directories, OpenClaw package files, this plugin's source files, or this
plugin's runtime scripts while onboarding. If onboarding exposes a code defect,
stop after collecting evidence and suggest the smallest source change instead
of making it.

Do not add wrappers, exporters, queues, enforcement behavior, test harnesses,
mock infrastructure, or repository scripts as part of onboarding unless the
user explicitly asks for source changes.

## Current Plugin Shape

Plugin id: `firewall-plugin`

Entrypoint: `index.ts`

Runtime behavior:

- `before_prompt_build` sends user prompt text as `USER_INPUT`
- `before_tool_call` sends JSON-serialized tool parameters as `TOOL_CALL`
- `tool_result_persist` sends persisted tool result text as `TOOL_RESPONSE`
- classifier errors and sync-worker failures fail open

Configuration fields:

- `apiKey`: Silmaril API key
- `apiUrl`: full Silmaril classify endpoint URL, ending in `/classify`

## Fresh OpenClaw Setup

Use these steps when OpenClaw is not already configured and this repository is
not already cloned.

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
   ```

6. Install and enable the local plugin:

   ```sh
   openclaw plugins install -l .
   openclaw plugins enable firewall-plugin
   ```

7. Add the plugin config to the user's OpenClaw config:

   ```json
   {
     "plugins": {
       "entries": {
         "firewall-plugin": {
           "enabled": true,
           "config": {
             "apiKey": "<SILMARIL_API_KEY>",
             "apiUrl": "https://<api-id>.execute-api.<region>.amazonaws.com/alpha/classify"
           }
         }
       }
     }
   }
   ```

   Preserve unrelated OpenClaw config. Only add or update
   `plugins.entries.firewall-plugin`.

8. Restart the gateway:

   ```sh
   openclaw gateway restart
   ```

9. Verify plugin load:

   ```sh
   openclaw --no-color plugins inspect firewall-plugin
   openclaw --no-color plugins doctor
   openclaw --no-color gateway status
   ```

   Expected inspect output includes:

   ```text
   Status: loaded
   Format: openclaw
   Shape: hook-only
   Typed hooks:
   before_prompt_build
   before_tool_call
   tool_result_persist
   ```

10. Run a manual smoke test:

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
    [firewall] tool_result_persist sync classify begin
    [firewall] tool_result_persist sync result:
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
