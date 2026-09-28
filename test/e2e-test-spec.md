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
model_call_started
model_call_ended
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

## Agent model Gateway acceptance

This checks captured classifier POST bodies, not only hook registration.
`model_call_started` and `model_call_ended` must not themselves be classifier
requests. A later classified request carries `metadata.silmaril.agent_model_id`
only while that model call is in flight.

The openclaw CLI is not installed in the environment that added this procedure,
so the Gateway steps below were not executed here. `npm test` checks
`scripts/check-agent-model-capture.mjs` against fixture JSONL and against POSTs
made directly to the local recorder. Those passes are not a Gateway result.
Run the procedure on a machine with OpenClaw 2026.7.1-2 or newer. Do not point
an existing Gateway at the recorder and do not edit `~/.openclaw`.

1. From this repository, after `npm run build`, start the recorder with a
   disposable capture file:

   ```sh
   CAPTURE="$(mktemp)"
   READY="$(mktemp)"
   SILMARIL_CLASSIFIER_CAPTURE_PATH="$CAPTURE" \
     SILMARIL_CLASSIFIER_READY_PATH="$READY" \
     node scripts/mock-silmaril-classifier.mjs
   ```

   Read `url` from `$READY`. The process listens on `127.0.0.1` only.

2. Create a disposable OpenClaw state directory and config. Export
   `OPENCLAW_STATE_DIR` to that directory for every `openclaw` command in this
   procedure. Set `plugins.entries.firewall-plugin` to this built checkout,
   `hooks.allowConversationAccess` true, `shadowMode` true, `blockMalicious`
   false, any non-empty `silmarilApiKey`, and `apiUrl` to the recorder `url`.
   Install and enable `firewall-plugin` only inside that state directory, then
   start that Gateway.

3. Choose two different host model ids the Gateway will put on
   `model_call_started.model`. Record those strings from the agent result or
   gateway log (`model` / `modelId`), not from the classifier capture and not
   from a provider name alone.

4. Run a tool-using turn on the first model, then a second tool-using turn on
   the second model. Use a new message for each turn so OpenClaw assigns a new
   `runId`. Example:

   ```sh
   openclaw agent --agent main --model <provider>/<first-model> \
     --message "Read README.md with the read tool, then reply with its first heading."
   openclaw agent --agent main --model <provider>/<second-model> \
     --message "Read package.json with the read tool, then reply with the name field."
   ```

   Each turn must actually emit `before_tool_call`. A turn that never calls a
   tool does not satisfy this procedure.

5. Stop the recorder. Run the checker with the host model strings from step 3:

   ```sh
   node scripts/check-agent-model-capture.mjs \
     --capture "$CAPTURE" \
     --first-model "<first-host-model>" \
     --second-model "<second-host-model>"
   ```

   The checker exits 0 only when the capture shows all of the following:

   - `before_agent_run` or `before_prompt_build` for the first run has no
     `metadata.silmaril.agent_model_id`. That early prompt is unknown.
   - A `before_tool_call` for that same `runId` has
     `metadata.silmaril.agent_model_id` equal to the first host model, and
     `metadata.silmaril.provenance.harness` is `openclaw`. `after_tool_call`
     during that call may carry the same id.
   - The second run's early prompt also omits `agent_model_id`. It must appear
     after the first run's tool POST, which is the post-`model_call_ended`
     observation available on this host.
   - A `before_tool_call` for the second `runId` has `agent_model_id` equal to
     the second host model and does not reuse the first model.
   - No POST uses `eventType` `model_call_started` or `model_call_ended`.
   - `message_sending`, `reply_payload_sending`, `message_sent`, and
     `tool_result_persist` omit `agent_model_id`. Current OpenClaw outbound
     hooks do not include `runId`, so they cannot prove an in-flight model
     after the call ends.

   One run that contains a `before_tool_call` for the first model and a later
   `before_tool_call` for the second model also satisfies the switch. A later
   same-run non-tool POST that still includes `agent_model_id` fails the check.

6. Cleanup, even when a step fails: terminate the recorder, delete `$CAPTURE`,
   `$READY`, and the disposable `OPENCLAW_STATE_DIR`, and leave the operator's
   normal Gateway and `~/.openclaw` unchanged.

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
