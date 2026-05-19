# Silmaril Firewall Plugin for OpenClaw

Hook-level prompt-injection detection for OpenClaw.

This branch is intentionally wrapper-free. The plugin does not register tools,
does not register a `silmaril-firewall` web fetch provider, and does not replace
OpenClaw's built-in `web_fetch`. It only observes OpenClaw's plugin hooks and
sends those hook payloads to Silmaril for classification.

Classification is observe-only and fail-open. The plugin logs Silmaril
classification results, but it does not block prompts, block tool calls,
sanitize tool results, or change OpenClaw execution based on the prediction.
Classifier errors and sync-worker failures are logged and then OpenClaw
continues.

There is no log exporter, local queue, inbox, checkpoint, or upload-lease flow
in this branch.

## Runtime Surface

| Hook | Silmaril label | What it inspects |
|---|---|---|
| `before_prompt_build` | `USER_INPUT` | User prompt text before prompt construction |
| `before_tool_call` | `TOOL_CALL` | Tool arguments before the tool executes |
| `tool_result_persist` | `TOOL_RESPONSE` | Tool result text before it is persisted into future context |

`tool_result_persist` is synchronous in OpenClaw, so this plugin classifies that
hook through `scripts/firewall-classify-worker.mjs` and waits for the worker to
return before the hook exits. This avoids returning a Promise from a synchronous
hook and keeps the classification tied to the persist path.

Removed surfaces:

- no plugin-owned `web_fetch` wrapper
- no `silmaril-firewall` web fetch provider
- no GitHub wrapper tools such as `github_issue_read`
- no Gmail wrapper tools such as `gmail_message_read`
- no false-positive reporting tool
- no guarded wrapper payloads or approval handles

OpenClaw's built-in tools may still exist. For example, the built-in
`web_fetch` can still be available when enabled in OpenClaw config; it is not
owned or wrapped by this plugin.

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

If `apiKey` or `apiUrl` is missing, the plugin logs a warning and disables
itself. Legacy wrapper flags such as `enableWebFetchWrapper`,
`enableGitHubWrappers`, and `enableGmailWrappers` are not used by this branch.

## Install

```sh
npm install
openclaw plugins install -l .
openclaw gateway restart
```

On startup, the gateway log should include:

```text
firewall-plugin: hook-only mode enabled; no wrapper tools or web fetch providers are registered
```

It should not include wrapper registration messages such as
`registered silmaril-firewall web_fetch wrapper tool`.

## Manual No-Wrapper E2E Probes

Verify the no-wrapper contract by running real OpenClaw messages and inspecting
gateway logs. The probes should be run after installing the plugin and
restarting the gateway.

Recommended setup for a local run:

1. Start a mock Silmaril classifier:
   ```sh
   node scripts/mock-silmaril-classifier.mjs
   ```
2. Configure the plugin with the mock classifier URL and a test API key.
3. Install and restart:
   ```sh
   openclaw plugins install -l .
   openclaw gateway restart
   ```
4. Confirm the startup log contains:
   ```text
   firewall-plugin: hook-only mode enabled; no wrapper tools or web fetch providers are registered
   ```
5. For a tool-bearing turn, confirm the log contains:
   ```text
   [firewall] tool_result_persist sync classify begin
   [firewall] tool_result_persist sync result:
   ```

Run these agent probes:

- `/tools verbose`
- `Use the web to summarize https://example.com in one sentence.`
- `Tell me what https://github.com/octocat/Hello-World/issues/1 is about.`
- `If email tools are available, say which ones are available. Do not use shell commands.`

For each probe, inspect the agent output, classifier captures, and gateway logs.
The built-in `web_fetch` name may appear because OpenClaw can expose that tool
without this plugin wrapping it. The following wrapper-only evidence must not
appear:

- `silmaril-firewall`
- `registered silmaril-firewall web_fetch wrapper tool`
- `github_issue_read`, `github_pr_read`, `github_file_read`, or other GitHub wrapper tools
- `gmail_message_read`, `gmail_thread_read`, or `gmail_search`
- `firewall_report_false_positive`
- `OPENCLAW_FIREWALL_SYSTEM_CONTEXT`
- `UNTRUSTED_FETCHED_`
- `approvalHandle`
