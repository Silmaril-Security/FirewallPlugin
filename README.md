# Silmaril Firewall Plugin for OpenClaw

Prompt injection detection for OpenClaw that self-improves. Every tool call, every response, every prompt, classified in under 20 ms.

## Why

When OpenClaw executes tools (reads files, runs code, sends messages) it is vulnerable to prompt injection through untrusted sources. To solve the utility-security tradeoff Silmaril's self-healing firewall plugin is integrated with the hooks below to inspect untrusted content before it enters inference.

| Hook | Firewall Label | What it inspects | Why it matters |
|---|---|---|---|
| `before_tool_call` | `TOOL_CALL` | Tool arguments before execution | Catches injected instructions in tool inputs before they run, preventing harmful outcomes |
| `tool_result_persist` | `TOOL_RESPONSE` | Tool output after execution | Detects malicious content returned by tools that read untrusted data (e.g. poisoned file contents, API responses) |
| `before_prompt_build` | `USER_INPUT` | The user's prompt before it enters the LLM | Flags direct prompt injection attempts from user input and is a failsafe for other hooks |

## Getting Started

```sh
git clone https://github.com/Silmaril-Security/FirewallPlugin.git
cd FirewallPlugin
npm install
```

## Configuration

Add your Silmaril API credentials to `~/.openclaw/.env`:

```sh
SILMARIL_API_KEY=sk-live-abc123...
SILMARIL_API_URL=https://your-endpoint.execute-api.us-west-2.amazonaws.com/alpha/classify
```

Then reference them in `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "firewall-plugin": {
        "enabled": true,
        "config": {
          "apiKey": {
            "$secretRef": {
              "provider": "env",
              "key": "SILMARIL_API_KEY"
            }
          },
          "apiUrl": {
            "$secretRef": {
              "provider": "env",
              "key": "SILMARIL_API_URL"
            }
          }
        }
      }
    }
  }
}
```

## Installation

Install the plugin into OpenClaw and restart the gateway:

```sh
openclaw plugins install -l .
openclaw gateway restart
```

## Test

Run an agent task that triggers tool calls:

```sh
openclaw agent --agent main --message "What's the date today? Write it to a file"
```
