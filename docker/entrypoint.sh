#!/usr/bin/env bash
set -euo pipefail

# Render config from template using env vars. When OPENCLAW_STATE_DIR is set
# (typical for e2e tests using a host-mounted volume), we render the config
# AND set up the workspace under that path so the gateway and the exporter
# share the same state root.
: "${OPENCLAW_GATEWAY_TOKEN:?OPENCLAW_GATEWAY_TOKEN must be set}"
: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY must be set}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
: "${SILMARIL_API_KEY:?SILMARIL_API_KEY must be set}"
: "${SILMARIL_CLASSIFY_URL:?SILMARIL_CLASSIFY_URL must be set}"
export SILMARIL_PLUGIN_API_KEY="${SILMARIL_PLUGIN_API_KEY:-${SILMARIL_API_KEY}}"
export SILMARIL_FP_REPORT_URL="${SILMARIL_FP_REPORT_URL:-}"

CONFIG_ROOT="${OPENCLAW_STATE_DIR:-/root/.openclaw}"
mkdir -p "$CONFIG_ROOT/workspace" "$CONFIG_ROOT/agents/main/agent"

# Patch the workspace path in the template so it points under CONFIG_ROOT.
sed "s|/root/.openclaw/workspace|$CONFIG_ROOT/workspace|g" \
    /root/.openclaw/openclaw.json.template \
  | envsubst > "$CONFIG_ROOT/openclaw.json"

# OpenClaw expects ~/.openclaw to exist for some skills/auth flows even if
# we override the state dir.
mkdir -p /root/.openclaw

echo "[entrypoint] config rendered to $CONFIG_ROOT/openclaw.json"
echo "[entrypoint] starting: openclaw $*"
exec openclaw "$@"
