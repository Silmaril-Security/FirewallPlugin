#!/usr/bin/env bash
set -euo pipefail

# Render config from template using env vars.
# Empty / unset envvars resolve to "" — the plugin treats blank userEmail as no-identity,
# which is the desired F1 fallback behavior.
: "${OPENCLAW_GATEWAY_TOKEN:?OPENCLAW_GATEWAY_TOKEN must be set}"
: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY must be set}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
: "${SILMARIL_API_KEY:?SILMARIL_API_KEY must be set}"
: "${SILMARIL_CLASSIFY_URL:?SILMARIL_CLASSIFY_URL must be set}"
export SILMARIL_PLUGIN_API_KEY="${SILMARIL_PLUGIN_API_KEY:-${SILMARIL_API_KEY}}"
export SILMARIL_FP_REPORT_URL="${SILMARIL_FP_REPORT_URL:-}"
export OPENCLAW_USER_EMAIL="${OPENCLAW_USER_EMAIL:-}"

envsubst < /root/.openclaw/openclaw.json.template > /root/.openclaw/openclaw.json

echo "[entrypoint] config rendered. user_email='${OPENCLAW_USER_EMAIL}'"
echo "[entrypoint] starting: openclaw $*"
exec openclaw "$@"
