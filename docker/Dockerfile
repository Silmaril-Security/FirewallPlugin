# Dockerfile — OpenClaw gateway with the silmaril-plugin (this worktree) baked in.
# Used to run the role-policy e2e matrix in isolation, without touching the host's
# ~/.openclaw config.

FROM node:22-bookworm-slim

# git is needed by the plugin's identity-resolution fallback (git config user.email)
# gettext-base provides envsubst for entrypoint config templating
# ca-certificates is needed for HTTPS to the Silmaril classifier endpoint
RUN apt-get update \
 && apt-get install -y --no-install-recommends git gettext-base ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/*

# Install OpenClaw CLI globally — pinned to match the locally tested version.
RUN npm install -g openclaw@2026.4.20

# --- plugin install ---
WORKDIR /opt/silmaril-plugin

# Install plugin npm deps first for layer caching.
COPY package.json package-lock.json ./
RUN npm ci

# Copy plugin source.
COPY index.ts metadata.ts openclaw.plugin.json ./
COPY src ./src
COPY scripts ./scripts
COPY skills ./skills

# OpenClaw config dir + workspace.
RUN mkdir -p /root/.openclaw/workspace /root/.openclaw/agents/main/agent

# Templates are rendered at container start so secrets stay in env vars.
COPY docker/openclaw.json.template /root/.openclaw/openclaw.json.template
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 18789

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gateway"]
