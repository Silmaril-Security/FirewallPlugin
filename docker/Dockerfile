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
# pnpm is used by this branch; install it once for the plugin install below.
RUN npm install -g openclaw@2026.4.20 pnpm@10.29.3

# --- plugin install ---
WORKDIR /opt/silmaril-plugin

# Install plugin deps. Source is copied later, so we copy package + lock and
# install with frozen lockfile. test/shims/openclaw is referenced as a local
# devDependency, so we need to copy that subtree too before pnpm install.
COPY package.json pnpm-lock.yaml ./
COPY test/shims ./test/shims
RUN pnpm install --frozen-lockfile --prod=false

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
