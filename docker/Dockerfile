# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Docker Image
# Secure container for running telclaude on Windows/Linux hosts
#
# Security features (2025 best practices):
# - Multi-stage build for minimal attack surface
# - Privilege dropping via gosu (starts root, drops to UID 1000)
# - Minimal base image (Debian slim)
# - Firewall script for network isolation (requires root at startup)
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# ─────────────────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS builder

# Install build dependencies for native modules
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    git \
    # For better-sqlite3
    libsqlite3-dev \
    # For keytar (libsecret backend) - needed for TOTP
    libsecret-1-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install pnpm via npm (corepack not available in all Node versions)
RUN npm install -g pnpm@9.15.0

WORKDIR /build

# Copy package files first (better layer caching)
# Include .npmrc for pnpm config (disables link-workspace-packages)
COPY package.json pnpm-lock.yaml .npmrc ./

# Install dependencies
# --ignore-scripts prevents the "prepare" hook from running (which tries to build
# before source files are copied)
RUN pnpm install --ignore-scripts

# Copy source code
COPY . .

# Build the project
RUN pnpm run build

# Rebuild native modules (they weren't compiled during install due to --ignore-scripts)
# This compiles better-sqlite3, sharp, keytar, etc.
RUN pnpm rebuild

# Prune dev dependencies for production
# --ignore-scripts prevents the "prepare" hook from running (typescript already removed)
RUN pnpm prune --prod --ignore-scripts

# ─────────────────────────────────────────────────────────────────────────────────
# Stage 2: Claude CLI
# Install Claude Code CLI in a separate stage
# ─────────────────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS claude-cli

RUN npm install -g @anthropic-ai/claude-code

# ─────────────────────────────────────────────────────────────────────────────────
# Stage 3: Runtime
# Minimal production image with security hardening
# ─────────────────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime

# Labels for container metadata
LABEL org.opencontainers.image.title="telclaude"
LABEL org.opencontainers.image.description="Secure Telegram-Claude bridge"
LABEL org.opencontainers.image.source="https://github.com/avivsinai/telclaude"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For better-sqlite3 runtime
    libsqlite3-0 \
    # For keytar/libsecret (TOTP daemon)
    libsecret-1-0 \
    dbus \
    gnome-keyring \
    # For sandbox (bubblewrap + socat for network proxying)
    bubblewrap \
    socat \
    # Utilities
    ca-certificates \
    curl \
    git \
    # For Claude CLI tools
    ripgrep \
    jq \
    # For healthcheck (pgrep)
    procps \
    # For network firewall (TELCLAUDE_FIREWALL=1)
    iptables \
    # For privilege dropping (gosu is the standard Docker tool for this)
    gosu \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    # Verify gosu works
    && gosu nobody true

# Modify the existing node user to match desired UID/GID
# The node base image already has a 'node' user with UID/GID 1000
# We use usermod/groupmod to adjust if needed (idiomatic Docker pattern)
# See: https://github.com/nodejs/docker-node/issues/289
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupmod -g ${USER_GID} node \
    && usermod -u ${USER_UID} -g ${USER_GID} node \
    # Create necessary directories
    && mkdir -p /home/node/.telclaude/logs \
    && mkdir -p /home/node/.telclaude/sandbox-tmp \
    && mkdir -p /home/node/.claude \
    && mkdir -p /workspace \
    && mkdir -p /data \
    # Remove shell rc files to prevent noisy "Permission denied" errors
    # when bash tries to source them inside the sandbox (which blocks reads)
    && rm -f /home/node/.bashrc /home/node/.profile \
    && chown -R node:node /home/node /workspace /data

# Copy Claude CLI from builder stage
COPY --from=claude-cli /usr/local/lib/node_modules/@anthropic-ai /usr/local/lib/node_modules/@anthropic-ai
COPY --from=claude-cli /usr/local/bin/claude /usr/local/bin/claude

# Copy built application
WORKDIR /app
COPY --from=builder --chown=node:node /build/dist ./dist
COPY --from=builder --chown=node:node /build/node_modules ./node_modules
COPY --from=builder --chown=node:node /build/package.json ./
COPY --from=builder --chown=node:node /build/bin ./bin
COPY --from=builder --chown=node:node /build/.claude ./.claude

# Copy firewall initialization script and entrypoint wrapper
COPY --chown=node:node docker/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY --chown=node:node docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/entrypoint.sh

# Create symlink for telclaude command
RUN ln -s /app/bin/telclaude.js /usr/local/bin/telclaude

# Environment variables
ENV NODE_ENV=production
ENV TELCLAUDE_DATA_DIR=/data
ENV HOME=/home/node

# NOTE: We do NOT use USER directive here.
# The entrypoint starts as root to run privileged operations (firewall setup),
# then drops to non-root user via gosu. This is the standard Docker pattern
# for containers that need initial root privileges but should run as non-root.

# Healthcheck - verify telclaude process is running
# The relay doesn't expose an HTTP endpoint, so we check if the node process is alive
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f "telclaude.js" > /dev/null || exit 1

# Default working directory for Claude operations
WORKDIR /workspace

# Entry point (wrapper runs firewall init, then exec's telclaude)
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["relay", "-v"]
