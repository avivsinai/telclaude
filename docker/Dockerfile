# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Docker Image
# Secure container for running telclaude relay and agents
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
RUN pnpm prune --prod --ignore-scripts \
    # Remove packages not needed in Docker
    && rm -rf node_modules/keytar node_modules/.pnpm/keytar* \
    # Remove TypeScript type definitions (pulled as transitive deps but not needed at runtime)
    && rm -rf node_modules/.pnpm/@types* \
    # Remove sharp musl (Alpine) binaries - we use Debian/glibc
    && rm -rf node_modules/.pnpm/@img+sharp-libvips-linuxmusl* \
    && rm -rf node_modules/.pnpm/@img+sharp-linuxmusl*

# ─────────────────────────────────────────────────────────────────────────────────
# Stage 2: Claude CLI
# Install Claude Code CLI in a separate stage
# ─────────────────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS claude-cli

RUN npm install -g @anthropic-ai/claude-code@latest

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
# NOTE: keytar/libsecret/gnome-keyring NOT needed - Docker uses file storage via SECRETS_ENCRYPTION_KEY
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For better-sqlite3 runtime
    libsqlite3-0 \
    # For sandbox (bubblewrap + socat for network proxying)
    bubblewrap \
    socat \
    # Utilities (minimal set)
    ca-certificates \
    git \
    curl \
    # For Claude CLI tools
    ripgrep \
    # For audio conversion (TTS voice messages need OGG/Opus)
    ffmpeg \
    # For network firewall (TELCLAUDE_FIREWALL=1)
    iptables \
    # For IPv6 detection in firewall setup (ip -6)
    iproute2 \
    # For privilege dropping (gosu is the standard Docker tool for this)
    gosu \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install GitHub CLI (gh) for issue/PR management
# Uses official GitHub apt repository for reliable updates
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# Post-install setup
RUN gosu nobody true \
    # Set setuid bit on bwrap for network namespace creation
    # Required for --unshare-net to work when running as non-root
    && chmod u+s /usr/bin/bwrap

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
    && mkdir -p /home/telclaude-auth \
    && mkdir -p /home/telclaude-skills \
    && mkdir -p /workspace \
    && mkdir -p /data \
    # Remove shell rc files to prevent noisy "Permission denied" errors
    # when bash tries to source them inside the sandbox (which blocks reads)
    && rm -f /home/node/.bashrc /home/node/.profile \
    && chown -R node:node /home/node /home/telclaude-auth /home/telclaude-skills /workspace /data

# Copy Claude CLI from builder stage
COPY --from=claude-cli /usr/local/lib/node_modules/@anthropic-ai /usr/local/lib/node_modules/@anthropic-ai
COPY --from=claude-cli /usr/local/bin/claude /usr/local/bin/claude

# Claude Code expects ripgrep at a specific path - create symlink to system rg
# This is needed because Claude CLI bundles its own rg but we use the system one
# Detect architecture dynamically to support both ARM64 (Raspberry Pi) and x86_64
RUN ARCH=$(uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/x64/') \
    && mkdir -p /usr/local/bin/vendor/ripgrep/${ARCH}-linux \
    && ln -s /usr/bin/rg /usr/local/bin/vendor/ripgrep/${ARCH}-linux/rg

# Copy built application
WORKDIR /app
COPY --from=builder --chown=node:node /build/dist ./dist
COPY --from=builder --chown=node:node /build/node_modules ./node_modules
COPY --from=builder --chown=node:node /build/package.json ./
COPY --from=builder --chown=node:node /build/bin ./bin
COPY --from=builder --chown=node:node /build/.claude ./.claude
COPY --from=builder --chown=node:node /build/src ./src
COPY --chown=node:node docs/social-contract.md ./docs/social-contract.md
COPY --chown=node:node docs/architecture.md ./docs/architecture.md
COPY --chown=node:node assets/logo/logo-512.png ./assets/logo/logo-512.png

# Copy firewall initialization scripts and entrypoint wrapper
COPY --chown=node:node docker/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY --chown=node:node docker/firewall-refresh.sh /usr/local/bin/firewall-refresh.sh
COPY --chown=node:node docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/firewall-refresh.sh /usr/local/bin/entrypoint.sh

# Create symlink for telclaude command
RUN ln -s /app/bin/telclaude.js /usr/local/bin/telclaude

# Environment variables
ARG GIT_COMMIT=unknown
ENV NODE_ENV=production
ENV TELCLAUDE_DATA_DIR=/data
ENV TELCLAUDE_REVISION=${GIT_COMMIT}
ENV HOME=/home/node

# NOTE: We do NOT use USER directive here.
# The entrypoint starts as root to run privileged operations (firewall setup),
# then drops to non-root user via gosu. This is the standard Docker pattern
# for containers that need initial root privileges but should run as non-root.

# Healthcheck - verify node process is running
# Uses simple process check without procps (saves ~10MB)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["curl", "-sf", "http://localhost:8788/health"]

# Mark bind-mount workdirs as safe for git (host UID ≠ container UID).
# Build-time so /etc/gitconfig is part of the image — no runtime writes needed.
RUN git config --system --add safe.directory /workspace && \
    git config --system --add safe.directory /social/sandbox

# Default working directory for Claude operations
WORKDIR /workspace

# Entry point (wrapper runs firewall init, then exec's telclaude)
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["relay", "-v"]
