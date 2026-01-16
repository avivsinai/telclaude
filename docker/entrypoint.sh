#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Docker Entrypoint
#
# This script runs as root to perform privileged operations, then drops to
# non-root user via gosu before executing the main application.
#
# Security flow:
# 1. Run as root (container starts as root)
# 2. Initialize firewall (requires CAP_NET_ADMIN)
# 3. Fix ownership of mounted volumes (if needed)
# 4. Drop to non-root user via gosu
# 5. Exec into telclaude application
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Target user to run the application as (node user from base image)
TELCLAUDE_USER="${TELCLAUDE_USER:-node}"
TELCLAUDE_UID="${TELCLAUDE_UID:-1000}"
TELCLAUDE_GID="${TELCLAUDE_GID:-1000}"

# ─────────────────────────────────────────────────────────────────────────────
# Privileged Operations (run as root)
# ─────────────────────────────────────────────────────────────────────────────

# Only perform privileged operations if running as root
if [ "$(id -u)" = "0" ]; then
    echo "[entrypoint] Running privileged initialization as root..."

    # Initialize firewall (requires root or CAP_NET_ADMIN)
    # The script checks TELCLAUDE_FIREWALL internally
    /usr/local/bin/init-firewall.sh

    # Start firewall refresh daemon in background (if firewall is enabled)
    # This periodically updates iptables rules when domain IPs change
    if [ "${TELCLAUDE_FIREWALL:-0}" = "1" ]; then
        /usr/local/bin/firewall-refresh.sh &
        echo "[entrypoint] Started firewall refresh daemon (interval: ${FIREWALL_REFRESH_INTERVAL:-3600}s)"
    fi

    # Create /tmp/claude for sandbox-runtime CWD tracking
    # srt hardcodes this path internally regardless of TMPDIR
    mkdir -p /tmp/claude
    chmod 1777 /tmp/claude

    # Install bundled skills to ~/.claude/skills (done at runtime so volumes don't obscure them)
    if [ -d "/app/.claude/skills" ]; then
        echo "[entrypoint] Installing bundled skills"
        mkdir -p /home/node/.claude/skills
        cp -a /app/.claude/skills/. /home/node/.claude/skills/
        # chown may fail on NFS with UID squashing - that's OK, files are still accessible
        chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" /home/node/.claude 2>/dev/null || true
    fi

    # Install bundled CLAUDE.md (agent playbook) if present
    if [ -f "/app/.claude/CLAUDE.md" ]; then
        echo "[entrypoint] Installing bundled CLAUDE.md"
        mkdir -p /home/node/.claude
        cp /app/.claude/CLAUDE.md /home/node/.claude/CLAUDE.md
    fi

    # Skills are installed at user-level (~/.claude/skills/) above.
    # However, WORKDIR is /workspace, so SDK looks for project-level skills at /workspace/.claude/skills/.
    # FORCE symlink to ensure SDK reads from the same location relay writes to.
    # This prevents divergence when host workspace has its own .claude/skills/ directory.
    if [ -d "/workspace" ] && [ -w "/workspace" ]; then
        mkdir -p /workspace/.claude
        if [ -L "/workspace/.claude/skills" ]; then
            # Already a symlink - nothing to do
            echo "[entrypoint] Skills symlink already exists"
        elif [ -e "/workspace/.claude/skills" ]; then
            # Exists but not a symlink - back it up and replace
            echo "[entrypoint] WARNING: /workspace/.claude/skills exists but is not a symlink"
            echo "[entrypoint] Backing up to /workspace/.claude/skills.bak and creating symlink"
            rm -rf /workspace/.claude/skills.bak
            mv /workspace/.claude/skills /workspace/.claude/skills.bak
            ln -s /home/node/.claude/skills /workspace/.claude/skills
            chown -h "${TELCLAUDE_UID}:${TELCLAUDE_GID}" /workspace/.claude/skills 2>/dev/null || true
        else
            # Doesn't exist - create symlink
            echo "[entrypoint] Symlinking skills to workspace"
            ln -s /home/node/.claude/skills /workspace/.claude/skills
            chown -h "${TELCLAUDE_UID}:${TELCLAUDE_GID}" /workspace/.claude /workspace/.claude/skills 2>/dev/null || true
        fi
    else
        echo "[entrypoint] Skipping workspace skills symlink (workspace not writable)"
    fi

    # Ensure data directories have correct ownership
    # This handles the case where volumes are mounted from host
    # NOTE: /workspace is skipped - it's a host bind mount and chowning is slow/unnecessary
    # NOTE: /home/node must be writable for Claude CLI to create .claude.json
    # NOTE: /media/outbox needs write access for generated content (relay container)
    # Create logs directory and file with correct ownership for pino logger
    # Must be done before dropping privileges since tmpfs dirs created as root
    mkdir -p /home/node/.telclaude/logs
    touch /home/node/.telclaude/logs/telclaude.log
    chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" /home/node/.telclaude 2>/dev/null || true

    for dir in /data /home/node /home/node/.claude /media/inbox /media/outbox; do
        if [ -d "$dir" ]; then
            # Only chown if not already owned by the target user
            if [ "$(stat -c '%u' "$dir" 2>/dev/null || stat -f '%u' "$dir" 2>/dev/null)" != "$TELCLAUDE_UID" ]; then
                echo "[entrypoint] Fixing ownership of $dir"
                chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" "$dir" 2>/dev/null || true
            fi
        fi
    done

    # Fix /data/logs permissions created by root before dropping privileges.
    # Some deployments create 600-perm log files as root, which blocks the node user.
    # Only run if /data is mounted and writable (relay container, not agent).
    if [ -d "/data" ] && [ -w "/data" ]; then
        mkdir -p /data/logs
        chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" /data/logs 2>/dev/null || true
        chmod -R a+rwX /data/logs 2>/dev/null || true
    fi

    # Git configuration: Use proxy in agent container, minimal config in relay
    if [ -n "$TELCLAUDE_GIT_PROXY_URL" ]; then
        # Agent container: Configure git to use the relay's git proxy
        # The proxy adds GitHub authentication transparently - agent never sees the token
        # Run as daemon with gosu to drop privileges (least privilege principle)
        echo "[entrypoint] Configuring git to use relay proxy"
        gosu "$TELCLAUDE_USER" /app/bin/telclaude.js git-proxy-init --daemon &
        GIT_PROXY_PID=$!

        # Wait a moment for initial configuration
        sleep 1

        # Verify git-proxy-init is running
        if ! kill -0 $GIT_PROXY_PID 2>/dev/null; then
            echo "[entrypoint] WARNING: git-proxy-init failed, git operations may not work"
        else
            echo "[entrypoint] git-proxy-init daemon started (PID $GIT_PROXY_PID)"
        fi
    else
        # Relay container: Minimal git config (relay doesn't do git operations)
        # Just set safe defaults for any incidental git usage
        echo "[entrypoint] Relay mode: minimal git config"
        git config --global init.defaultBranch main
        git config --global core.autocrlf input
    fi

    # Drop privileges and exec into the application (unless TELCLAUDE_RUN_AS_ROOT=1)
    if [ "${TELCLAUDE_RUN_AS_ROOT:-0}" = "1" ]; then
        echo "[entrypoint] Running as root (TELCLAUDE_RUN_AS_ROOT=1)"
        echo "[entrypoint] WARNING: Consider setting TELCLAUDE_RUN_AS_ROOT=0 for better security"
        exec /app/bin/telclaude.js "$@"
    else
        echo "[entrypoint] Dropping privileges to user: $TELCLAUDE_USER"
        exec gosu "$TELCLAUDE_USER" /app/bin/telclaude.js "$@"
    fi
else
    # Already running as non-root (e.g., docker-compose user: directive)
    # Skip privileged operations and run directly
    echo "[entrypoint] Already running as non-root (UID=$(id -u)), skipping privileged init"
    echo "[entrypoint] Note: Firewall initialization requires root - it will be skipped"
    exec /app/bin/telclaude.js "$@"
fi
