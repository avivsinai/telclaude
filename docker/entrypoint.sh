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
        chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" /home/node/.claude
    fi

    # Install bundled CLAUDE.md (agent playbook) if present
    if [ -f "/app/.claude/CLAUDE.md" ]; then
        echo "[entrypoint] Installing bundled CLAUDE.md"
        mkdir -p /home/node/.claude
        cp /app/.claude/CLAUDE.md /home/node/.claude/CLAUDE.md
    fi

    # Symlink skills and CLAUDE.md to workspace for SDK's Skill tool discovery
    # The SDK looks at <cwd>/.claude/skills, not ~/.claude/skills
    if [ -d "/home/node/.claude/skills" ]; then
        echo "[entrypoint] Linking skills to workspace"
        mkdir -p /workspace/.claude
        ln -sfn /home/node/.claude/skills /workspace/.claude/skills
        if [ -f "/home/node/.claude/CLAUDE.md" ]; then
            ln -sfn /home/node/.claude/CLAUDE.md /workspace/.claude/CLAUDE.md
        fi
    fi

    # Configure git credential helper (uses telclaude's secure storage)
    # This allows git operations without storing plaintext credentials
    echo "[entrypoint] Configuring git credential helper"
    git config --global credential.helper "/app/bin/telclaude.js git-credential"
    git config --global credential.useHttpPath true

    # Apply git identity if credentials are stored
    if /app/bin/telclaude.js git-identity --check 2>/dev/null; then
        echo "[entrypoint] Applying git identity from secure storage"
        /app/bin/telclaude.js git-identity 2>/dev/null || true
    else
        # Check for environment variable fallback
        if [ -n "$GIT_USERNAME" ] && [ -n "$GIT_EMAIL" ]; then
            echo "[entrypoint] Applying git identity from environment"
            git config --global user.name "$GIT_USERNAME"
            git config --global user.email "$GIT_EMAIL"
        fi
    fi

    # Ensure data directories have correct ownership
    # This handles the case where volumes are mounted from host
    # NOTE: /workspace is skipped - it's a host bind mount and chowning is slow/unnecessary
    # NOTE: /home/node must be writable for Claude CLI to create .claude.json
    for dir in /data /home/node /home/node/.claude /home/node/.telclaude; do
        if [ -d "$dir" ]; then
            # Only chown if not already owned by the target user
            if [ "$(stat -c '%u' "$dir" 2>/dev/null || stat -f '%u' "$dir" 2>/dev/null)" != "$TELCLAUDE_UID" ]; then
                echo "[entrypoint] Fixing ownership of $dir"
                chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" "$dir" 2>/dev/null || true
            fi
        fi
    done

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
