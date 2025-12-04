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

    # Ensure data directories have correct ownership
    # This handles the case where volumes are mounted from host
    for dir in /data /workspace /home/node/.claude /home/node/.telclaude; do
        if [ -d "$dir" ]; then
            # Only chown if not already owned by the target user
            if [ "$(stat -c '%u' "$dir" 2>/dev/null || stat -f '%u' "$dir" 2>/dev/null)" != "$TELCLAUDE_UID" ]; then
                echo "[entrypoint] Fixing ownership of $dir"
                chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" "$dir" 2>/dev/null || true
            fi
        fi
    done

    # Drop privileges and exec into the application
    echo "[entrypoint] Dropping privileges to user: $TELCLAUDE_USER"
    exec gosu "$TELCLAUDE_USER" /app/bin/telclaude.js "$@"
else
    # Already running as non-root (e.g., docker-compose user: directive)
    # Skip privileged operations and run directly
    echo "[entrypoint] Already running as non-root (UID=$(id -u)), skipping privileged init"
    echo "[entrypoint] Note: Firewall initialization requires root - it will be skipped"
    exec /app/bin/telclaude.js "$@"
fi
