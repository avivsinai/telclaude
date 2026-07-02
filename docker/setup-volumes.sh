#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Volume Setup
#
# Creates external Docker volumes for persistent Telclaude data.
# Run this ONCE before first `docker compose up`.
#
# These volumes are marked as 'external' in docker-compose.yml, which means:
# - Docker Compose will NOT create them automatically
# - Docker Compose will NOT delete them with `docker compose down -v`
# - This protects your secrets from accidental deletion
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

echo "Creating external volumes for Telclaude..."

ensure_volume() {
    local name="$1"
    if docker volume inspect "$name" >/dev/null 2>&1; then
        echo "✓ $name already exists"
    else
        docker volume create "$name" >/dev/null
        echo "✓ Created $name"
    fi
}

# Relay data: SQLite DB, sessions, identity links, approvals
ensure_volume "telclaude-data"

# Claude Code auth profile (OAuth tokens)
ensure_volume "telclaude-claude-auth"

# Shared skill catalogs
ensure_volume "telclaude-skill-catalog"
ensure_volume "telclaude-hermes-skill-catalog"
ensure_volume "telclaude-hermes-social-skill-catalog"

# Sidecar and persona state
ensure_volume "telclaude-google-data"
ensure_volume "telclaude-social-memory"
ensure_volume "telclaude-media-outbox"
ensure_volume "telclaude-whatsapp-bridge-data"

# TOTP secrets (encrypted 2FA seeds) - CRITICAL
ensure_volume "telclaude-totp-data"

# Vault credentials (encrypted API keys, OAuth tokens) - CRITICAL
ensure_volume "telclaude-vault-data"

echo ""
echo "Volume setup complete!"
echo ""
echo "⚠️  IMPORTANT: Back up these volumes regularly:"
echo "   - telclaude-data: Relay SQLite DB, sessions, identity links, approvals"
echo "   - telclaude-claude-auth: Claude OAuth tokens"
echo "   - telclaude-skill-catalog: Shared installed + draft skills"
echo "   - telclaude-hermes-skill-catalog: Private Hermes installed + draft skills"
echo "   - telclaude-hermes-social-skill-catalog: Social Hermes installed + draft skills"
echo "   - telclaude-google-data: Google sidecar replay store"
echo "   - telclaude-social-memory: Social persona memory"
echo "   - telclaude-media-outbox: Generated media awaiting delivery"
echo "   - telclaude-whatsapp-bridge-data: WhatsApp bridge session state"
echo "   - telclaude-totp-data: Encrypted 2FA secrets (CANNOT be recovered if lost)"
echo "   - telclaude-vault-data: Encrypted credentials (CANNOT be recovered if lost)"
echo ""
echo "To back up a volume:"
echo "   docker run --rm -v telclaude-totp-data:/data -v \$(pwd):/backup alpine tar czf /backup/totp-backup.tar.gz -C /data ."
echo ""
echo "You can now run: docker compose up -d"
