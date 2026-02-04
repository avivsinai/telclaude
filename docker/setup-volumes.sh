#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Volume Setup
#
# Creates external Docker volumes for secrets storage.
# Run this ONCE before first `docker compose up`.
#
# These volumes are marked as 'external' in docker-compose.yml, which means:
# - Docker Compose will NOT create them automatically
# - Docker Compose will NOT delete them with `docker compose down -v`
# - This protects your secrets from accidental deletion
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

echo "Creating external volumes for Telclaude..."

# Claude Code auth profile (OAuth tokens)
if docker volume inspect telclaude-claude-auth >/dev/null 2>&1; then
    echo "✓ telclaude-claude-auth already exists"
else
    docker volume create telclaude-claude-auth
    echo "✓ Created telclaude-claude-auth"
fi

# TOTP secrets (encrypted 2FA seeds) - CRITICAL
if docker volume inspect telclaude-totp-data >/dev/null 2>&1; then
    echo "✓ telclaude-totp-data already exists"
else
    docker volume create telclaude-totp-data
    echo "✓ Created telclaude-totp-data"
fi

echo ""
echo "Volume setup complete!"
echo ""
echo "⚠️  IMPORTANT: Back up these volumes regularly:"
echo "   - telclaude-claude-auth: Claude OAuth tokens"
echo "   - telclaude-totp-data: Encrypted 2FA secrets (CANNOT be recovered if lost)"
echo ""
echo "To back up a volume:"
echo "   docker run --rm -v telclaude-totp-data:/data -v \$(pwd):/backup alpine tar czf /backup/totp-backup.tar.gz -C /data ."
echo ""
echo "You can now run: docker compose up -d"
