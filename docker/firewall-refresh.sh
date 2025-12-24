#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Firewall DNS Refresh Daemon
#
# Periodically re-resolves whitelisted domains and updates iptables rules.
# This handles the case where CDN/cloud providers change IP addresses during
# container lifetime.
#
# Usage:
#   ./firewall-refresh.sh &
#
# Environment variables:
#   FIREWALL_REFRESH_INTERVAL - Refresh interval in seconds (default: 3600 = 1 hour)
#   TELCLAUDE_FIREWALL - Must be "1" for daemon to run
# ═══════════════════════════════════════════════════════════════════════════════

set -e

REFRESH_INTERVAL="${FIREWALL_REFRESH_INTERVAL:-3600}"

echo "[firewall-refresh] daemon started (interval: ${REFRESH_INTERVAL}s)"

while true; do
    sleep "$REFRESH_INTERVAL"

    if [ "${TELCLAUDE_FIREWALL:-0}" = "1" ]; then
        /usr/local/bin/init-firewall.sh --refresh-only 2>&1 || \
            echo "[firewall-refresh] ERROR: refresh failed"
    fi
done
