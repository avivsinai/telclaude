#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Network Firewall Initialization
#
# Restricts outbound connections to whitelisted domains only.
# Based on Claude Code's official devcontainer firewall.
#
# This script uses iptables to enforce network isolation.
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# ─────────────────────────────────────────────────────────────────────────────────
# Whitelisted Domains
# ─────────────────────────────────────────────────────────────────────────────────

ALLOWED_DOMAINS=(
    # Anthropic API
    "api.anthropic.com"
    "console.anthropic.com"

    # Claude Code / Agent SDK
    "code.claude.com"
    "claude.ai"

    # Telegram API
    "api.telegram.org"
    "telegram.org"

    # Package registries
    "registry.npmjs.org"
    "registry.yarnpkg.com"
    "pypi.org"
    "files.pythonhosted.org"

    # GitHub (for repos, releases, raw content)
    "github.com"
    "api.github.com"
    "raw.githubusercontent.com"
    "objects.githubusercontent.com"
    "codeload.github.com"

    # Common CDNs
    "cdn.jsdelivr.net"
    "unpkg.com"

    # Docker Hub (if needed)
    "hub.docker.com"
    "registry-1.docker.io"
    "auth.docker.io"
)

# ─────────────────────────────────────────────────────────────────────────────────
# Firewall Setup (only if iptables is available and we have permissions)
# ─────────────────────────────────────────────────────────────────────────────────

setup_firewall() {
    # Check if iptables is available
    if ! command -v iptables &> /dev/null; then
        echo "[firewall] iptables not available, skipping firewall setup"
        return 0
    fi

    # Check if we have permissions (need root or CAP_NET_ADMIN)
    if ! iptables -L -n &> /dev/null 2>&1; then
        echo "[firewall] insufficient permissions for iptables, skipping firewall setup"
        echo "[firewall] to enable firewall, run container with --cap-add=NET_ADMIN"
        return 0
    fi

    echo "[firewall] setting up network firewall..."

    # Flush existing OUTPUT rules
    iptables -F OUTPUT 2>/dev/null || true

    # Allow loopback
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow DNS (UDP and TCP port 53)
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow SSH (for git operations)
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

    # Resolve and allow whitelisted domains
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        # Resolve domain to IP addresses
        ips=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u)

        if [ -n "$ips" ]; then
            for ip in $ips; do
                iptables -A OUTPUT -d "$ip" -j ACCEPT
                echo "[firewall] allowed: $domain ($ip)"
            done
        else
            echo "[firewall] warning: could not resolve $domain"
        fi
    done

    # Allow HTTPS to any IP (fallback for CDNs with many IPs)
    # Comment out these lines for stricter isolation
    # iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    # iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

    # Default deny for OUTPUT
    iptables -A OUTPUT -j DROP

    echo "[firewall] firewall configured with default-deny policy"
}

# ─────────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────────

main() {
    # Only setup firewall if TELCLAUDE_FIREWALL=1
    if [ "${TELCLAUDE_FIREWALL:-0}" = "1" ]; then
        setup_firewall
    else
        echo "[firewall] firewall disabled (set TELCLAUDE_FIREWALL=1 to enable)"
    fi
}

main "$@"
