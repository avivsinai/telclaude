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

# IMPORTANT: This list must match src/sandbox/domains.ts
# If you add domains here, also add them to DEFAULT_ALLOWED_DOMAINS in domains.ts
ALLOWED_DOMAINS=(
    # ═══════════════════════════════════════════════════════════════════════════
    # Anthropic API + Claude Code
    # ═══════════════════════════════════════════════════════════════════════════
    "api.anthropic.com"
    "console.anthropic.com"
    "claude.ai"
    "code.anthropic.com"

    # ═══════════════════════════════════════════════════════════════════════════
    # OpenAI API (for image generation, TTS)
    # ═══════════════════════════════════════════════════════════════════════════
    "api.openai.com"

    # ═══════════════════════════════════════════════════════════════════════════
    # Telegram API
    # ═══════════════════════════════════════════════════════════════════════════
    "api.telegram.org"
    "telegram.org"

    # ═══════════════════════════════════════════════════════════════════════════
    # Package registries (read-only)
    # ═══════════════════════════════════════════════════════════════════════════
    "registry.npmjs.org"
    "registry.yarnpkg.com"
    "pypi.org"
    "files.pythonhosted.org"
    "crates.io"
    "static.crates.io"
    "index.crates.io"
    "rubygems.org"
    "repo.maven.apache.org"
    "repo1.maven.org"
    "api.nuget.org"
    "proxy.golang.org"
    "sum.golang.org"
    "repo.packagist.org"

    # ═══════════════════════════════════════════════════════════════════════════
    # Code hosting (read-only)
    # ═══════════════════════════════════════════════════════════════════════════
    "github.com"
    "api.github.com"
    "raw.githubusercontent.com"
    "objects.githubusercontent.com"
    "codeload.github.com"
    "gist.githubusercontent.com"
    "gitlab.com"
    "bitbucket.org"

    # ═══════════════════════════════════════════════════════════════════════════
    # Documentation sites
    # ═══════════════════════════════════════════════════════════════════════════
    "docs.python.org"
    "docs.rs"
    "developer.mozilla.org"
    "stackoverflow.com"

    # ═══════════════════════════════════════════════════════════════════════════
    # CDNs
    # ═══════════════════════════════════════════════════════════════════════════
    "cdn.jsdelivr.net"
    "unpkg.com"

    # ═══════════════════════════════════════════════════════════════════════════
    # Docker Hub (for container pulls)
    # ═══════════════════════════════════════════════════════════════════════════
    "hub.docker.com"
    "registry-1.docker.io"
    "auth.docker.io"
)

# ─────────────────────────────────────────────────────────────────────────────────
# Blocked metadata endpoints (cloud instance metadata - SSRF targets)
# ─────────────────────────────────────────────────────────────────────────────────
BLOCKED_METADATA_IPS=(
    "169.254.169.254"  # AWS/GCP/Azure/OCI/DO metadata
    "169.254.170.2"    # AWS ECS container metadata
    "100.100.100.200"  # Alibaba Cloud metadata
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

    # ═══════════════════════════════════════════════════════════════════════════
    # BLOCK FIRST: Metadata endpoints (SSRF protection - critical!)
    # These must be blocked BEFORE any allow rules
    # ═══════════════════════════════════════════════════════════════════════════
    for ip in "${BLOCKED_METADATA_IPS[@]}"; do
        iptables -A OUTPUT -d "$ip" -j DROP
        echo "[firewall] blocked metadata: $ip"
    done

    # ═══════════════════════════════════════════════════════════════════════════
    # BLOCK: RFC1918 private networks (prevent internal network access)
    # ═══════════════════════════════════════════════════════════════════════════
    iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
    iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
    iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
    iptables -A OUTPUT -d 169.254.0.0/16 -j DROP  # Link-local
    echo "[firewall] blocked RFC1918 private networks"

    # ═══════════════════════════════════════════════════════════════════════════
    # ALLOW: Essential services
    # ═══════════════════════════════════════════════════════════════════════════

    # Allow loopback (needed for internal communication)
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow DNS (UDP and TCP port 53)
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow SSH (for git operations)
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

    # ═══════════════════════════════════════════════════════════════════════════
    # ALLOW: Whitelisted domains
    # ═══════════════════════════════════════════════════════════════════════════
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

    # ═══════════════════════════════════════════════════════════════════════════
    # DEFAULT DENY: Block everything else
    # ═══════════════════════════════════════════════════════════════════════════
    iptables -A OUTPUT -j DROP

    echo "[firewall] firewall configured with default-deny policy"
    echo "[firewall] blocked: metadata endpoints, RFC1918 private networks"
    echo "[firewall] allowed: ${#ALLOWED_DOMAINS[@]} domains + DNS + SSH"
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
