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

# IMPORTANT: Keep in sync with src/sandbox/domains.ts (DEFAULT_ALLOWED_DOMAINS)
# Note: Wildcard domains (*.example.com) in domains.ts can't be resolved here,
# so we expand them to known subdomains below.
ALLOWED_DOMAINS=(
    # ═══════════════════════════════════════════════════════════════════════════
    # Anthropic API + Claude Code
    # (domains.ts wildcards: *.claude.ai, *.code.anthropic.com)
    # ═══════════════════════════════════════════════════════════════════════════
    "api.anthropic.com"
    "claude.ai"
    "code.anthropic.com"
    # Expanded from *.claude.ai
    "api.claude.ai"
    "platform.claude.ai"
    # Expanded from *.code.anthropic.com
    "api.code.anthropic.com"

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
    # (domains.ts wildcard: *.stackexchange.com)
    # ═══════════════════════════════════════════════════════════════════════════
    "docs.python.org"
    "docs.rs"
    "developer.mozilla.org"
    "stackoverflow.com"
    # Expanded from *.stackexchange.com (common sites)
    "superuser.com"
    "serverfault.com"
    "askubuntu.com"
    "unix.stackexchange.com"
    "security.stackexchange.com"

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
        echo "[firewall] ERROR: iptables not available"
        echo "[firewall] firewall setup FAILED - Bash will have unrestricted network access"
        return 1
    fi

    # Check if we have permissions (need root or CAP_NET_ADMIN)
    if ! iptables -L -n &> /dev/null 2>&1; then
        echo "[firewall] ERROR: insufficient permissions for iptables"
        echo "[firewall] to enable firewall, run container with --cap-add=NET_ADMIN"
        echo "[firewall] firewall setup FAILED - Bash will have unrestricted network access"
        return 1
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
        # Resolve domain to IPv4 addresses only (iptables doesn't handle IPv6)
        # Filter: grep for lines with dots (IPv4) and exclude colons (IPv6)
        ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u)

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

    # Write sentinel file to indicate firewall is actually applied
    # relay.ts checks for this file to verify firewall is working
    local sentinel_dir="/run/telclaude"
    mkdir -p "$sentinel_dir" 2>/dev/null || true
    echo "$(date -Iseconds)" > "$sentinel_dir/firewall-active"
    echo "[firewall] sentinel written to $sentinel_dir/firewall-active"
}

# ─────────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────────

main() {
    # Only setup firewall if TELCLAUDE_FIREWALL=1
    if [ "${TELCLAUDE_FIREWALL:-0}" = "1" ]; then
        if ! setup_firewall; then
            echo "[firewall] CRITICAL: firewall setup failed but TELCLAUDE_FIREWALL=1"
            echo "[firewall] relay will refuse to start without verified firewall"
            exit 1
        fi
    else
        echo "[firewall] firewall disabled (set TELCLAUDE_FIREWALL=1 to enable)"
    fi
}

main "$@"
