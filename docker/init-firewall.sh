#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude Network Firewall Initialization
#
# Restricts outbound connections to whitelisted domains only.
# Based on Claude Code's official devcontainer firewall.
#
# This script uses iptables (IPv4) and ip6tables (IPv6) to enforce network isolation.
# IPv6 uses a default-deny policy to prevent bypassing the allowlist.
#
# Internal host resolution uses retry logic to handle container startup races.
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Configuration
INTERNAL_HOST_RETRY_COUNT=${TELCLAUDE_FIREWALL_RETRY_COUNT:-10}
INTERNAL_HOST_RETRY_DELAY=${TELCLAUDE_FIREWALL_RETRY_DELAY:-2}
IPV6_FAIL_CLOSED=${TELCLAUDE_IPV6_FAIL_CLOSED:-1}
NETWORK_MODE="${TELCLAUDE_NETWORK_MODE:-restricted}"

# Network mode determines egress policy:
#   - restricted (default): domain allowlist + default-deny
#   - permissive: allow all public egress (WebFetch can reach any URL)
#   - open: alias for permissive
# In all modes, metadata endpoints are ALWAYS blocked (SSRF protection)

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
    # Social service APIs (credential proxy outbound)
    # ═══════════════════════════════════════════════════════════════════════════
    "api.x.com"

    # ═══════════════════════════════════════════════════════════════════════════
    # Docker Hub (for container pulls)
    # ═══════════════════════════════════════════════════════════════════════════
    "hub.docker.com"
    "registry-1.docker.io"
    "auth.docker.io"
)

# ─────────────────────────────────────────────────────────────────────────────────
# Internal service allowlist (relay/agent RPC)
# ─────────────────────────────────────────────────────────────────────────────────

INTERNAL_HOSTS=()
if [ -n "${TELCLAUDE_INTERNAL_HOSTS:-}" ]; then
    IFS=',' read -r -a INTERNAL_HOSTS <<< "${TELCLAUDE_INTERNAL_HOSTS}"
else
    INTERNAL_HOSTS=("telclaude" "telclaude-agent")
fi

# Append a host if it's not already in INTERNAL_HOSTS
append_internal_host() {
    local host="$1"
    if [ -z "$host" ]; then
        return 0
    fi
    for existing in "${INTERNAL_HOSTS[@]}"; do
        if [ "$existing" = "$host" ]; then
            return 0
        fi
    done
    INTERNAL_HOSTS+=("$host")
}

# Auto-include provider hosts from telclaude.json (for sidecar services)
# Set TELCLAUDE_FIREWALL_SKIP_PROVIDERS=1 on agent containers to prevent direct
# provider access — agents must route through the relay proxy.
TELCLAUDE_CONFIG_PATH="${TELCLAUDE_CONFIG:-/data/telclaude.json}"
PROVIDER_HOSTS_RAW=""
if [ "${TELCLAUDE_FIREWALL_SKIP_PROVIDERS:-0}" = "1" ]; then
    echo "[firewall] skipping provider hosts (TELCLAUDE_FIREWALL_SKIP_PROVIDERS=1)"
elif [ -f "$TELCLAUDE_CONFIG_PATH" ] && command -v node &> /dev/null; then
    PROVIDER_HOSTS_RAW="$(
        TELCLAUDE_CONFIG_PATH="$TELCLAUDE_CONFIG_PATH" node <<'NODE'
const fs = require("fs");
const configPath = process.env.TELCLAUDE_CONFIG_PATH || "/data/telclaude.json";
if (!fs.existsSync(configPath)) process.exit(0);
let JSON5;
try {
  JSON5 = require("/app/node_modules/json5");
} catch {
  try {
    JSON5 = require("json5");
  } catch {
    process.exit(0);
  }
}
let raw;
try {
  raw = fs.readFileSync(configPath, "utf8");
} catch {
  process.exit(0);
}
let cfg;
try {
  cfg = JSON5.parse(raw);
} catch {
  process.exit(0);
}
const providers = Array.isArray(cfg.providers) ? cfg.providers : [];
const hosts = [];
const seen = new Set();
for (const provider of providers) {
  if (!provider || typeof provider.baseUrl !== "string") continue;
  try {
    const host = new URL(provider.baseUrl).hostname;
    if (host && !seen.has(host)) {
      seen.add(host);
      hosts.push(host);
    }
  } catch {}
}
process.stdout.write(hosts.join(","));
NODE
    )"
fi

if [ -n "$PROVIDER_HOSTS_RAW" ]; then
    IFS=',' read -r -a PROVIDER_HOSTS <<< "$PROVIDER_HOSTS_RAW"
    for host in "${PROVIDER_HOSTS[@]}"; do
        append_internal_host "$host"
    done
    echo "[firewall] added provider hosts: ${PROVIDER_HOSTS[*]}"
fi

# ─────────────────────────────────────────────────────────────────────────────────
# Blocked metadata endpoints (cloud instance metadata - SSRF targets)
# ─────────────────────────────────────────────────────────────────────────────────
BLOCKED_METADATA_IPS=(
    "169.254.169.254"  # AWS/GCP/Azure/OCI/DO metadata
    "169.254.170.2"    # AWS ECS container metadata
    "100.100.100.200"  # Alibaba Cloud metadata
)

# ─────────────────────────────────────────────────────────────────────────────────
# Internal Host Resolution with Retry
# ─────────────────────────────────────────────────────────────────────────────────

# Resolve internal hosts with retry logic to handle container startup races.
# Returns 0 if all hosts resolved, 1 if any failed after retries.
resolve_internal_hosts_with_retry() {
    local all_resolved=0
    local attempt=1

    while [ $attempt -le $INTERNAL_HOST_RETRY_COUNT ]; do
        all_resolved=1
        local unresolved_hosts=()

        for host in "${INTERNAL_HOSTS[@]}"; do
            if [ -z "$host" ]; then
                continue
            fi
            local ips=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
            if [ -z "$ips" ]; then
                all_resolved=0
                unresolved_hosts+=("$host")
            fi
        done

        if [ $all_resolved -eq 1 ]; then
            echo "[firewall] all internal hosts resolved on attempt $attempt"
            return 0
        fi

        if [ $attempt -lt $INTERNAL_HOST_RETRY_COUNT ]; then
            echo "[firewall] waiting for internal hosts (attempt $attempt/$INTERNAL_HOST_RETRY_COUNT): ${unresolved_hosts[*]}"
            sleep $INTERNAL_HOST_RETRY_DELAY
        fi
        ((attempt++))
    done

    echo "[firewall] WARNING: some internal hosts failed to resolve after $INTERNAL_HOST_RETRY_COUNT attempts"
    return 1
}

# Add firewall rules for internal hosts (used by both setup and refresh)
add_internal_host_rules() {
    local updated=0
    for host in "${INTERNAL_HOSTS[@]}"; do
        if [ -z "$host" ]; then
            continue
        fi
        local ips=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
        if [ -n "$ips" ]; then
            for ip in $ips; do
                # Check if rule already exists before adding
                if ! iptables -C OUTPUT -d "$ip" -j ACCEPT 2>/dev/null; then
                    iptables -I OUTPUT 1 -d "$ip" -j ACCEPT 2>/dev/null || true
                    echo "[firewall] allowed internal: $host ($ip)"
                    ((updated++)) || true
                fi
            done
        else
            echo "[firewall] warning: could not resolve internal host $host"
        fi
    done
    return 0
}

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
    # ALLOW: Internal service hosts (relay/agent RPC)
    # Wait for internal hosts to be resolvable before blocking RFC1918
    # This handles container startup races (agent starts before relay is ready)
    # ═══════════════════════════════════════════════════════════════════════════
    if [ ${#INTERNAL_HOSTS[@]} -gt 0 ]; then
        resolve_internal_hosts_with_retry
        add_internal_host_rules
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # BLOCK: RFC1918 private networks (prevent internal network access)
    # IMPORTANT: This comes AFTER internal host allowlist to ensure RPC works
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

    # Allow DNS only to Docker resolver
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP

    # Block DNS-over-TLS (DoT)
    iptables -A OUTPUT -p tcp --dport 853 -j DROP
    iptables -A OUTPUT -p udp --dport 853 -j DROP

    # ═══════════════════════════════════════════════════════════════════════════
    # Network Mode: permissive/open allows all public egress
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "$NETWORK_MODE" = "permissive" ] || [ "$NETWORK_MODE" = "open" ]; then
        # In permissive/open mode, allow all outbound traffic (except metadata/RFC1918)
        # WebFetch can reach any public URL; protection is at application level
        iptables -A OUTPUT -j ACCEPT
        echo "[firewall] IPv4 firewall configured with PERMISSIVE policy"
        echo "[firewall] blocked: metadata endpoints, RFC1918 private networks"
        echo "[firewall] allowed: ALL public internet egress (TELCLAUDE_NETWORK_MODE=$NETWORK_MODE)"
        return 0
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # ALLOW: Whitelisted domains (restricted mode only)
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
    # DEFAULT DENY: Block everything else (must be LAST rule)
    # ═══════════════════════════════════════════════════════════════════════════
    # Remove any stale DROP-all rules first to ensure only one at the end
    while iptables -D OUTPUT -j DROP 2>/dev/null; do :; done
    iptables -A OUTPUT -j DROP

    echo "[firewall] IPv4 firewall configured with default-deny policy"
    echo "[firewall] blocked: metadata endpoints, RFC1918 private networks"
    echo "[firewall] allowed: ${#ALLOWED_DOMAINS[@]} domains + ${#INTERNAL_HOSTS[@]} internal hosts + DNS + SSH"
}

# ─────────────────────────────────────────────────────────────────────────────────
# IPv6 Firewall Setup (default-deny to prevent allowlist bypass)
#
# FAIL-CLOSED SEMANTICS:
# If IPv6 is enabled on the container and ip6tables is unavailable,
# this function fails when IPV6_FAIL_CLOSED=1 (default).
# This prevents a security gap where IPv6 egress bypasses the allowlist.
# ─────────────────────────────────────────────────────────────────────────────────

# Check if IPv6 is enabled on the container
# Returns 0 if IPv6 is enabled, 1 if disabled
is_ipv6_enabled() {
    # Check for global IPv6 addresses (not just link-local fe80::)
    if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
        return 0
    fi

    # Check for IPv6 default route
    if ip -6 route show default 2>/dev/null | grep -q "default"; then
        return 0
    fi

    # Check if IPv6 is disabled at kernel level
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
        if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = "1" ]; then
            return 1
        fi
    fi

    # No global IPv6 addresses and no default route = IPv6 not usable for egress
    return 1
}

setup_ipv6_firewall() {
    local ipv6_enabled=0
    if is_ipv6_enabled; then
        ipv6_enabled=1
        echo "[firewall-ipv6] IPv6 is enabled on this container"
    else
        echo "[firewall-ipv6] IPv6 is not enabled (no global addresses or routes)"
        echo "[firewall-ipv6] skipping IPv6 firewall setup"
        return 0
    fi

    # Check if ip6tables is available
    if ! command -v ip6tables &> /dev/null; then
        echo "[firewall-ipv6] ERROR: ip6tables not available but IPv6 is enabled"
        if [ "$IPV6_FAIL_CLOSED" = "1" ]; then
            echo "[firewall-ipv6] FAIL-CLOSED: refusing to start with unfiltered IPv6 egress"
            echo "[firewall-ipv6] set TELCLAUDE_IPV6_FAIL_CLOSED=0 to allow (not recommended)"
            return 1
        else
            echo "[firewall-ipv6] WARNING: IPv6 egress is UNFILTERED (IPV6_FAIL_CLOSED=0)"
            return 0
        fi
    fi

    # Check if we have permissions
    if ! ip6tables -L -n &> /dev/null 2>&1; then
        echo "[firewall-ipv6] ERROR: insufficient permissions for ip6tables but IPv6 is enabled"
        if [ "$IPV6_FAIL_CLOSED" = "1" ]; then
            echo "[firewall-ipv6] FAIL-CLOSED: refusing to start with unfiltered IPv6 egress"
            echo "[firewall-ipv6] run container with --cap-add=NET_ADMIN or disable IPv6 on Docker network"
            return 1
        else
            echo "[firewall-ipv6] WARNING: IPv6 egress is UNFILTERED (IPV6_FAIL_CLOSED=0)"
            return 0
        fi
    fi

    echo "[firewall-ipv6] setting up IPv6 firewall..."

    # Flush existing OUTPUT rules
    ip6tables -F OUTPUT 2>/dev/null || true

    # ═══════════════════════════════════════════════════════════════════════════
    # BLOCK FIRST: IPv6 metadata and private networks (SSRF protection)
    # These must be blocked BEFORE any allow rules, even in permissive mode
    # ═══════════════════════════════════════════════════════════════════════════
    # AWS IMDSv2 IPv6 endpoint
    ip6tables -A OUTPUT -d fd00:ec2::254 -j DROP
    echo "[firewall-ipv6] blocked: AWS IMDSv2 IPv6 metadata"
    # ULA (Unique Local Addresses) - IPv6 equivalent of RFC1918
    ip6tables -A OUTPUT -d fc00::/7 -j DROP
    echo "[firewall-ipv6] blocked: fc00::/7 (ULA private networks)"
    # Link-local - except ICMPv6 which is needed for NDP
    ip6tables -A OUTPUT -d fe80::/10 ! -p icmpv6 -j DROP
    echo "[firewall-ipv6] blocked: fe80::/10 (link-local, except ICMPv6)"

    # Allow loopback
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Block DNS over IPv6 (Docker resolver is IPv4-only)
    ip6tables -A OUTPUT -p udp --dport 53 -j DROP
    ip6tables -A OUTPUT -p tcp --dport 53 -j DROP

    # Block DNS-over-TLS (DoT)
    ip6tables -A OUTPUT -p tcp --dport 853 -j DROP
    ip6tables -A OUTPUT -p udp --dport 853 -j DROP

    # Allow ICMPv6 (needed for IPv6 to function properly)
    ip6tables -A OUTPUT -p icmpv6 -j ACCEPT

    # Network mode determines policy
    if [ "$NETWORK_MODE" = "permissive" ] || [ "$NETWORK_MODE" = "open" ]; then
        # In permissive/open mode, allow all IPv6 egress
        ip6tables -A OUTPUT -j ACCEPT
        echo "[firewall-ipv6] IPv6 configured with PERMISSIVE policy"
    else
        # DEFAULT DENY: Block all other IPv6 outbound
        # This is intentionally restrictive - we don't allowlist IPv6 destinations
        # because domain resolution for the allowlist only covers IPv4
        ip6tables -A OUTPUT -j DROP
        echo "[firewall-ipv6] IPv6 configured with default-deny policy"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────────
# Combined Firewall Setup
# ─────────────────────────────────────────────────────────────────────────────────

setup_all_firewalls() {
    # Setup IPv4 firewall (required)
    if ! setup_firewall; then
        return 1
    fi

    # Setup IPv6 firewall (fail-closed if IPv6 enabled and ip6tables unavailable)
    if ! setup_ipv6_firewall; then
        echo "[firewall] IPv6 firewall setup failed"
        return 1
    fi

    # Write sentinel file to indicate firewall is actually applied
    # Agent checks for this file to verify firewall is working
    local sentinel_dir="/run/telclaude"
    mkdir -p "$sentinel_dir" 2>/dev/null || true
    echo "$(date -Iseconds)" > "$sentinel_dir/firewall-active"
    echo "[firewall] sentinel written to $sentinel_dir/firewall-active"
}

# ─────────────────────────────────────────────────────────────────────────────────
# Refresh firewall rules (updates IP addresses for allowed domains)
# ─────────────────────────────────────────────────────────────────────────────────

refresh_firewall() {
    if ! command -v iptables &> /dev/null; then
        echo "[firewall-refresh] ERROR: iptables not available"
        return 1
    fi

    if ! iptables -L -n &> /dev/null 2>&1; then
        echo "[firewall-refresh] ERROR: insufficient permissions for iptables"
        return 1
    fi

    # In permissive/open mode, there's no domain allowlist to refresh
    if [ "$NETWORK_MODE" = "permissive" ] || [ "$NETWORK_MODE" = "open" ]; then
        echo "[firewall-refresh] skipping refresh (permissive mode - no domain allowlist)"
        return 0
    fi

    echo "[firewall-refresh] refreshing firewall rules..."

    local updated=0
    local failed=0

    # ═══════════════════════════════════════════════════════════════════════════
    # Refresh internal host IPs (handles IP changes after container restarts)
    # ═══════════════════════════════════════════════════════════════════════════
    echo "[firewall-refresh] checking internal hosts..."
    for host in "${INTERNAL_HOSTS[@]}"; do
        if [ -z "$host" ]; then
            continue
        fi
        local new_ips=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)

        if [ -z "$new_ips" ]; then
            echo "[firewall-refresh] warning: could not resolve internal host $host"
            ((failed++)) || true
            continue
        fi

        for ip in $new_ips; do
            if ! iptables -C OUTPUT -d "$ip" -j ACCEPT 2>/dev/null; then
                # Insert at position 1 (top) to ensure it's before RFC1918 drops
                iptables -I OUTPUT 1 -d "$ip" -j ACCEPT 2>/dev/null || true
                echo "[firewall-refresh] added internal: $host -> $ip"
                ((internal_updated++)) || true
                ((updated++)) || true
            fi
        done
    done

    # Ensure DROP-all is at end after internal host updates
    if [ ${internal_updated:-0} -gt 0 ]; then
        while iptables -D OUTPUT -j DROP 2>/dev/null; do :; done
        iptables -A OUTPUT -j DROP
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # Refresh allowed domain IPs (handles DNS changes)
    # ═══════════════════════════════════════════════════════════════════════════
    echo "[firewall-refresh] checking allowed domains..."
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        # Resolve domain to current IP addresses
        local new_ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u)

        if [ -z "$new_ips" ]; then
            echo "[firewall-refresh] warning: could not resolve $domain"
            ((failed++)) || true
            continue
        fi

        # Add new IPs that aren't already allowed
        for ip in $new_ips; do
            if ! iptables -C OUTPUT -d "$ip" -j ACCEPT 2>/dev/null; then
                # Rule doesn't exist, add it at position 1 (top, before any DROP rules)
                iptables -I OUTPUT 1 -d "$ip" -j ACCEPT 2>/dev/null || true
                echo "[firewall-refresh] added: $domain -> $ip"
                ((updated++)) || true
            fi
        done
    done

    # Ensure DROP-all rule is at the very end (refresh inserts may have shifted it)
    if [ $updated -gt 0 ]; then
        # Remove and re-add DROP-all to ensure it's last
        while iptables -D OUTPUT -j DROP 2>/dev/null; do :; done
        iptables -A OUTPUT -j DROP
    fi

    if [ $updated -gt 0 ]; then
        echo "[firewall-refresh] updated $updated rules"
    else
        echo "[firewall-refresh] no updates needed"
    fi

    if [ $failed -gt 0 ]; then
        echo "[firewall-refresh] warning: $failed entries failed to resolve"
    fi

    # Update sentinel timestamp
    local sentinel_dir="/run/telclaude"
    if [ -d "$sentinel_dir" ]; then
        echo "$(date -Iseconds) (refreshed)" > "$sentinel_dir/firewall-active"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────────

main() {
    # Check for --refresh-only mode (used by firewall-refresh.sh daemon)
    if [ "$1" = "--refresh-only" ]; then
        if [ "${TELCLAUDE_FIREWALL:-0}" = "1" ]; then
            refresh_firewall
        fi
        exit 0
    fi

    # Only setup firewall if TELCLAUDE_FIREWALL=1
    if [ "${TELCLAUDE_FIREWALL:-0}" = "1" ]; then
        if ! setup_all_firewalls; then
            echo "[firewall] CRITICAL: firewall setup failed but TELCLAUDE_FIREWALL=1"
            echo "[firewall] container will refuse to start without verified firewall"
            exit 1
        fi
    else
        echo "[firewall] firewall disabled (set TELCLAUDE_FIREWALL=1 to enable)"
    fi
}

main "$@"
