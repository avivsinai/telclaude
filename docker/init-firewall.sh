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

# Generated from src/sandbox/firewall-domains.ts.
source "$(dirname "$0")/allowed-domains.generated.sh"

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

# Parse privateEndpoints from config (security.network.privateEndpoints[])
# These allow agent WebFetch access to specific trusted private network hosts/CIDRs.
PRIVATE_ENDPOINTS_RAW=""
if [ -f "$TELCLAUDE_CONFIG_PATH" ] && command -v node &> /dev/null; then
    PRIVATE_ENDPOINTS_RAW="$(
        TELCLAUDE_CONFIG_PATH="$TELCLAUDE_CONFIG_PATH" node <<'NODE'
const fs = require("fs");
const configPath = process.env.TELCLAUDE_CONFIG_PATH || "/data/telclaude.json";
if (!fs.existsSync(configPath)) process.exit(0);
let JSON5;
try { JSON5 = require("/app/node_modules/json5"); } catch {
  try { JSON5 = require("json5"); } catch { process.exit(0); }
}
let raw;
try { raw = fs.readFileSync(configPath, "utf8"); } catch { process.exit(0); }
let cfg;
try { cfg = JSON5.parse(raw); } catch { process.exit(0); }
const endpoints = cfg?.security?.network?.privateEndpoints;
if (!Array.isArray(endpoints)) process.exit(0);
const rules = [];
for (const ep of endpoints) {
  if (!ep) continue;
  const target = ep.cidr || ep.host;
  if (!target) continue;
  // Match app-layer default: omitted/empty ports → 80,443 only
  const ports = Array.isArray(ep.ports) && ep.ports.length > 0 ? ep.ports.join(",") : "80,443";
  rules.push(target + "|" + ports);
}
process.stdout.write(rules.join("\n"));
NODE
    )"
fi

# ─────────────────────────────────────────────────────────────────────────────────
# Blocked metadata endpoints (cloud instance metadata - SSRF targets)
# ─────────────────────────────────────────────────────────────────────────────────
BLOCKED_METADATA_IPS=(
    "169.254.169.254"  # AWS/GCP/Azure/OCI/DO metadata
    "169.254.170.2"    # AWS ECS container metadata
    "100.100.100.200"  # Alibaba Cloud metadata
)

# Check if an IP is public (not RFC1918, not CGNAT, not link-local, not loopback, not metadata)
is_public_ip() {
    local ip="$1"
    case "$ip" in
        10.*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 1 ;;
        192.168.*) return 1 ;;
        169.254.*) return 1 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 1 ;;
        127.*) return 1 ;;
    esac
    for blocked in "${BLOCKED_METADATA_IPS[@]}"; do
        if [ "$ip" = "$blocked" ]; then
            return 1
        fi
    done
    return 0
}

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
                if ! iptables -C TELCLAUDE_ALLOW -d "$ip" -j ACCEPT 2>/dev/null; then
                    iptables -A TELCLAUDE_ALLOW -d "$ip" -j ACCEPT 2>/dev/null || true
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

    # Create/flush TELCLAUDE_ALLOW chain for dynamic ACCEPT rules.
    # All dynamic rules (internal hosts + allowed domains) go here,
    # ensuring they can never land above metadata DROPs in OUTPUT.
    iptables -N TELCLAUDE_ALLOW 2>/dev/null || iptables -F TELCLAUDE_ALLOW

    # ═══════════════════════════════════════════════════════════════════════════
    # OUTPUT chain: fixed structure (order is critical for security!)
    #
    # 1. ESTABLISHED,RELATED  — performance (most packets match here)
    # 2. Loopback              — local communication
    # 3. Metadata DROPs        — SSRF protection (ALWAYS before any ACCEPT)
    # 4. → TELCLAUDE_ALLOW     — dynamic rules (internal hosts + domains)
    # 5. RFC1918 DROPs         — after allow chain so Docker bridge IPs pass
    # 6. DNS rules             — Docker resolver only
    # 7. Default DROP          — deny everything else
    # ═══════════════════════════════════════════════════════════════════════════

    # Allow established connections (must be first for performance)
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow loopback (needed for internal communication)
    iptables -A OUTPUT -o lo -j ACCEPT

    # BLOCK: Metadata endpoints (SSRF protection - critical!)
    # These must be blocked BEFORE the TELCLAUDE_ALLOW jump so no dynamic
    # rule can ever bypass them
    for ip in "${BLOCKED_METADATA_IPS[@]}"; do
        iptables -A OUTPUT -d "$ip" -j DROP
        echo "[firewall] blocked metadata: $ip"
    done

    # Jump to dynamic allow chain (internal hosts + allowed domains)
    # Placed AFTER metadata DROPs (can never be bypassed) but BEFORE
    # RFC1918 DROPs (Docker bridge IPs are RFC1918 and need to pass)
    iptables -A OUTPUT -j TELCLAUDE_ALLOW

    # BLOCK: RFC1918 private networks (prevent internal network access)
    # AFTER TELCLAUDE_ALLOW jump so explicitly allowed internal hosts pass
    iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
    iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
    iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
    iptables -A OUTPUT -d 169.254.0.0/16 -j DROP  # Link-local
    iptables -A OUTPUT -d 100.64.0.0/10 -j DROP   # CGNAT (Tailscale, carrier NAT)
    echo "[firewall] blocked RFC1918 + CGNAT private networks"

    # Allow DNS only to Docker resolver
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -j DROP
    iptables -A OUTPUT -p tcp --dport 53 -j DROP

    # Block DNS-over-TLS (DoT)
    iptables -A OUTPUT -p tcp --dport 853 -j DROP
    iptables -A OUTPUT -p udp --dport 853 -j DROP

    # ═══════════════════════════════════════════════════════════════════════════
    # TELCLAUDE_ALLOW: Internal hosts (needed by ALL modes including permissive)
    # Must be populated BEFORE the permissive ACCEPT or default DENY,
    # because RFC1918 DROPs above catch Docker bridge IPs.
    # ═══════════════════════════════════════════════════════════════════════════

    # Add internal hosts (Docker bridge IPs — must be allowed before RFC1918 drop)
    if [ ${#INTERNAL_HOSTS[@]} -gt 0 ]; then
        resolve_internal_hosts_with_retry
        add_internal_host_rules
    fi

    # Add private endpoint rules (from security.network.privateEndpoints config)
    if [ -n "$PRIVATE_ENDPOINTS_RAW" ]; then
        echo "[firewall] adding private endpoint rules..."
        while IFS='|' read -r target ports; do
            [ -z "$target" ] && continue
            if [ -n "$ports" ]; then
                IFS=',' read -r -a port_arr <<< "$ports"
                for port in "${port_arr[@]}"; do
                    iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
                    echo "[firewall] allowed private endpoint: $target:$port"
                done
            else
                # Defensive fallback — serializer should always emit ports (default 80,443)
                echo "[firewall] WARNING: private endpoint $target has no ports, applying default 80,443"
                iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
                iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
            fi
        done <<< "$PRIVATE_ENDPOINTS_RAW"
    fi

    # ═══════════════════════════════════════════════════════════════════════════
    # Network Mode: permissive/open allows all public egress
    # ═══════════════════════════════════════════════════════════════════════════
    if [ "$NETWORK_MODE" = "permissive" ] || [ "$NETWORK_MODE" = "open" ]; then
        # In permissive/open mode, allow all outbound traffic (except metadata/RFC1918)
        # WebFetch can reach any public URL; protection is at application level
        iptables -A OUTPUT -j ACCEPT
        echo "[firewall] IPv4 firewall configured with PERMISSIVE policy"
        echo "[firewall] blocked: metadata endpoints, RFC1918 private networks"
        echo "[firewall] allowed: ALL public internet egress + ${#INTERNAL_HOSTS[@]} internal hosts (TELCLAUDE_NETWORK_MODE=$NETWORK_MODE)"
        return 0
    fi

    # DEFAULT DENY (must be last in OUTPUT)
    iptables -A OUTPUT -j DROP

    # Add whitelisted domains (restricted mode only)
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        # Resolve domain to IPv4 addresses only (iptables doesn't handle IPv6)
        ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u)

        if [ -n "$ips" ]; then
            for ip in $ips; do
                if is_public_ip "$ip"; then
                    iptables -A TELCLAUDE_ALLOW -d "$ip" -j ACCEPT
                    echo "[firewall] allowed: $domain ($ip)"
                else
                    echo "[firewall] WARNING: $domain resolved to private IP $ip, skipping"
                fi
            done
        else
            echo "[firewall] warning: could not resolve $domain"
        fi
    done

    echo "[firewall] IPv4 firewall configured with default-deny policy"
    echo "[firewall] blocked: metadata endpoints, RFC1918 private networks"
    echo "[firewall] allowed: ${#ALLOWED_DOMAINS[@]} domains + ${#INTERNAL_HOSTS[@]} internal hosts + DNS"
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

    echo "[firewall-refresh] refreshing TELCLAUDE_ALLOW chain..."

    local updated=0
    local failed=0

    # Flush and rebuild the entire TELCLAUDE_ALLOW chain.
    # This is clean and atomic — no risk of rules landing above
    # metadata/RFC1918 DROPs in the OUTPUT chain.
    iptables -F TELCLAUDE_ALLOW 2>/dev/null || true

    # ═══════════════════════════════════════════════════════════════════════════
    # Re-add internal host rules (handles IP changes after container restarts)
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
            iptables -A TELCLAUDE_ALLOW -d "$ip" -j ACCEPT 2>/dev/null || true
            ((updated++)) || true
        done
        echo "[firewall-refresh] allowed internal: $host"
    done

    # ═══════════════════════════════════════════════════════════════════════════
    # Re-add allowed domain rules (handles DNS changes)
    # ═══════════════════════════════════════════════════════════════════════════
    echo "[firewall-refresh] checking allowed domains..."
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        local new_ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u)

        if [ -z "$new_ips" ]; then
            echo "[firewall-refresh] warning: could not resolve $domain"
            ((failed++)) || true
            continue
        fi

        for ip in $new_ips; do
            if is_public_ip "$ip"; then
                iptables -A TELCLAUDE_ALLOW -d "$ip" -j ACCEPT 2>/dev/null || true
            else
                echo "[firewall-refresh] WARNING: $domain resolved to private IP $ip, skipping"
            fi
        done
        ((updated++)) || true
    done

    # Re-add private endpoint rules
    if [ -n "$PRIVATE_ENDPOINTS_RAW" ]; then
        while IFS='|' read -r target ports; do
            [ -z "$target" ] && continue
            if [ -n "$ports" ]; then
                IFS=',' read -r -a port_arr <<< "$ports"
                for port in "${port_arr[@]}"; do
                    iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
                done
            else
                # Defensive fallback — serializer should always emit ports
                iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
                iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
            fi
            ((updated++)) || true
        done <<< "$PRIVATE_ENDPOINTS_RAW"
        echo "[firewall-refresh] re-added private endpoint rules"
    fi

    echo "[firewall-refresh] rebuilt TELCLAUDE_ALLOW chain ($updated entries)"

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
