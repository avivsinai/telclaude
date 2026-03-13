# Security Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 12 findings from GPT-5.4 Pro review + Codex cross-review (4 HIGH, 4 MEDIUM, 2 LOW, 2 Codex additions).

**Architecture:** Thread session tokens explicitly instead of global state. Harden Docker firewall DNS validation and rule ordering. Enforce documented invariants (token grace, mixed-IP DNS, CGNAT). Fix DX issues (atomic writes, safe git config).

**Tech Stack:** TypeScript, Node.js, bash/iptables (Docker firewall)

---

## Chunk 1: HIGH Priority Fixes (#1-#4)

### Task 1: Fix session token race condition (Finding #1)

**Files:**
- Modify: `src/sdk/client.ts:127-170` (add `sessionToken` to `TelclaudeQueryOptions`)
- Modify: `src/sdk/client.ts:860-864` (read from opts, not process.env)
- Modify: `src/agent/server.ts:25-31, 310-318, 394-401` (remove global state, pass through opts)
- Modify: `src/agent/server.ts:163-175` (pass sessionToken to executePooledQuery)
- Test: `tests/agent/server.test.ts`

- [ ] **Step 1: Add `sessionToken` field to `TelclaudeQueryOptions`**

In `src/sdk/client.ts`, add to the `TelclaudeQueryOptions` type:

```typescript
/** Pre-minted session token for relay capabilities (request-scoped, NOT from process.env). */
sessionToken?: string;
```

- [ ] **Step 2: Update `buildSdkOptions` to use opts.sessionToken instead of process.env**

In `src/sdk/client.ts:860-864`, replace:

```typescript
if (process.env.TELCLAUDE_SESSION_TOKEN) {
    sandboxEnv.TELCLAUDE_SESSION_TOKEN = process.env.TELCLAUDE_SESSION_TOKEN;
}
```

with:

```typescript
if (opts.sessionToken) {
    sandboxEnv.TELCLAUDE_SESSION_TOKEN = opts.sessionToken;
}
```

- [ ] **Step 3: Remove global session token state from agent server**

In `src/agent/server.ts`, remove:
- The `activeSessionTokenRequestId` variable (line ~30)
- The `process.env.TELCLAUDE_SESSION_TOKEN = parsed.sessionToken` block (lines 310-318)
- The cleanup in `.finally()` (lines 396-401)

- [ ] **Step 4: Thread sessionToken through streamQuery → executePooledQuery**

In `src/agent/server.ts:163-175`, add `sessionToken: req.sessionToken` to the opts passed to `executePooledQuery`.

- [ ] **Step 5: Run tests**

Run: `pnpm test -- --grep "agent server|client-options|pooled"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/sdk/client.ts src/agent/server.ts
git commit -m "fix(security): thread session token explicitly instead of global process.env

Fixes concurrent request race where request B's token overwrites request A's
token before A's subprocess launches. Session token is now passed through
TelclaudeQueryOptions and written directly into per-request sandboxEnv."
```

---

### Task 2: Fix settingSources / hook-bypass regression (Finding #2)

**Files:**
- Modify: `src/sdk/client.ts:1173-1184` (always project-only settingSources)

- [ ] **Step 1: Lock settingSources to project-only**

In `src/sdk/client.ts:1173-1184`, replace:

```typescript
sdkOpts.settingSources = opts.enableSkills ? ["user", "project"] : ["project"];
```

with:

```typescript
// SECURITY: Always project-only. Loading "user" settings would allow a pre-seeded
// settings.json in CLAUDE_CONFIG_DIR to set disableAllHooks: true, bypassing
// PreToolUse security hooks. Skills are discovered via CLAUDE_CONFIG_DIR/skills/
// which the SDK loads regardless of settingSources when enableSkills is true.
sdkOpts.settingSources = ["project"];
```

- [ ] **Step 2: Verify skills still load without "user" settingSources**

Run: `pnpm test -- --grep "skill|settings"`
Expected: PASS — skills load from CLAUDE_CONFIG_DIR/skills/ independent of settingSources.

- [ ] **Step 3: Commit**

```bash
git add src/sdk/client.ts
git commit -m "fix(security): lock settingSources to project-only, preventing disableAllHooks bypass

Previously, enableSkills=true added 'user' to settingSources, allowing a
pre-seeded settings.json in CLAUDE_CONFIG_DIR to disable all hooks. Skills
are loaded from CLAUDE_CONFIG_DIR/skills/ regardless of settingSources."
```

---

### Task 3: Fix Docker firewall DNS→RFC1918 bypass + add CGNAT block (Findings #3, Codex #1)

**Files:**
- Modify: `docker/init-firewall.sh:345-356` (add CGNAT 100.64.0.0/10 drop rule)
- Modify: `docker/init-firewall.sh:396-409` (add `is_public_ip` check for domain resolution)
- Modify: `docker/init-firewall.sh:617-629` (same check in refresh function)

- [ ] **Step 1: Add `is_public_ip` helper function**

Add after the `BLOCKED_METADATA_IPS` array (around line 223):

```bash
# Check if an IP is public (not RFC1918, not CGNAT, not link-local, not metadata)
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
    # Check metadata IPs
    for blocked in "${BLOCKED_METADATA_IPS[@]}"; do
        if [ "$ip" = "$blocked" ]; then
            return 1
        fi
    done
    return 0
}
```

- [ ] **Step 2: Add CGNAT drop rule alongside RFC1918**

In `docker/init-firewall.sh:350-356`, add CGNAT block after the existing RFC1918 drops:

```bash
iptables -A OUTPUT -d 100.64.0.0/10 -j DROP   # CGNAT (Tailscale, carrier NAT)
```

- [ ] **Step 3: Filter non-public IPs from domain resolution (initial setup)**

In `docker/init-firewall.sh:396-409`, wrap the IP acceptance with `is_public_ip`:

```bash
for domain in "${ALLOWED_DOMAINS[@]}"; do
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
```

- [ ] **Step 4: Same filter in refresh function**

In `docker/init-firewall.sh:617-629`, apply the same `is_public_ip` check:

```bash
for ip in $new_ips; do
    if is_public_ip "$ip"; then
        iptables -A TELCLAUDE_ALLOW -d "$ip" -j ACCEPT 2>/dev/null || true
    else
        echo "[firewall-refresh] WARNING: $domain resolved to private IP $ip, skipping"
    fi
    ((updated++)) || true
done
```

- [ ] **Step 5: Commit**

```bash
git add docker/init-firewall.sh
git commit -m "fix(security): block CGNAT in firewall, reject private IPs from domain resolution

Adds 100.64.0.0/10 (CGNAT/Tailscale) to iptables DROP rules alongside RFC1918.
Domain resolution now validates that resolved IPs are public before adding
ACCEPT rules to TELCLAUDE_ALLOW chain, preventing DNS-based RFC1918 bypass."
```

---

### Task 4: Implement privateEndpoints in Docker firewall (Finding #4)

**Files:**
- Modify: `docker/init-firewall.sh:154-213` (add privateEndpoints parsing from config)
- Modify: `docker/init-firewall.sh:372-378` (add private endpoint rules to TELCLAUDE_ALLOW)

- [ ] **Step 1: Parse privateEndpoints from config**

After the provider hosts parsing block (line ~213), add:

```bash
# Parse privateEndpoints from config (security.network.privateEndpoints[])
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
  const ports = Array.isArray(ep.ports) ? ep.ports.join(",") : "";
  rules.push(target + "|" + ports);
}
process.stdout.write(rules.join("\n"));
NODE
    )"
fi
```

- [ ] **Step 2: Add private endpoint rules to TELCLAUDE_ALLOW chain**

After the internal host rules block (line ~378), add:

```bash
# Add private endpoint rules (from security.network.privateEndpoints config)
if [ -n "$PRIVATE_ENDPOINTS_RAW" ]; then
    echo "[firewall] adding private endpoint rules..."
    while IFS='|' read -r target ports; do
        [ -z "$target" ] && continue
        if [ -n "$ports" ]; then
            # Port-scoped rules
            IFS=',' read -r -a port_arr <<< "$ports"
            for port in "${port_arr[@]}"; do
                iptables -A TELCLAUDE_ALLOW -d "$target" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
                echo "[firewall] allowed private endpoint: $target:$port"
            done
        else
            # No port restriction
            iptables -A TELCLAUDE_ALLOW -d "$target" -j ACCEPT 2>/dev/null || true
            echo "[firewall] allowed private endpoint: $target (all ports)"
        fi
    done <<< "$PRIVATE_ENDPOINTS_RAW"
fi
```

- [ ] **Step 3: Also add to refresh function**

Add private endpoint rules to `refresh_firewall_rules()` after internal hosts.

- [ ] **Step 4: Commit**

```bash
git add docker/init-firewall.sh
git commit -m "fix(security): implement privateEndpoints in Docker firewall

Config schema already supports security.network.privateEndpoints and
the app layer enforces them, but Docker iptables rules were never
synthesized. Now parses endpoints from telclaude.json and installs
ACCEPT rules with host/CIDR + port scoping in TELCLAUDE_ALLOW chain."
```

---

## Chunk 2: MEDIUM Priority Fixes (#5-#8)

### Task 5: Fix SOCIAL tier permissive inconsistency (Finding #5, Codex #2)

**Files:**
- Modify: `src/sdk/client.ts:1143-1154` (use `effectivePermissive` instead of `isPermissiveMode`)

- [ ] **Step 1: Fix canUseTool to use effectivePermissive**

In `src/sdk/client.ts:1143-1154`, replace:

```typescript
if (
    !isPermissiveMode &&
    !allowedDomains.some((pattern) => domainMatchesPattern(url.hostname, pattern))
) {
```

with:

```typescript
if (
    !effectivePermissive &&
    !allowedDomains.some((pattern) => domainMatchesPattern(url.hostname, pattern))
) {
```

- [ ] **Step 2: Run tests**

Run: `pnpm test -- --grep "canUseTool|can-use-tool"`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/sdk/client.ts
git commit -m "fix(security): use effectivePermissive in canUseTool for SOCIAL tier consistency

canUseTool was checking isPermissiveMode (env var only) while buildSdkOptions
used effectivePermissive (which includes social context). This caused SOCIAL
agents to be blocked by canUseTool even though the hook would allow them."
```

---

### Task 6: Enforce all-IPs-must-match in checkPrivateNetworkAccess (Finding #6)

**Files:**
- Modify: `src/sandbox/network-proxy.ts:650-663` (fail on mixed public+private resolution)
- Test: `tests/sandbox/network-proxy.test.ts`

- [ ] **Step 1: Add mixed public/private IP check**

In `src/sandbox/network-proxy.ts:650-663`, after the `isPrivateIP` check block, add an else clause:

```typescript
// 4b. Check if IP is private - if so, must be in allowlist
if (isPrivateIP(canonicalIP)) {
    const match = findMatchingPrivateEndpoint(canonicalIP, endpoints, hostname);
    if (!match.matched) {
        return {
            allowed: false,
            reason: `Private IP ${ip} is not in the allowlist`,
        };
    }
    if (match.endpoint) {
        matchedEndpoints.push(match.endpoint);
    }
} else if (matchedEndpoints.length > 0) {
    // Mixed resolution: hostname resolves to BOTH private (already matched)
    // and public IPs. This is suspicious (DNS rebinding) — fail closed.
    return {
        allowed: false,
        reason: `Mixed private/public DNS resolution for ${hostname} — possible DNS rebinding`,
    };
}
```

Also after the loop, add a check for the reverse case (public first, then private):

Actually, let me reconsider. The loop processes IPs sequentially. If a private IP matches first, then a public IP is seen → mixed. If a public IP is first, matchedEndpoints is still empty, so the else-if won't trigger. But then a private IP may come later and match. We need to track both.

Better approach: track whether we've seen public AND private IPs:

```typescript
let hasPublicIP = false;
let hasPrivateIP = false;

for (const ip of targetIPs) {
    // ... existing canonicalize + non-overridable checks ...

    if (isPrivateIP(canonicalIP)) {
        hasPrivateIP = true;
        const match = findMatchingPrivateEndpoint(canonicalIP, endpoints, hostname);
        if (!match.matched) {
            return { allowed: false, reason: `Private IP ${ip} is not in the allowlist` };
        }
        if (match.endpoint) {
            matchedEndpoints.push(match.endpoint);
        }
    } else {
        hasPublicIP = true;
    }
}

// Fail closed on mixed public/private resolution (DNS rebinding indicator)
if (hasPublicIP && hasPrivateIP) {
    return {
        allowed: false,
        reason: `Mixed private/public DNS resolution for ${hostname} — possible DNS rebinding`,
    };
}
```

- [ ] **Step 2: Add test for mixed resolution**

In `tests/sandbox/network-proxy.test.ts`, add a test case.

- [ ] **Step 3: Run tests**

Run: `pnpm test -- --grep "network-proxy|private-endpoint"`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/sandbox/network-proxy.ts tests/sandbox/network-proxy.test.ts
git commit -m "fix(security): fail closed on mixed public/private DNS resolution

Architecture doc says all resolved IPs must pass allowlist. Previously
only private IPs were checked. Now mixed public+private resolution is
rejected as a DNS rebinding indicator."
```

---

### Task 7: Enforce session ID membership in token verification (Finding #7)

**Files:**
- Modify: `src/relay/token-manager.ts:147-203` (add sessionId membership check)
- Test: `tests/relay/token-manager.test.ts` (create if needed)

- [ ] **Step 1: Add sessionId membership check to verifyTokenLocally**

After the signature verification succeeds (line ~199), before the return, add:

```typescript
// Verify sessionId is a known current or grace-period token
const scopeState = scopeTokens.get(scope as InternalAuthScope);
if (scopeState) {
    const isCurrentSession = scopeState.current.sessionId === sessionId;
    const isPreviousSession = scopeState.previous?.sessionId === sessionId;
    if (!isCurrentSession && !isPreviousSession) {
        return { valid: false, error: "Session ID not recognized (rotated out)" };
    }
}
// If no scope state exists (relay just restarted), accept any valid-signature token
```

- [ ] **Step 2: Run tests**

Run: `pnpm test -- --grep "token"`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/relay/token-manager.ts
git commit -m "fix(security): enforce sessionId membership during token verification

verifyTokenLocally now checks that the token's sessionId matches either
the current or previous (grace period) token for its scope. Previously
only signature and expiry were checked, making the grace period comments
misleading."
```

---

### Task 8: Stream video hash instead of loading entire file (Finding #8)

**Files:**
- Modify: `src/services/video-processor.ts:126-129` (use createReadStream)

- [ ] **Step 1: Replace readFile with streaming hash**

In `src/services/video-processor.ts:126-129`, replace:

```typescript
const videoBuffer = await fs.promises.readFile(videoPath);
const hash = crypto.createHash("sha256").update(videoBuffer).digest("hex").slice(0, 16);
```

with:

```typescript
const hash = await new Promise<string>((resolve, reject) => {
    const hasher = crypto.createHash("sha256");
    const stream = fs.createReadStream(videoPath);
    stream.on("data", (chunk) => hasher.update(chunk));
    stream.on("end", () => resolve(hasher.digest("hex").slice(0, 16)));
    stream.on("error", reject);
});
```

- [ ] **Step 2: Run tests**

Run: `pnpm test -- --grep "video"`
Expected: PASS (or no existing tests — verify manually)

- [ ] **Step 3: Commit**

```bash
git add src/services/video-processor.ts
git commit -m "fix(perf): stream video hash instead of loading entire file into RAM

Large video uploads could spike memory or OOM before the duration cap
kicked in. Now uses createReadStream for constant-memory hashing."
```

---

## Chunk 3: LOW Priority Fixes (#9-#10)

### Task 9: Replace execSync with execFileSync in setup-github-app (Finding #9)

**Files:**
- Modify: `src/commands/setup-github-app.ts:46-55`

- [ ] **Step 1: Replace shell-interpolated execSync with execFileSync**

In `src/commands/setup-github-app.ts:46-55`, replace:

```typescript
execSync(`git config --global user.name "${identity.username}"`, { stdio: "pipe" });
execSync(`git config --global user.email "${identity.email}"`, { stdio: "pipe" });
```

with:

```typescript
execFileSync("git", ["config", "--global", "user.name", identity.username], { stdio: "pipe" });
execFileSync("git", ["config", "--global", "user.email", identity.email], { stdio: "pipe" });
```

Also update the import from `child_process` to include `execFileSync`.

- [ ] **Step 2: Commit**

```bash
git add src/commands/setup-github-app.ts
git commit -m "fix(security): use execFileSync instead of shell-interpolated execSync for git config

Removes unnecessary shell injection surface. The rest of the codebase
already uses spawnSync/execFileSync for git operations."
```

---

### Task 10: Atomic JSON write + JSON5 warning in network command (Finding #10)

**Files:**
- Modify: `src/commands/network.ts:44-46`

- [ ] **Step 1: Implement atomic write with temp file + rename**

In `src/commands/network.ts:44-46`, replace:

```typescript
function writeConfigFile(config: Record<string, unknown>): void {
    const configPath = getConfigPath();
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), "utf-8");
}
```

with:

```typescript
function writeConfigFile(config: Record<string, unknown>): void {
    const configPath = getConfigPath();
    const tmpPath = `${configPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(config, null, 2), "utf-8");
    fs.renameSync(tmpPath, configPath);
    logger.debug("config written atomically (note: JSON5 comments/trailing commas are stripped)");
}
```

- [ ] **Step 2: Commit**

```bash
git add src/commands/network.ts
git commit -m "fix(dx): atomic config write + JSON5 syntax loss warning

Write to temp file and rename atomically to prevent partial writes
on interruption. Log a warning about JSON5 syntax being stripped."
```

---

## Execution Checklist

After all tasks:

- [ ] Run full test suite: `pnpm test`
- [ ] Run typecheck: `pnpm typecheck`
- [ ] Run lint: `pnpm lint`
- [ ] Send to Codex for review via AMQ
