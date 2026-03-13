# GPT-5.4 Pro Code Review — Telclaude
**Date**: 2026-03-13
**Model**: ChatGPT 5.4 Pro (Extended Pro, 37min thinking)
**Input**: 310 files, ~580K tokens

---

## Summary

The codebase has a strong design, but the implementation currently breaks some of its own stated security invariants. No obvious one-shot container escape or raw secret leakage to Telegram found in highest-value codepaths, but several HIGH issues and important medium/low ones.

---

## HIGH Findings

### 1. Request-scoped session tokens stored in global process state — concurrent requests inherit wrong token
**Files**: `src/agent/server.ts:310-317, 394-400`, `src/sdk/client.ts:860-864`, `src/agent/token-client.ts:239-267, 281-288`
**Severity**: HIGH

The agent server writes `parsed.sessionToken` into `process.env.TELCLAUDE_SESSION_TOKEN` for each request, then `buildSdkOptions()` copies that global value into the spawned Claude subprocess environment. The request-id guard only prevents one request from deleting another request's token during cleanup; it does **not** prevent one request from overwriting another request's token before the subprocess is created.

Under concurrency:
- request A sets token A
- request B sets token B
- request A's subprocess can now be launched with token B

Relay capability calls from A's subprocess can run under the wrong session identity.

**Fix**: Stop using `process.env` for per-request auth state. Thread `sessionToken` explicitly through `executePooledQuery()` / `buildSdkOptions()` and write it directly into that request's `sandboxEnv`. `AsyncLocalStorage` would also work, but explicit parameters are simpler and safer.

### 2. Enabling skills re-opens the disableAllHooks bypass that docs say is prevented
**Files**: `CLAUDE.md:23-25`, `src/sdk/client.ts:1173-1184`, `src/agent/server.ts:163-170`, `docker/docker-compose.yml:241-243, 267-268, 338-339, 354-358`
**Severity**: HIGH

Docs say `settingSources: ["project"]` prevents user-level `disableAllHooks` bypasses. But runtime switches to `["user", "project"]` whenever `enableSkills` is true, and non-READ_ONLY requests default to `enableSkills: true`.

A stale or pre-seeded `settings.json` in `CLAUDE_CONFIG_DIR` (mounted from writable Docker volumes) can disable PreToolUse hooks before they ever enforce anything.

**Fix**: Keep `settingSources` project-only at runtime. If skills must live in user profile, copy/sync only `skills/` subtree into a clean runtime directory and refuse startup if any `settings*.json` exists there.

### 3. Docker firewall can whitelist RFC1918/private IPs via allowlisted domain DNS
**Files**: `docker/init-firewall.sh:345-356, 396-405, 617-629`, `docs/architecture.md:79`
**Severity**: HIGH

The firewall jumps into `TELCLAUDE_ALLOW` before RFC1918 drop rules. When resolving public allowlisted domains, there's no "must be public" check. If an allowlisted domain resolves to `10.x`, `172.16/12`, `192.168.x`, or link-local, the script installs an ACCEPT rule above the RFC1918 DROPs.

Directly violates architecture doc's "RFC1918/metadata endpoints are always blocked" invariant.

**Fix**: When resolving public allowlisted domains, reject non-public results entirely. Only explicit internal-host / private-endpoint rules should sit above RFC1918 drops.

### 4. privateEndpoints documented and modeled in config, but not implemented in Docker firewall
**Files**: `src/config/config.ts:227-255`, `README.md:20`, `src/sandbox/network-proxy.ts:591-683`, `docker/init-firewall.sh:154-213`
**Severity**: HIGH

Config schema supports `security.network.privateEndpoints`, README advertises a private network allowlist, and app-layer `checkPrivateNetworkAccess()` understands them. But Docker firewall only imports internal service hosts and provider base URLs — no iptables rules from `privateEndpoints`.

Result: WebFetch may pass app-layer but fail at firewall. Operators may "fix" by broadening network access.

**Fix**: Parse `privateEndpoints` during firewall init and install precise ACCEPT rules with host/CIDR + port scoping before RFC1918 drops.

---

## MEDIUM Findings

### 5. SOCIAL tier treated as "permissive WebFetch" in code/docs but not in Docker reality
**Files**: `CLAUDE.md:19`, `docs/architecture.md:93-99`, `src/sdk/client.ts:937-945`, `docker/docker-compose.yml:323-350`
**Severity**: MEDIUM

SDK force-enables permissive behavior for social contexts (`effectivePermissive = socialContext ? true : isPermissiveMode`), but agent-social container doesn't set `TELCLAUDE_NETWORK_MODE=permissive|open`. Docker firewall remains on restricted allowlist — autonomous browsing/posting fails in Docker.

**Fix**: Either make social container explicitly permissive at firewall layer, or remove permissive SOCIAL behavior/docs.

### 6. checkPrivateNetworkAccess() doesn't enforce "all resolved IPs must match" rule
**Files**: `docs/architecture.md:79`, `src/sandbox/network-proxy.ts:613-683`
**Severity**: MEDIUM

Architecture doc says DNS enforcement requires all resolved IPs to pass allowlist. Implementation only enforces on private IPs; public IPs ignored. A hostname resolving to one approved private IP + one public IP still passes — weaker than documented.

**Fix**: Fail closed on mixed public/private answers, or require every resolved address to match approved endpoint/CIDR.

### 7. Token "rotation grace" tracked in memory but not actually enforced
**Files**: `src/relay/token-manager.ts:35-37, 109-127, 147-200, 254-278`
**Severity**: MEDIUM

Token manager tracks `current` and `previous` with comments describing 5-minute grace window. But `verifyTokenLocally()` only verifies shape, signature, and expiry — never checks sessionId against stored current/previous. Actual rule is "valid until expiry," not "current plus short grace."

**Fix**: Enforce sessionId membership against `scopeTokens` during verification/refresh, or simplify code/comments to match real behavior.

### 8. Video processing reads entire video into RAM just to hash it
**Files**: `src/services/video-processor.ts:126-129`
**Severity**: MEDIUM

`fs.promises.readFile(videoPath)` loads whole file before any frame extraction. Large uploads can spike memory or OOM before configured duration cap helps.

**Fix**: Hash with `createReadStream` and add explicit max input size check before processing.

---

## LOW Findings

### 9. setup-github-app uses shell-interpolated execSync for git identity
**Files**: `src/commands/setup-github-app.ts:46-55`
**Severity**: LOW

Uses `execSync(\`git config --global user.name "${identity.username}"\`)` — unnecessary shell injection surface when repo already has safe `spawnSync` pattern in `src/services/git-credentials.ts`.

**Fix**: Replace with `spawnSync`/`execFileSync`.

### 10. Network add/remove rewrites JSON5 config as plain JSON, non-atomically
**Files**: `src/commands/network.ts:44-46`
**Severity**: LOW (DX issue)

Reads config with JSON5 but writes back with `JSON.stringify()` — strips comments/trailing commas. Direct `writeFileSync` can leave partially-written config if interrupted.

**Fix**: Write to temp file and rename atomically. Warn about JSON5 syntax loss.

---

## Recommended Fix Order

1. Request-scoped token handling (#1)
2. settingSources / hook-bypass regression (#2)
3. Firewall private-IP filtering (#3)
4. Docker support for privateEndpoints (#4)

These four are the ones most likely to bite in production.
