# OpenClaw Security Backport Plan

**Date**: 2026-02-17
**Status**: v2 (incorporates Codex review)
**Scope**: Security-focused features from OpenClaw worth backporting to telclaude
**Prior art**: PR #34 (`1306a85`) already backported external-content wrapping, homoglyphs, skill scanner, bash chain analysis, skill write protection

## Context

Two independent agents (Claude + Codex) evaluated OpenClaw's codebase for backport candidates. This plan covers the security-focused items both agents agreed on, with effort estimates adjusted after reading telclaude's existing code.

### Key Finding: SSRF Gap Is Narrower Than Estimated

Both agents initially ranked "SSRF DNS pinning" as the #1 security gap. After reading telclaude's `src/sandbox/network-proxy.ts` and `src/sandbox/config.ts`, the gap is narrower:

**Telclaude already has:**
- DNS resolution with `{all: true}` via `cachedDNSLookup()` — validates ALL resolved IPs
- DNS cache (60s TTL) to prevent rebinding attacks
- IP canonicalization via ip-num to block hex/octal obfuscation
- Non-overridable metadata blocks (169.254.x.x can never be allowlisted)
- Private endpoint allowlist with CIDR + port enforcement
- IPv4-mapped IPv6 detection (`::ffff:192.168.1.1`)
- Self-test suite and doctor integration

**What OpenClaw adds that we lack:**
1. **DNS-pinned fetch dispatcher** — undici `Agent` with pinned `lookup`, ensuring the actual TCP connection uses the validated IPs (not a re-resolved set)
2. **Redirect hop re-validation** — `fetchWithSsrFGuard()` sets `redirect: "manual"`, re-resolves and re-validates DNS at each hop
3. **Integrated guarded fetch** — single `fetchWithSsrFGuard()` primitive that all outbound HTTP should use

---

## Task 1: DNS-Pinned Fetch Guard

**Priority**: High
**Effort**: Small-Medium (mostly integration, core primitives exist)
**OpenClaw source**: `src/infra/net/ssrf.ts` (pinned dispatcher), `src/infra/net/fetch-guard.ts` (redirect guard)

### What

Create a `fetchWithGuard()` function that:
1. Resolves hostname via existing `cachedDNSLookup()`
2. Validates all resolved IPs via existing `isBlockedIP()` / `isNonOverridableBlock()`
3. Creates an undici `Agent` with a pinned DNS `lookup` callback (so the TCP connection uses exactly the validated IPs)
4. Follows redirects manually (`redirect: "manual"`), re-validating each hop's hostname
5. Caps redirect count (default 3), detects loops
6. Returns response + cleanup function for the dispatcher

### Where in telclaude

- New: `src/sandbox/fetch-guard.ts` — the guarded fetch primitive
- Modify: `src/sandbox/network-proxy.ts` — export `createPinnedLookup()` helper (OpenClaw's pattern)
- Modify: `src/sandbox/index.ts` — re-export fetch guard

### Consumers (adopt incrementally, highest risk first)

1. `src/services/summarize.ts` — fetches arbitrary user-provided URLs (highest SSRF risk)
2. `src/commands/summarize.ts` — CLI path calls `summarizeUrl` directly
3. `src/relay/http-credential-proxy.ts` — proxies authenticated requests to upstream hosts
4. `src/relay/provider-proxy.ts` — already has `validateProviderBaseUrl()` with private-IP checks, so lower incremental value
5. `src/relay/anthropic-proxy.ts` — fixed host (`api.anthropic.com`), lowest priority

### Acceptance criteria

- [ ] `fetchWithGuard()` resolves all IPs, blocks private/metadata, pins DNS to connection
- [ ] Redirect hops are individually validated (hostname resolves to new IPs, all checked)
- [ ] Redirect loop detection and max-redirect cap
- [ ] Timeout support via AbortSignal
- [ ] Tests: private IP redirect bypass, DNS rebinding simulation, loop detection, normal happy path
- [ ] Existing `cachedDNSLookup` + `isBlockedIP` reused (no duplication)

---

## Task 2: Sandbox Posture Audit (Static)

**Priority**: High
**Effort**: Small
**OpenClaw source**: `src/agents/sandbox/validate-sandbox-security.ts`

### What

> **Codex review note**: Telclaude has no runtime Docker container-creation path to hook. `src/sandbox/mode.ts` only detects docker/native mode. Re-scoped from "runtime validator" to static `doctor --security` checks against compose/env/sandbox posture.

Static audit checks for `doctor --security` that flag:
- `docker-compose.yml`: host network mode, privileged flag, unconfined seccomp/AppArmor
- Bind mount analysis: resolve symlinks in compose volume mounts, check for escape to host root, Docker socket mount
- Environment posture: sensitive env vars exposed to agent containers, permissive network mode without justification

### Where in telclaude

- New: `src/sandbox/validate-config.ts` — static validation functions (reads compose file + env)
- Modify: `src/commands/doctor.ts` — integrate as a `--security` check
- Input: `docker/docker-compose.yml` and `docker/.env` (parsed, not executed)

### Acceptance criteria

- [ ] Parses docker-compose.yml and flags dangerous settings (host network, privileged, seccomp)
- [ ] Resolves symlinks in bind mount paths, detects escape to host root or sensitive dirs
- [ ] Flags Docker socket bind mount (`/var/run/docker.sock`)
- [ ] Returns structured findings (severity + description) for doctor output
- [ ] Tests: known-bad compose configs produce findings, clean config passes

---

## Task 3: Inbound Message Sanitization

**Priority**: Medium
**Effort**: Small
**Dependencies**: Homoglyph library already backported in PR #34

### What

Apply `foldHomoglyphs()` and zero-width character stripping to inbound Telegram messages before they reach the security pipeline. Currently we have the library but don't use it on input.

> **Codex review note**: `src/telegram/auto-reply.ts` uses `msg.body` for command parsing (`/approve`, `/link`, `/otp`). Global mutation would break command semantics. Use dual-field: raw body for command parsing + audit, normalized body for observer/classification/prompting.

### Where in telclaude

- Modify: `src/telegram/inbound.ts` — add `normalizedBody` field early in pipeline
- Modify: observer/classification code — use `normalizedBody` instead of raw `body`
- Do NOT modify: `src/telegram/auto-reply.ts` command parsing (keeps raw `body`)
- Reuse: `src/security/homoglyphs.ts` — already has `foldHomoglyphs()`, `containsHomoglyphs()`

### Acceptance criteria

- [ ] Inbound messages carry both `body` (raw) and `normalizedBody` (sanitized)
- [ ] Observer/classification uses `normalizedBody`; command parsing uses raw `body`
- [ ] Zero-width chars stripped (U+200B, U+200C, U+200D, U+FEFF, etc.)
- [ ] Fullwidth ASCII folded to ASCII equivalents
- [ ] Original message preserved in audit log
- [ ] Detection logged (not blocked — just normalized)
- [ ] Tests: message with homoglyphs is folded, command messages still parse correctly

---

## Task 4: Deep Security Audit Collectors

**Priority**: Medium
**Effort**: Medium
**OpenClaw source**: `src/security/audit.ts`, `src/security/audit-extra.*.ts`

### What

Structured, severity-based audit collectors for `doctor --security`:
- Config audit: dangerous sandbox settings, exposed ports, permissive network mode
- Filesystem audit: permission checks on config/auth/session files
- Plugin/skill trust: skill signature verification, untrusted skill detection
- Hook hardening: check for disableAllHooks bypass vectors
- Exposure matrix: which tiers have access to which capabilities

### Where in telclaude

- New: `src/commands/audit-collectors.ts` — structured collectors returning `{severity, category, message, fix?}`
- Modify: `src/commands/doctor.ts` — integrate collectors into `--security` output

### Acceptance criteria

- [ ] Collectors return structured findings with severity levels (critical/warning/info)
- [ ] Config, filesystem, skill trust, hook hardening checks implemented
- [ ] Doctor output groups by severity, actionable descriptions
- [ ] Tests: known-vulnerable config produces critical findings, clean config passes

---

## Task 5: Security Auto-Remediation

**Priority**: Low (depends on Task 4)
**Effort**: Medium
**OpenClaw source**: `src/security/fix.ts`

### What

`doctor --security --fix` that automatically applies safe remediations:
- Tighten file permissions on config/auth files
- Set conservative config defaults for flagged settings
- Report what was changed

### Where in telclaude

- Modify: `src/commands/doctor.ts` — add `--fix` flag
- New: `src/commands/audit-fixers.ts` — remediation functions per finding type

### Acceptance criteria

- [ ] No-op by default — only applies fixes when `--fix` is explicitly passed
- [ ] Only applies "safe" fixes (permission tightening, conservative defaults)
- [ ] Reports each fix applied with before/after state
- [ ] Config writes use atomic write + backup (write to `.tmp`, rename, keep `.bak`)
- [ ] Tests: verify fixes are applied correctly, verify no data loss, verify backup created

---

## Task 6: Stream Output Size Guard

**Priority**: Medium
**Effort**: Medium (scoped down from Large)
**OpenClaw source**: `src/agents/session-tool-result-guard.ts`, `src/agents/pi-embedded-runner/tool-result-truncation.ts`

> **Codex review note**: Telclaude's `session-manager.ts` doesn't own transcript storage — SDK handles persistence. Transcript repair (patching stored transcripts) is not viable from our wrapper layer. Re-scoped to what's SDK-feasible: output/tool-result size guards in stream handling, and context overflow recovery.

### What

Guards in the stream handling layer:
- Cap oversized tool-result content in streaming responses before they exhaust context
- Detect context overflow errors and trigger graceful recovery (session reset with summary)
- Log truncation events for debugging

### Where in telclaude

- New: `src/sdk/output-guard.ts` — tool-result size cap + truncation logic
- Modify: `src/sdk/client.ts` — integrate guard in stream processing hooks
- Modify: `src/sdk/session-manager.ts` — overflow detection → recovery path

### Acceptance criteria

- [ ] Oversized tool results truncated with configurable size cap
- [ ] Context overflow detected and triggers graceful recovery (not crash)
- [ ] Truncation events logged with original size for debugging
- [ ] Tests: size cap enforcement, overflow recovery path

---

## Implementation Order

Updated per Codex review — summarize path first for Task 1, dual-field for Task 3:

```
Task 1 (fetch guard — summarize path first) ─┐── Sprint 1 (security hardening)
Task 3 (inbound sanitize — dual-field)  ─────┘

Task 2 (sandbox posture audit — static)  ────┐── Sprint 2 (observability)
Task 4 (deep audit collectors)  ─────────────┤
Task 5 (auto-fix, depends on Task 4)  ───────┘

Task 6 (stream output size guard)  ──────────── Sprint 3 (robustness)
```

## Non-Security Features

A separate evaluation is tracking non-security features (Telegram UX, auth rotation, cron, inline buttons, etc.) in a parallel analysis.
