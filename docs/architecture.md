# Telclaude Architecture Deep Dive

Updated: 2025-12-06  
Scope: detailed design and security rationale for telclaude (Telegram ⇄ Claude Code relay).

## Runtime guardrail notes (dec 2025)
- **Network enforcement model**:
  - **Bash**: SDK sandbox `allowedDomains` (OS-level, strict allowlist always)
  - **WebFetch**: PreToolUse hook (PRIMARY) + `canUseTool` callback (fallback).
  - **WebSearch**: NOT filtered. Uses `query` parameter (not `url`); requests made server-side by Anthropic's search service, not by the local process.
- `TELCLAUDE_NETWORK_MODE=open|permissive` enables broad egress for **WebFetch only**. Private/metadata still blocked via PreToolUse hook.
- SDK permission rules for network are NOT used (SDK matcher doesn't support needed wildcards). WebFetch filtering is in PreToolUse hook + `canUseTool` fallback.
- **Settings isolation (disableAllHooks defense)**:
  - `settingSources: ["project"]` always set - user settings (~/.claude/settings.json) are never loaded.
  - Writes to `.claude/settings.json` and `.claude/settings.local.json` are blocked via sensitive paths.
  - This two-layer defense prevents both: (1) user settings with `disableAllHooks: true`, (2) prompt injection writing `disableAllHooks` to project settings.
  - NOTE: This means user-level model overrides, plugins, etc. won't load in telclaude. This is intentional.
- Read model is deny-list based: files outside the sensitive path list are readable if the user/agent asks. Seatbelt/bubblewrap plus the sensitive denyRead set provide defense-in-depth, but absolute allow-list reads are not supported by the runtime. For stricter isolation, run inside Docker/WSL with a minimal bind-mounted workspace.

## System Overview

```
Telegram Bot API
      │
      ▼
┌────────────────────────────────────────────┐
│ Security Layer                             │
│ • Fast-path regex (part of observer)       │
│ • Security observer (security-gate skill)  │
│ • Permission tiers & approvals             │
│ • Rate limits & audit                      │
│ • Identity linking                         │
└────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────┐
│ OS Sandbox (mandatory)                     │
│ • Seatbelt (macOS) / bubblewrap (Linux)    │
│ • Tier-aligned write rules + private /tmp  │
│ • Network filtering                        │
└────────────────────────────────────────────┘
      │
      ▼
Claude Agent SDK (allowedTools per tier)
      │
      ▼
TOTP daemon (separate process, keychain-backed)
```

## Security Profiles
- **simple (default)**: sandbox + secret filter + rate limits + audit. No observer/approvals.
- **strict (opt-in)**: adds Haiku observer, approvals, and tier enforcement.
- **test**: disables all enforcement; gated by `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Five Security Pillars
1) Filesystem isolation (deny sensitive paths; private `/tmp`; host `/tmp`/`/var/tmp`/`/run/user` denied).
2) Environment isolation (allowlist env vars).
3) Network isolation (strict default allowlist for Bash; metadata + RFC1918 always blocked for WebFetch; `TELCLAUDE_NETWORK_MODE=open|permissive` enables broad egress for WebFetch only; WebSearch is NOT filtered - server-side by Anthropic).
4) Secret output filtering (CORE patterns + entropy, streaming; infrastructure secrets are non-overridable blockers).
5) Auth/rate limits/audit (identity links, TOTP auth gate for periodic identity verification, SQLite-backed).

## Design notes
- Sandbox is mandatory; relay exits if sandbox-runtime prerequisites are missing.  
- Enforcement vs policy: sandbox + secret filter + rate limits + auth are always enforced; tiers/observer/approvals are policy layers.  
- WRITE_LOCAL is for accidental safety; sandbox still enforces filesystem/network limits.  
- Profiles:  
  - simple (default): sandbox + secret filter + rate limits + audit + tiers; observer/approvals off.  
  - strict: adds security observer (fast-path + LLM) and approval workflow.  
  - test: disables enforcement; requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Permission Tiers

| Tier | Tools | Extra safeguards | Notes |
| --- | --- | --- | --- |
| READ_ONLY | Read, Glob, Grep, WebFetch, WebSearch | No writes allowed | Sandbox blocks writes; SDK default write paths mitigated via denyWrite |
| WRITE_LOCAL | READ_ONLY + Write, Edit, Bash | Blocks destructive/bash & dangerous patterns (rm/rmdir/mv/chmod/chown/kill, curl\|sh, netcat, git hooks, path redirects, etc.); denyWrite patterns for secrets | Prevents accidents, not malicious intent |
| FULL_ACCESS | All tools | Approval required unless user is claimed admin | Same sandbox as WRITE_LOCAL; `bypassPermissions` gated by approval/identity |

## OS-Level Sandbox
- **macOS**: Seatbelt via `sandbox-exec`.
- **Linux**: bubblewrap + socat proxy; glob patterns expanded once at startup (newly created matching files after init are not auto-blocked).
- Tier-aligned write rules: READ_ONLY (no writes), WRITE_LOCAL/FULL_ACCESS (cwd + `~/.telclaude/sandbox-tmp`).
- Deny-read includes `~/.ssh`, `~/.aws`, `~/.telclaude`, shell histories, host `/tmp`/`/var/tmp`/`/run/user`, etc.; private temp at `~/.telclaude/sandbox-tmp`.
- **Network for Bash**: SDK sandbox `allowedDomains` (OS-level, strict allowlist always). Bash cannot reach arbitrary domains even in permissive mode.
- **Network for WebFetch**: PreToolUse hook (PRIMARY) + `canUseTool` fallback. In permissive mode, allows all public domains while blocking private/metadata.
- **Network for WebSearch**: NOT filtered. Uses `query` parameter (not `url`); requests made server-side by Anthropic's search service.
- SDK sandbox is the primary enforcement layer for Bash. WebFetch uses PreToolUse hook + `canUseTool` for network filtering.
- **Settings files**: `.claude/settings.json` and `.claude/settings.local.json` are blocked as sensitive paths (prevents prompt injection from writing `disableAllHooks`).

## Session & Conversation Model
- Uses stable `query()` API with resume support; 30‑minute cache.  
- Per-chat session IDs; idle timeout configurable.  
- Implemented in `src/sdk/session-manager.ts`.

## Control Plane & Auth
- **Identity linking**: `/link` codes generated via CLI; stored in SQLite.
- **First-time admin claim**: private chat only, short-lived approval code.
- **TOTP auth gate (identity verification)**: Periodic identity check when session expires (default: 4 hours). Runs BEFORE any message processing. Separate daemon process, Unix socket IPC, secrets in OS keychain (native) or encrypted file backend in Docker.
- **Approvals (intent confirmation)**: Nonce-based confirmation for dangerous operations. Required for FULL_ACCESS (except claimed admin), all BLOCK classifications, WARN with WRITE_LOCAL, and low-confidence WARN; TTL 5 minutes.
- **Emergency controls**: CLI-only `ban`/`unban` (prevents attacker with Telegram+TOTP from unbanning themselves), `force-reauth`, `list-bans`. Telegram `/force-reauth [chat-id]` available for admins.

## Observer & Fast Path
- Fast-path regex handles obvious safe/unsafe patterns and structural issues (zero-width chars, mixed scripts, repetition).  
- Observer uses the security-gate skill via Claude Agent SDK (`query` with allowedTools: Skill); dangerThreshold downgrades BLOCK→WARN and WARN→ALLOW when confidence is low; circuit breaker + timeout fallback (`fallbackOnTimeout` default: block).  
- WARN/BLOCK may trigger approvals per tier rules above.

## Persistence
- SQLite at `~/.telclaude/telclaude.db` stores approvals, rate limits, identity links, sessions, and audit metadata.  
- Config path resolution in `src/config/path.ts`; schema in `src/config/config.ts`.

## Message Flow (strict profile)
1) Telegram message received.
2) Ban check — blocked users silently rejected.
3) Admin claim flow (if no admin configured yet).
4) TOTP auth gate — if session expired, challenge and save message; on valid code, create session and replay.
5) Control-plane commands handled (`/link`, `/approve`, `/deny`, `/whoami`, `/force-reauth`, etc.).
6) Infrastructure secret block (non-overridable).
7) Rate-limit check.
8) Observer: structural checks + fast path, then LLM if needed.
9) Approval gate (nonce-based, per tier/classification).
10) Session lookup/resume.
11) Tier lookup (identity links/admin claim).
12) SDK query with tiered allowedTools inside sandbox.
13) Streaming reply to Telegram; audit logged.

## Deployment Notes
- **Production**: Docker/WSL Compose adds container boundary, read-only root FS, dropped caps, optional outbound firewall; TOTP sidecar uses encrypted file backend.  
- **Native**: macOS 14+ or Linux with bubblewrap, socat, ripgrep on PATH; sandbox mandatory (relay refuses to start otherwise).  
- Keep `~/.telclaude/telclaude.json` chmod 600; `defaultTier=FULL_ACCESS` rejected at startup.

## Troubleshooting Pointers
- Bot silent: ensure `allowedChats` set and rate limits not exceeded.  
- Sandbox unavailable: install seatbelt/bubblewrap deps; see `pnpm dev doctor --network --secrets`.  
- TOTP issues: daemon running; device time synced.  
- SDK/observer errors: Claude CLI installed and `claude login` done.

## File Map (high-touch)
- `src/security/*` — pipeline, permissions, observer, approvals, rate limits.  
- `src/sandbox/*` — OS sandbox config.  
- `src/sdk/*` — Claude SDK integration and session manager.  
- `src/telegram/*` — inbound/outbound bot wiring.  
- `src/commands/*` — CLI commands.  
- `.claude/skills/*` — skills auto-loaded by SDK.
