# Telclaude Architecture Deep Dive

Updated: 2025-12-06  
Scope: detailed design and security rationale for telclaude (Telegram ⇄ Claude Code relay).

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
3) Network isolation (strict default allowlist of developer/Anthropic domains; metadata + RFC1918 always blocked; `TELCLAUDE_NETWORK_MODE=open|permissive` widens to wildcard).  
4) Secret output filtering (CORE patterns + entropy, streaming; infrastructure secrets are non-overridable blockers).  
5) Auth/rate limits/audit (identity links, TOTP optional, SQLite-backed).

## Design notes
- Sandbox is mandatory; relay exits if sandbox-runtime prerequisites are missing.  
- Enforcement vs policy: sandbox + secret filter + rate limits + auth are always enforced; tiers/observer/approvals are policy layers.  
- WRITE_SAFE is for accidental safety; sandbox still enforces filesystem/network limits.  
- Profiles:  
  - simple (default): sandbox + secret filter + rate limits + audit + tiers; observer/approvals off.  
  - strict: adds security observer (fast-path + LLM) and approval workflow.  
  - test: disables enforcement; requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Permission Tiers

| Tier | Tools | Extra safeguards | Notes |
| --- | --- | --- | --- |
| READ_ONLY | Read, Glob, Grep, WebFetch, WebSearch | No writes allowed | Sandbox blocks writes; SDK default write paths mitigated via denyWrite |
| WRITE_SAFE | READ_ONLY + Write, Edit, Bash | Blocks destructive/bash & dangerous patterns (rm/rmdir/mv/chmod/chown/kill, curl\|sh, netcat, git hooks, path redirects, etc.); denyWrite patterns for secrets | Prevents accidents, not malicious intent |
| FULL_ACCESS | All tools | Approval required unless user is claimed admin | Same sandbox as WRITE_SAFE; `bypassPermissions` gated by approval/identity |

## OS-Level Sandbox
- **macOS**: Seatbelt via `sandbox-exec`.  
- **Linux**: bubblewrap + socat proxy; glob patterns expanded once at startup (newly created matching files after init are not auto-blocked).  
- Tier-aligned write rules: READ_ONLY (no writes), WRITE_SAFE/FULL_ACCESS (cwd + `~/.telclaude/sandbox-tmp`).  
- Deny-read includes `~/.ssh`, `~/.aws`, `~/.telclaude`, shell histories, host `/tmp`/`/var/tmp`/`/run/user`, etc.; private temp at `~/.telclaude/sandbox-tmp`.  
- Network: default strict allowlist (npm/pypi/docs/github/Anthropic API); set `TELCLAUDE_NETWORK_MODE=open|permissive` to allow `*`. Metadata endpoints and RFC1918 ranges always blocked; local binding disabled except for sandbox proxy ports (Seatbelt limitation).  
- Sandbox wrapper (`srt`) attempts to sandbox ALL Claude tools; if wrapper init fails, relay degrades to Bash-only sandboxing and warns at startup.

## Session & Conversation Model
- Uses stable `query()` API with resume support; 30‑minute cache.  
- Per-chat session IDs; idle timeout configurable.  
- Implemented in `src/sdk/session-manager.ts`.

## Control Plane & Auth
- **Identity linking**: `/link` codes generated via CLI; stored in SQLite.  
- **First-time admin claim**: private chat only, short-lived approval code.  
- **TOTP daemon**: separate process, Unix socket IPC, secrets in OS keychain (native) or encrypted file backend in Docker.  
- **Approvals**: required for FULL_ACCESS (except claimed admin), all BLOCK classifications, WARN with WRITE_SAFE, and low-confidence WARN; TTL 5 minutes.

## Observer & Fast Path
- Fast-path regex handles obvious safe/unsafe patterns and structural issues (zero-width chars, mixed scripts, repetition).  
- Observer uses the security-gate skill via Claude Agent SDK (`query` with allowedTools: Skill); dangerThreshold downgrades BLOCK→WARN and WARN→ALLOW when confidence is low; circuit breaker + timeout fallback (`fallbackOnTimeout` default: block).  
- WARN/BLOCK may trigger approvals per tier rules above.

## Persistence
- SQLite at `~/.telclaude/telclaude.db` stores approvals, rate limits, identity links, sessions, and audit metadata.  
- Config path resolution in `src/config/path.ts`; schema in `src/config/config.ts`.

## Message Flow (strict profile)
1) Telegram message received.  
2) Control-plane commands handled (`/link`, `/approve`, `/deny`, `/whoami`).  
3) Infrastructure secret block (non-overridable).  
4) Rate-limit check.  
5) Observer: structural checks + fast path, then LLM if needed.  
6) Approval gate (per tier/classification).  
7) Session lookup/resume.  
8) Tier lookup (identity links/admin claim).  
9) SDK query with tiered allowedTools inside sandbox.  
10) Streaming reply to Telegram; audit logged.

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
- `src/sandbox/*` — OS sandbox config and wrapper.  
- `src/sdk/*` — Claude SDK wrapper and session manager.  
- `src/telegram/*` — inbound/outbound bot wiring.  
- `src/commands/*` — CLI commands.  
- `.claude/skills/*` — skills auto-loaded by SDK.
