# Telclaude Architecture Deep Dive

Updated: 2025-12-23
Scope: detailed design and security rationale for telclaude (Telegram ⇄ Claude Code relay).

## Dual-Mode Sandbox Architecture

Telclaude uses a simplified dual-mode architecture for isolation:

- **Docker mode**: SDK sandbox disabled. Docker container provides filesystem and network isolation.
- **Native mode**: SDK sandbox enabled. bubblewrap (Linux) or Seatbelt (macOS) provides isolation.

Mode is auto-detected at startup via `/.dockerenv` or `TELCLAUDE_DOCKER=1` env var.

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
│ Isolation (mode-dependent)                 │
│ • Docker: container isolation              │
│ • Native: SDK sandbox (bwrap/Seatbelt)     │
└────────────────────────────────────────────┘
      │
      ▼
Claude Agent SDK (allowedTools per tier)
      │
      ▼
TOTP daemon (separate process, keychain-backed)
```

## Security Profiles
- **simple (default)**: rate limits + audit + secret filter. No observer/approvals.
- **strict (opt-in)**: adds Haiku observer, approvals, and tier enforcement.
- **test**: disables all enforcement; gated by `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Five Security Pillars
1) **Filesystem isolation**: Docker container or SDK sandbox; sensitive paths blocked via canUseTool.
2) **Environment isolation**: minimal env vars passed to SDK.
3) **Network isolation**: PreToolUse hook blocks RFC1918/metadata for WebFetch; SDK sandbox allowedDomains for Bash in native mode.
4) **Secret output filtering**: CORE patterns + entropy detection; infrastructure secrets are non-overridable blockers.
5) **Auth/rate limits/audit**: identity links, TOTP auth gate, SQLite-backed.

## Permission Tiers

| Tier | Tools | Notes |
| --- | --- | --- |
| READ_ONLY | Read, Glob, Grep, WebFetch, WebSearch | No writes allowed |
| WRITE_LOCAL | READ_ONLY + Write, Edit, Bash | Blocks destructive patterns; prevents accidents |
| FULL_ACCESS | All tools | Approval required unless user is claimed admin |

## Network Enforcement

- **Bash**: SDK sandbox `allowedDomains` in native mode; Docker network in container mode.
- **WebFetch**: PreToolUse hook (blocks RFC1918/metadata) + canUseTool domain allowlist.
- **WebSearch**: NOT filtered (server-side by Anthropic).
- `TELCLAUDE_NETWORK_MODE=open|permissive`: enables broad egress for WebFetch only.

## Application-Level Security

The canUseTool callback and PreToolUse hooks provide defense-in-depth:
- Block reads/writes to sensitive paths (~/.telclaude, ~/.ssh, ~/.aws, etc.)
- Block WebFetch to private networks and metadata endpoints
- Block dangerous bash commands in WRITE_LOCAL tier
- Prevent disableAllHooks bypass via settings isolation

## Session & Conversation Model
- Uses stable `query()` API with resume support; 30‑minute cache.
- Per-chat session IDs; idle timeout configurable.
- Implemented in `src/sdk/session-manager.ts`.

## Control Plane & Auth
- **Identity linking**: `/link` codes generated via CLI; stored in SQLite.
- **First-time admin claim**: private chat only, short-lived approval code.
- **TOTP auth gate**: Periodic identity check when session expires (default: 4 hours).
- **Approvals**: Nonce-based confirmation for dangerous operations; TTL 5 minutes.
- **Emergency controls**: CLI-only `ban`/`unban`, `force-reauth`, `list-bans`.

## Observer & Fast Path
- Fast-path regex handles obvious safe/unsafe patterns.
- Observer uses security-gate skill via Claude Agent SDK.
- WARN/BLOCK may trigger approvals per tier rules.

## Persistence
- SQLite at `~/.telclaude/telclaude.db` stores approvals, rate limits, identity links, sessions, audit.
- Config at `~/.telclaude/telclaude.json`.

## Message Flow (strict profile)
1) Telegram message received.
2) Ban check.
3) Admin claim flow (if no admin configured).
4) TOTP auth gate.
5) Control-plane commands handled.
6) Infrastructure secret block.
7) Rate-limit check.
8) Observer: structural checks + fast path, then LLM if needed.
9) Approval gate (per tier/classification).
10) Session lookup/resume.
11) Tier lookup (identity links/admin claim).
12) SDK query with tiered allowedTools.
13) Streaming reply to Telegram; audit logged.

## Deployment

### Docker (Production)
- SDK sandbox disabled; container provides isolation.
- TOTP daemon uses encrypted file backend.
- Read-only root FS, dropped caps.

### Native (Development)
- SDK sandbox enabled (bubblewrap/Seatbelt).
- TOTP daemon uses OS keychain.
- macOS 14+ or Linux with bubblewrap, socat, ripgrep on PATH.

## File Map
- `src/security/*` — pipeline, permissions, observer, approvals, rate limits.
- `src/sandbox/*` — mode detection, constants, SDK settings builder.
- `src/sdk/*` — Claude SDK integration and session manager.
- `src/telegram/*` — inbound/outbound bot wiring.
- `src/commands/*` — CLI commands.
- `.claude/skills/*` — skills auto-loaded by SDK.
