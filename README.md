# telclaude

OS-sandboxed Telegram ⇄ Claude Code relay with LLM pre-screening, approvals, and tiered permissions.

[![CI](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml)
[![Gitleaks](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Status: alpha (0.1.x). Security-first defaults; expect breaking changes before 1.0.

## Highlights
- Mandatory OS sandboxing (Seatbelt on macOS, bubblewrap + socat + ripgrep on Linux) with private /tmp and tier-aligned deny-write rules.
- Hard defaults: secret redaction (CORE patterns + entropy), rate limits, audit log, and fail-closed chat allowlist.
- Soft controls: Haiku observer, approval workflow, and TOTP-backed human-in-the-loop for FULL_ACCESS.
- Three permission tiers mapped to Claude Agent SDK allowedTools: READ_ONLY, WRITE_SAFE, FULL_ACCESS.
- Runs locally on macOS/Linux or via the Docker Compose stack (Windows through WSL2).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Telegram                                    │
│                                 │                                        │
│                                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                        Security Layer                             │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │   │
│  │  │ Fast Path  │─▶│  Observer  │─▶│ Rate Limit │─▶│  Approval  │  │   │
│  │  │  (regex)   │  │  (Haiku)   │  │  (SQLite)  │  │  (human)   │  │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Permission Tiers                             │   │
│  │  READ_ONLY          WRITE_SAFE           FULL_ACCESS              │   │
│  │  (5 tools)          (8 tools)            (all, +approval)         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    OS Sandbox (mandatory)                         │   │
│  │            macOS: Seatbelt  │  Linux: bubblewrap                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│                        Claude Agent SDK                                  │
│                                                                          │
│  ┌────────────────────┐                                                  │
│  │    TOTP Daemon     │◄─── separate process, OS keychain               │
│  └────────────────────┘                                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Requirements
- Node 22+, pnpm 9.x
- Claude CLI (`brew install anthropic-ai/cli/claude`) **or** `ANTHROPIC_API_KEY`
- Telegram bot token from @BotFather
- macOS 14+ or Linux with `bubblewrap`, `socat`, and `ripgrep` available on PATH (Windows via Docker/WSL only)
- Optional but recommended: TOTP daemon uses the OS keychain (keytar)

## Quick start (local)
1) Clone and install
```bash
git clone https://github.com/avivsinai/telclaude.git
cd telclaude
pnpm install
```
2) Create config (JSON5) at `~/.telclaude/telclaude.json` — allowlist is required or the bot will ignore all chats (fail-closed).
```json
{
  "telegram": {
    "botToken": "123456:ABC-DEF",
    "allowedChats": [123456789]      // your Telegram numeric chat ID
  },
  "security": {
    "profile": "strict",             // simple | strict | test
    "permissions": {
      "users": {
        "tg:123456789": { "tier": "FULL_ACCESS" }
      }
    }
  }
}
```
Notes: `defaultTier=FULL_ACCESS` is intentionally rejected at runtime. Prefer putting `botToken` in the config for native installs; `TELEGRAM_BOT_TOKEN` is accepted (mainly for Docker).

3) Authenticate Claude
```bash
claude login             # or export ANTHROPIC_API_KEY=sk-ant-...
```

4) (Recommended) Start TOTP daemon in another terminal
```bash
pnpm dev totp-daemon
```

5) Health check
```bash
pnpm dev doctor --network --secrets
```

6) Run the relay
```bash
pnpm dev relay --profile strict   # omit flag to use simple profile
```

7) First admin claim
- DM your bot from the allowed chat; it replies with `/approve <code>`.
- Send that command back to link the chat as admin (FULL_ACCESS with per-request approvals).
- In the same chat, run `/setup-2fa` to bind TOTP (daemon must be running). `/skip-totp` is allowed but not recommended.

## Configuration
- Default path: `~/.telclaude/telclaude.json` (override with `TELCLAUDE_CONFIG` or `--config`).
- Profiles:
  - `simple` (default): sandbox + secret filter + rate limits + audit.
  - `strict`: adds Haiku observer, approval workflow, and tiered tool gates.
  - `test`: disables all enforcement; requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`.
- Permission tiers:
  - `READ_ONLY`: read/search/web only; no writes.
  - `WRITE_SAFE`: read/write/edit/bash with destructive commands blocked.
  - `FULL_ACCESS`: unrestricted tools but every request needs human approval.
  - Set per-user under `security.permissions.users`; `defaultTier` stays `READ_ONLY`.
- Rate limits and audit logging are on by default; see `CLAUDE.md` for full schema and options.

## CLI
- `telclaude relay [--profile simple|strict|test] [--dry-run]`
- `telclaude doctor [--network] [--secrets]`
- `telclaude status [--json]`
- `telclaude link <user-id> | --list | --remove <chat-id>`
- `telclaude send <chatId> [message] [--media <path>] [--caption <text>]`
- `telclaude totp-daemon [--socket-path <path>]`
- `telclaude totp-setup <user-id>`
- `telclaude reset-auth [--force]`

Use `pnpm dev <command>` during development (tsx). For production: `pnpm build && pnpm start <command>` (runs from `dist/`).

## Deployment
- Preferred for production: Docker/WSL Compose stack (see `docker/README.md`) — gives a strong container boundary, read-only root FS, dropped caps, optional outbound firewall. Use this on shared or multi-tenant hosts.
- Native macOS/Linux: good for development and trusted single-user hosts; relies on Seatbelt/bubblewrap for the security boundary. Ensure deps are installed and `~/.telclaude/telclaude.json` stays chmod 600, then `pnpm build && pnpm start relay --profile strict`.

## Development
- Lint/format: `pnpm lint`, `pnpm format`
- Types: `pnpm typecheck`
- Tests: `pnpm test` or `pnpm test:coverage`
- Build: `pnpm build`
- Local CLI: `pnpm dev relay`, `pnpm dev doctor`, etc.
- Secrets scan: `brew install gitleaks` (or download binary) then `pnpm security:scan` (uses `.gitleaks.toml`)

## Documentation & Support
- `CLAUDE.md` — architecture and configuration details
- `docker/README.md` — container deployment
- `CONTRIBUTING.md` — how to get involved
- `SECURITY.md` — vulnerability reporting and threat model

## License

MIT
