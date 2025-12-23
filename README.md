# telclaude

OS-sandboxed Telegram ⇄ Claude Code relay with LLM pre-screening, approvals, and tiered permissions.

[![CI](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml)
[![Gitleaks](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml)
[![CodeQL](https://github.com/avivsinai/telclaude/actions/workflows/codeql.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Alpha** — Security-first defaults; expect breaking changes until 1.0.

## Highlights
- Mandatory OS sandboxing (Seatbelt on macOS, bubblewrap + socat + ripgrep on Linux) with private /tmp and tier-aligned deny-write rules.
- Hard defaults: secret redaction (CORE patterns + entropy), rate limits, audit log, and fail-closed chat allowlist.
- Soft controls: Haiku observer, nonce-based approval workflow for FULL_ACCESS, and optional TOTP auth gate for periodic identity verification.
- Three permission tiers mapped to Claude Agent SDK allowedTools: READ_ONLY, WRITE_LOCAL, FULL_ACCESS.
- Runs locally on macOS/Linux or via the Docker Compose stack (Windows through WSL2).
- No telemetry or analytics; only audit logs you enable in your own environment.

## Documentation map
- Overview & onboarding: this `README.md`
- Configuration examples: `examples/` (minimal, personal, team)
- Agent playbook: `CLAUDE.md` (auto-loaded by Claude Code)
- Agents guide pointer: `AGENTS.md`
- Architecture/security deep dive: `docs/architecture.md`
- Container deploy: `docker/README.md`
- Policies: `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`

## Support & cadence
- Status: alpha — breaking changes possible until 1.0.
- Platforms: macOS 14+, Linux (bubblewrap+socat+rg); Docker/WSL recommended for prod.
- Issues/PR triage: weekly; security reports acknowledged within 48h.
- Releases: ad-hoc during alpha; aim for monthly.
- Security contact: project maintainer(s) via GitHub security advisory.

## Permission tiers (at a glance)
| Tier | What it can do | Safeguards |
| --- | --- | --- |
| READ_ONLY | Read files, search, web fetch/search | No writes; sandbox + secret filter |
| WRITE_LOCAL | READ_ONLY + write/edit/bash | Blocks destructive bash (rm/chown/kill, etc.); denyWrite patterns |
| FULL_ACCESS | All tools | Every request requires human approval; still sandboxed |

## Architecture

```
                            Telegram
                               |
                               v
+--------------------------------------------------------------+
|                       Security Layer                          |
|  +------------+   +------------+   +----------+   +--------+  |
|  | Fast Path  |-->|  Observer  |-->| Rate     |-->|Approval|  |
|  | (regex)    |   |  (Haiku)   |   | Limit    |   |(human) |  |
|  +------------+   +------------+   +----------+   +--------+  |
+--------------------------------------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                      Permission Tiers                         |
|    READ_ONLY          WRITE_LOCAL          FULL_ACCESS        |
|    (5 tools)          (8 tools)            (all, +approval)   |
+--------------------------------------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                   OS Sandbox (mandatory)                      |
|           macOS: Seatbelt  |  Linux: bubblewrap               |
+--------------------------------------------------------------+
                               |
                               v
                       Claude Agent SDK

+------------------+
|   TOTP Daemon    |<--- separate process, OS keychain
+------------------+
```

## Requirements
- Node 25+, pnpm 9.x
- Claude CLI (`brew install anthropic-ai/cli/claude`) — recommended. API key is **not** forwarded into the sandboxed relay; use `claude login` so tokens live in `~/.claude`.
- Telegram bot token from @BotFather
- macOS 14+ or Linux with `bubblewrap`, `socat`, and `ripgrep` available on PATH (Windows via Docker/WSL only)
- Optional but recommended: TOTP daemon uses the OS keychain (keytar)

## Third-party terms
- This project depends on `@anthropic-ai/claude-agent-sdk`, which is distributed under Anthropic’s Claude Code legal agreements (see its `LICENSE.md` in `node_modules/` after install).

## Quick start (Docker, recommended for prod)
```bash
git clone https://github.com/avivsinai/telclaude.git
cd telclaude/docker
cp .env.example .env   # set TELEGRAM_BOT_TOKEN and WORKSPACE_PATH
docker compose up -d --build
docker compose exec telclaude claude login  # required; API key is not forwarded into sandbox
```
See `docker/README.md` for firewall, volume, and upgrade details.

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
claude login             # API key is not forwarded into sandboxed relay
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
# Development (native, uses @anthropic-ai/sandbox-runtime; if it fails on your host, use Docker below)
pnpm dev relay --profile simple

# Recommended / Production: Docker or WSL with container boundary + srt
docker compose up -d --build
docker compose exec telclaude pnpm start relay --profile strict
```

7) First admin claim
- DM your bot from the allowed chat; it replies with `/approve <code>`.
- Send that command back to link the chat as admin (FULL_ACCESS with per-request approvals).
- In the same chat, run `/setup-2fa` to bind TOTP for periodic identity verification (daemon must be running). `/skip-totp` is allowed but not recommended.
- Optional hardening: set `TELCLAUDE_ADMIN_SECRET` and start with `/claim <secret>` to prevent scanner bots claiming admin first (see `SECURITY.md`).

## Configuration
- Default path: `~/.telclaude/telclaude.json` (override with `TELCLAUDE_CONFIG` or `--config`).
- Profiles:
  - `simple` (default): sandbox + secret filter + rate limits + audit.
  - `strict`: adds Haiku observer, approval workflow, and tiered tool gates.
  - `test`: disables all enforcement; requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`.
- Permission tiers:
  - `READ_ONLY`: read/search/web only; no writes.
  - `WRITE_LOCAL`: read/write/edit/bash with destructive commands blocked.
  - `FULL_ACCESS`: unrestricted tools but every request needs human approval.
  - Set per-user under `security.permissions.users`; `defaultTier` stays `READ_ONLY`.
- Optional group guardrail:
  - `telegram.groupChat.requireMention: true` to ignore group/supergroup messages unless they mention the bot or reply to it.
- OpenAI/GitHub key exposure (tier-based):
  - WRITE_LOCAL and FULL_ACCESS tiers automatically get configured API keys (OpenAI, GitHub) exposed to sandbox.
  - READ_ONLY tier never gets keys (no Bash access anyway).
  - Configure keys via `telclaude setup-openai` / `telclaude setup-git` or env vars.
  - **Security note:** keys are exposed to the model in WRITE_LOCAL+ tiers; use restricted keys if concerned.
- Rate limits and audit logging are on by default; see `CLAUDE.md` for full schema and options.

## CLI
- `telclaude relay [--profile simple|strict|test] [--dry-run]`
- `telclaude doctor [--network] [--secrets]`
- `telclaude status [--json]`
- `telclaude link <user-id> | --list | --remove <chat-id>`
- `telclaude send <chatId> [message] [--media <path>] [--caption <text>]`
- `telclaude totp-daemon [--socket-path <path>]`
- `telclaude totp-setup <user-id>`
- `telclaude totp-disable <user-id>`
- `telclaude reset-auth [--force]`
- `telclaude ban <chat-id> [-r <reason>]` — block a chat from using the bot
- `telclaude unban <chat-id>` — restore access for a banned chat
- `telclaude force-reauth <chat-id>` — invalidate TOTP session, requiring re-verification
- `telclaude list-bans` — show all banned chats
- `telclaude reset-db [--force]` — delete SQLite database (requires `TELCLAUDE_ENABLE_RESET_DB=1`)

## Usage example
Run strict profile with approvals and TOTP:
```bash
pnpm dev totp-daemon &
pnpm dev relay --profile strict
# In Telegram (allowed chat):
# 1) bot replies with /approve CODE for admin claim
# 2) run /setup-2fa to bind TOTP
```

Use `pnpm dev <command>` during development (tsx). For production: `pnpm build && pnpm start <command>` (runs from `dist/`).

## Deployment
- **Production (mandatory): Docker/WSL Compose stack** (`docker/README.md`). Container boundary + sandbox-runtime. Use this on shared or multi-tenant hosts.
- **Development:** Native macOS/Linux with SDK sandbox (Seatbelt/bubblewrap). SDK sandbox provides OS-level network isolation for ALL tools (Bash, WebFetch, WebSearch). Keep `~/.telclaude/telclaude.json` chmod 600.

## Development
- Lint/format: `pnpm lint`, `pnpm format`
- Types: `pnpm typecheck`
- Tests: `pnpm test` or `pnpm test:coverage`
- Build: `pnpm build`
- Local CLI: `pnpm dev relay`, `pnpm dev doctor`, etc.
- Secrets scan: `brew install gitleaks` (or download binary) then `pnpm security:scan` (uses `.gitleaks.toml`)

## Security & reporting
- Default stance is fail-closed (empty `allowedChats` denies all; `defaultTier=FULL_ACCESS` is rejected).
- Sandbox is mandatory; relay exits if Seatbelt/bubblewrap is unavailable.
- Vulnerabilities: please follow `SECURITY.md` for coordinated disclosure.
- Security contact: project maintainer(s) via GitHub security advisory.

## Troubleshooting (quick)
| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Bot silent/denied | `allowedChats` empty or rate limit hit | Add your chat ID and rerun; check audit/doctor |
| Sandbox unavailable | seatbelt/bubblewrap/rg/socat missing | Install deps (see `CLAUDE.md#sandbox-unavailable-relay-wont-start`) |
| TOTP fails | Daemon not running or clock drift | Start `pnpm dev totp-daemon`; sync device time |
| SDK/observer errors | Claude CLI missing or not logged in | `brew install anthropic-ai/cli/claude && claude login` |

## Community
- Contributing guidelines: see `CONTRIBUTING.md`.
- Code of Conduct: see `CODE_OF_CONDUCT.md`.
- Issues & discussions: open GitHub issues; we triage weekly.
- Changelog: see `CHANGELOG.md`.

## Documentation & Support
- `CLAUDE.md` — architecture and configuration details
- `docker/README.md` — container deployment
- `CONTRIBUTING.md` — how to get involved
- `SECURITY.md` — vulnerability reporting and threat model

## Acknowledgments

Inspired by [Clawdis](https://github.com/steipete/clawdis) by [@steipete](https://github.com/steipete).

## License

MIT
