# telclaude

Isolation-first Telegram ⇄ Claude Code relay with LLM pre-screening, approvals, and tiered permissions.

[![CI](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml)
[![Gitleaks](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml)
[![CodeQL](https://github.com/avivsinai/telclaude/actions/workflows/codeql.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Alpha** — Security-first defaults; expect breaking changes until 1.0.

## Highlights
- Mandatory isolation boundary: SDK sandbox (Seatbelt/bubblewrap) in native mode, relay+agent containers + firewall in Docker mode.
- Credential vault: sidecar daemon stores API keys and injects them into requests — agents never see raw credentials.
- Hard defaults: secret redaction (CORE patterns + entropy), rate limits, audit log, and fail-closed chat allowlist.
- Soft controls: Haiku observer, nonce-based approval workflow for FULL_ACCESS, and optional TOTP auth gate for periodic identity verification.
- Three permission tiers mapped to Claude Agent SDK allowedTools: READ_ONLY, WRITE_LOCAL, FULL_ACCESS.
- Generic social services integration (X/Twitter, Moltbook, Bluesky, etc.) via config-driven `SOCIAL` agent context with unified social persona.
- Private network allowlist for homelab services (Home Assistant, NAS, etc.) with port enforcement.
- Runs locally on macOS/Linux or via the Docker Compose stack (Windows through WSL2).
- No telemetry or analytics; only audit logs you enable in your own environment.

## Documentation map
| Document | Purpose |
|----------|---------|
| This `README.md` | Overview, quick start, configuration |
| `examples/` | Configuration examples (minimal, personal, team) |
| `CLAUDE.md` | Agent playbook (auto-loaded by Claude Code) |
| `AGENTS.md` | Agents guide pointer |
| `docs/architecture.md` | Architecture deep dive, security model, vault details |
| `docker/README.md` | Container deployment, firewall, volumes |
| `CHANGELOG.md` | Version history |
| `SECURITY.md` | Vulnerability reporting, threat model |
| `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md` | Community policies |

## Support & cadence
- Status: alpha — breaking changes possible until 1.0.
- Platforms: native mode on macOS 14+ or Linux (bubblewrap+socat+rg); Docker/WSL recommended for prod.
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
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                        Security Layer                            │
│  ┌────────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐  │
│  │ Fast Path  │──▶│  Observer  │──▶│   Rate   │──▶│ Approval │  │
│  │  (regex)   │   │  (Haiku)   │   │  Limit   │   │ (human)  │  │
│  └────────────┘   └────────────┘   └──────────┘   └──────────┘  │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Permission Tiers                           │
│     READ_ONLY           WRITE_LOCAL           FULL_ACCESS        │
│     (5 tools)           (8 tools)            (all, +approval)    │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│            Isolation Boundary (mode-dependent)                   │
│   Docker: relay+agent + firewall  │  Native: SDK sandbox         │
│          (SDK sandbox off)        │  (Seatbelt/bwrap)            │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
                        Claude Agent SDK

┌──────────────────┐     ┌──────────────────┐
│   TOTP Daemon    │     │  Vault Daemon    │
│  (OS keychain)   │     │ (credential      │
└──────────────────┘     │  injection)      │
                         └──────────────────┘
```

## Requirements
- Node 20+, pnpm 9.x
- Claude CLI (`brew install anthropic-ai/cli/claude`) — recommended. In Docker, telclaude routes Anthropic access through the relay proxy; if you use OAuth, run `claude login` in the relay container with `CLAUDE_CONFIG_DIR=/home/telclaude-auth` so tokens live in the dedicated auth profile.
- Telegram bot token from @BotFather
- Native mode: macOS 14+ or Linux with `bubblewrap`, `socat`, and `ripgrep` available on PATH
- Docker/WSL: Docker + Compose (no host bubblewrap required)
- Optional but recommended: TOTP daemon uses the OS keychain (keytar)

## Third-party terms
- This project depends on `@anthropic-ai/claude-agent-sdk`, which is distributed under Anthropic's Claude Code legal agreements (see its `LICENSE.md` in `node_modules/` after install).

## Quick start (Docker, recommended for prod)
```bash
git clone https://github.com/avivsinai/telclaude.git
cd telclaude/docker
cp .env.example .env   # set TELEGRAM_BOT_TOKEN, WORKSPACE_PATH, TOTP_ENCRYPTION_KEY, run `telclaude keygen telegram` and `telclaude keygen social` for RPC keys, ANTHROPIC_PROXY_TOKEN
docker compose up -d --build
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login  # optional if not using ANTHROPIC_API_KEY
```
See `docker/README.md` for firewall, volume, and upgrade details.
This starts `telclaude` (relay), `telclaude-agent` (SDK + tools), `agent-social` (social persona), and sidecar containers.

Note: Docker uses a shared **skills** profile (`/home/telclaude-skills`) and a relay-only **auth** profile (`/home/telclaude-auth`). Agents access Anthropic through the relay proxy; credentials never mount in agent containers.

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
claude login             # API key is not forwarded into sandboxed agent
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
# Development (native: SDK sandbox via @anthropic-ai/sandbox-runtime; if unavailable, use Docker below)
pnpm dev relay --profile simple

# Recommended / Production: Docker or WSL with container boundary + firewall
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
  - FULL_ACCESS tier automatically gets configured API keys (OpenAI, GitHub) exposed to sandbox.
  - READ_ONLY and WRITE_LOCAL tiers never get keys.
  - Configure keys via `telclaude setup-openai` / `telclaude setup-git` or env vars.
  - **Security note:** keys are exposed to the model in FULL_ACCESS; use restricted keys if concerned.
- Rate limits and audit logging are on by default; see `CLAUDE.md` for full schema and options.

## Credential vault

The vault daemon stores API credentials and injects them into HTTP requests transparently — agents never see raw credentials. This feature is primarily designed for Docker deployments with a remote agent.

**How it works (Docker/remote agent mode):**
1. Vault daemon runs as a sidecar (Unix socket, no network except OAuth refresh)
2. HTTP proxy on relay (port 8792) intercepts requests like `http://relay:8792/api.openai.com/v1/...`
3. Proxy looks up credentials by host, injects auth headers, forwards to upstream
4. Agent receives response without ever seeing the API key

**Note:** The HTTP credential proxy is only started when a remote agent is configured (`TELCLAUDE_AGENT_URL`). Native mode uses direct key exposure for FULL_ACCESS tier instead (see Configuration section).

**Supported auth types:** `bearer`, `api-key`, `basic`, `query`, `oauth2` (with automatic token refresh)

**Security properties:**
- Credentials encrypted at rest (AES-256-GCM)
- Host allowlist prevents injection to unexpected destinations
- Optional path restrictions per host
- Socket permissions 0600

**Quick setup:**
```bash
# Generate encryption key
export VAULT_ENCRYPTION_KEY=$(openssl rand -base64 32)

# Start vault daemon
telclaude vault-daemon

# Add a credential
telclaude vault add http api.openai.com --type bearer --label "OpenAI"
# (prompts for token securely)

# List credentials
telclaude vault list
```

See `docs/architecture.md` for full vault architecture and CLI reference.

## Private network allowlist

For local services (Home Assistant, NAS, Plex, etc.), configure explicit private endpoints:

```json
{
  "security": {
    "network": {
      "privateEndpoints": [
        { "label": "home-assistant", "host": "192.168.1.100", "ports": [8123] },
        { "label": "homelab", "cidr": "192.168.1.0/24", "ports": [80, 443] }
      ]
    }
  }
}
```

**CLI:**
```bash
telclaude network list
telclaude network add ha --host 192.168.1.100 --ports 8123
telclaude network test http://192.168.1.100:8123/api
```

Metadata endpoints (169.254.169.254) and link-local addresses remain blocked regardless of allowlist.

## External providers (sidecars)
Telclaude can integrate with private REST APIs ("sidecars") over WebFetch without assuming any specific vendor or schema.

**Configuration (generic):**
- Add providers to `telclaude.json` under `providers[]` (id, baseUrl, services list).
- Allowlist the provider host/port under `security.network.privateEndpoints`.
- See `docker/README.md` for the full config shape and examples.

**Recommended contract (best-effort):**
- `GET /v1/schema` — optional but recommended; used for auto-discovery and skills docs.
- `GET /v1/health` — health check (expected to return JSON with a status field).
- `POST /v1/{service}/{action}` — perform actions (Telclaude injects `x-actor-user-id` automatically).
- `POST /v1/challenge/respond` — OTP/2FA completion (handled via Telegram `/otp`, never by the LLM).

**Schema notes:**
- Telclaude tolerates provider-specific shapes and extracts services/actions if present.
- Optional `credentialFields` metadata is supported to describe required fields for operators; it is never shown as a request for user credentials.

## CLI reference

### Core
| Command | Description |
|---------|-------------|
| `telclaude relay [--profile simple\|strict\|test] [--dry-run]` | Start the relay |
| `telclaude quickstart` | Interactive first-time setup |
| `telclaude doctor [--network] [--secrets]` | Health check |
| `telclaude status [--json]` | Show relay status |

### Authentication & access control
| Command | Description |
|---------|-------------|
| `telclaude link <user-id> \| --list \| --remove <chat-id>` | Manage identity links |
| `telclaude totp-daemon [--socket-path <path>]` | Start TOTP daemon |
| `telclaude totp-setup <user-id>` | Set up TOTP for a user |
| `telclaude totp-disable <user-id>` | Disable TOTP for a user |
| `telclaude reset-auth [--force]` | Reset auth state |
| `telclaude ban <chat-id> [-r <reason>]` | Block a chat |
| `telclaude unban <chat-id>` | Restore access |
| `telclaude force-reauth <chat-id>` | Invalidate TOTP session |
| `telclaude list-bans` | Show banned chats |

### Credential vault
| Command | Description |
|---------|-------------|
| `telclaude vault-daemon` | Start vault daemon |
| `telclaude vault list` | List stored credentials |
| `telclaude vault add http <host> --type <type> [--label <name>]` | Add credential |
| `telclaude vault remove http <host>` | Remove credential |
| `telclaude vault test http <host>` | Test credential injection |

### API key setup (legacy, use vault for new setups)
| Command | Description |
|---------|-------------|
| `telclaude setup-openai` | Configure OpenAI API key |
| `telclaude setup-git` | Configure Git credentials |
| `telclaude setup-github-app` | Configure GitHub App |

### Network & providers
| Command | Description |
|---------|-------------|
| `telclaude network list` | List private endpoints |
| `telclaude network add <label> (--host <ip> \| --cidr <range>) [--ports <ports>]` | Add endpoint |
| `telclaude network remove <label>` | Remove endpoint |
| `telclaude network test <url>` | Test endpoint access |
| `telclaude provider-query --provider <id> --service <svc> --action <act>` | Query external provider |
| `telclaude provider-health [provider-id]` | Check provider health |

### Media & messaging
| Command | Description |
|---------|-------------|
| `telclaude send <chatId> [message] [--media <path>] [--caption <text>]` | Send message/media |
| `telclaude send-local-file --path <path> [--filename <name>]` | Send workspace file to Telegram |
| `telclaude send-attachment --ref <ref>` | Send provider attachment via ref token |
| `telclaude fetch-attachment --provider <id> --id <attachment-id>` | Download provider attachment |
| `telclaude generate-image <prompt> [-s <size>] [-q <quality>]` | Generate image (requires OpenAI) |
| `telclaude text-to-speech <text> [-v <voice>] [-f <format>]` | Text-to-speech (requires OpenAI) |

### Diagnostics
| Command | Description |
|---------|-------------|
| `telclaude diagnose-sandbox-network` | Debug sandbox network issues |
| `telclaude integration-test [--all]` | Run SDK integration tests |
| `telclaude reset-db [--force]` | Delete SQLite database (requires `TELCLAUDE_ENABLE_RESET_DB=1`) |

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
- **Production (mandatory): Docker/WSL Compose stack** (`docker/README.md`). Relay+agent containers + firewall; SDK sandbox disabled in Docker mode. Use this on shared or multi-tenant hosts.
- **Development:** Native macOS/Linux with SDK sandbox (Seatbelt/bubblewrap). SDK sandbox provides OS-level isolation for Bash; WebFetch/WebSearch are filtered by hooks/allowlists. Keep `~/.telclaude/telclaude.json` chmod 600.

## Development
- Lint/format: `pnpm lint`, `pnpm format`
- Types: `pnpm typecheck`
- Tests: `pnpm test` or `pnpm test:coverage`
- Build: `pnpm build`
- Local CLI: `pnpm dev relay`, `pnpm dev doctor`, etc.
- Secrets scan: `brew install gitleaks` (or download binary) then `pnpm security:scan` (uses `.gitleaks.toml`)

## Security & reporting
- Default stance is fail-closed (empty `allowedChats` denies all; `defaultTier=FULL_ACCESS` is rejected).
- Native mode requires the SDK sandbox; relay exits if Seatbelt/bubblewrap (or socat on Linux) is unavailable. Docker mode requires the firewall (containers enforce it).
- Vulnerabilities: please follow `SECURITY.md` for coordinated disclosure.
- Security contact: project maintainer(s) via GitHub security advisory.

## Troubleshooting (quick)
| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Bot silent/denied | `allowedChats` empty or rate limit hit | Add your chat ID and rerun; check audit/doctor |
| Sandbox unavailable (native) | seatbelt/bubblewrap/rg/socat missing | Install deps (see `CLAUDE.md#sandbox-unavailable-relay-wont-start`) |
| TOTP fails | Daemon not running or clock drift | Start `pnpm dev totp-daemon`; sync device time |
| SDK/observer errors | Claude CLI missing or not logged in | `brew install anthropic-ai/cli/claude && claude login` (Docker: `docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login`) |
| Vault not injecting | Daemon not running or host not configured | Start `telclaude vault-daemon`; check `vault list` |

## Community
- Contributing guidelines: see `CONTRIBUTING.md`.
- Code of Conduct: see `CODE_OF_CONDUCT.md`.
- Issues & discussions: open GitHub issues; we triage weekly.
- Changelog: see `CHANGELOG.md`.

## Acknowledgments

Inspired by [Clawdis](https://github.com/steipete/clawdis) by [@steipete](https://github.com/steipete).

## Disclaimer

Provided as-is for authorized use only. Use at your own risk.

## License

MIT
