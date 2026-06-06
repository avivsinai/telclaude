# telclaude

Isolation-first Telegram ⇄ agent relay for Claude Code, Codex, and operator workflows, with LLM pre-screening, approvals, and tiered permissions.

[![CI](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml)
[![Gitleaks](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/gitleaks.yml)
[![CodeQL](https://github.com/avivsinai/telclaude/actions/workflows/codeql.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Alpha** — Security-first defaults; expect breaking changes until 1.0.

## Highlights
- Mandatory isolation boundary: SDK sandbox (Seatbelt/bubblewrap) in native mode, relay+agent containers + firewall in Docker mode.
- Credential vault: sidecar daemon stores API keys and injects them into requests — agents never see raw credentials.
- Relay-authoritative memory: trusted semantic memory + episodic shared history archive + compiled Claude `MEMORY.md` working set. Private recall is aggressive, but source boundaries remain hard.
- Hard defaults: secret redaction (CORE patterns + entropy), rate limits, audit log, and fail-closed chat allowlist.
- Soft controls: Haiku observer, nonce-based approval workflow for FULL_ACCESS, and optional TOTP auth gate for periodic identity verification.
- Four permission tiers mapped to agent runtime capabilities: READ_ONLY, WRITE_LOCAL, SOCIAL, FULL_ACCESS.
- Generic social services integration (X/Twitter, Moltbook, Bluesky, etc.) via config-driven `SOCIAL` agent context with unified social persona.
- External provider sidecars: Google Services (Gmail, Calendar, Drive, Contacts) with approval-gated actions; extensible pattern for adding new providers.
- No-fork Hermes wrapper: run a pinned upstream Hermes runtime inside the same security envelope, with a contained Docker runtime, a relay-internal MCP bridge, signed proof artifacts, and a strict cutover gate.
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
| `docs/architecture.md` | Architecture design rationale, security model, invariants |
| `docs/providers.md` | Provider integration guide (sidecar pattern, adding new providers) |
| `docker/README.md` | Container deployment, firewall, volumes |
| `CHANGELOG.md` | Version history |
| `SECURITY.md` | Vulnerability reporting, threat model |
| `docs/soul.md` | Agent identity, voice, interests |

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
| SOCIAL | File tools + Bash + WebFetch/WebSearch | Bash trust-gated by actor type; WebFetch permissive; protected paths blocked |
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
│  READ_ONLY    WRITE_LOCAL    SOCIAL         FULL_ACCESS        │
│  (5 tools)    (8 tools)     (trust-gated)  (all, +approval)   │
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

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   TOTP Daemon    │  │  Vault Daemon    │  │ Google Services  │
│  (OS keychain)   │  │ (credential      │  │ (Gmail, Calendar │
└──────────────────┘  │  injection)      │  │  Drive, Contacts)│
                      └──────────────────┘  └──────────────────┘
```

## Requirements
- Node 20+, pnpm 9.x
- Claude CLI (`brew install anthropic-ai/cli/claude`) — current primary runtime. In Docker, telclaude routes Anthropic access through the relay proxy; if you use OAuth, run `claude login` in the relay container with `CLAUDE_CONFIG_DIR=/home/telclaude-auth` so tokens live in the dedicated auth profile.
- Codex CLI (`codex`) — first-class peer runtime surface. For write-capable Codex work, configure a dedicated `CODEX_HOME`; `telclaude runtimes status` reports whether Codex would use controlled or global config.
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
cp telclaude.json.example telclaude.json
cp telclaude-private.json.example telclaude-private.json
docker compose up -d --build
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login  # optional if not using ANTHROPIC_API_KEY
```
See `docker/README.md` for firewall, volume, and upgrade details.
This starts 6 containers: `telclaude` (relay), `telclaude-agent` (private persona), `agent-social` (social persona), `google-services` (Google sidecar), `totp`, and `vault`.

Note: Docker uses a shared **skills** profile (`/home/telclaude-skills`) and a relay-only **auth** profile (`/home/telclaude-auth`). Agents access Anthropic through the relay proxy; credentials never mount in agent containers.

The relay also compiles private Telegram memory into the agent's Claude project-memory path under `/home/telclaude-skills/projects/<project-slug>/memory/MEMORY.md`. That file is a working-set cache, not the source of truth.

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
pnpm dev maintenance totp-daemon
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
- In the same chat, run `/auth setup` to bind TOTP for periodic identity verification (daemon must be running). `/auth skip` is allowed but not recommended.
- Optional hardening: set `TELCLAUDE_ADMIN_SECRET` and start with `/claim <secret>` to prevent scanner bots claiming admin first (see `SECURITY.md`).

## Telegram command surface
- Chat normally — anything not starting with `/` goes to the AI agent.
- `/help <topic>` — contextual help for approvals, 2fa, sessions, etc.
- `/system` — system status, sessions, cron (card-based with inline buttons).
- `/me`, `/auth`, `/social`, `/skills` — identity, 2FA, social persona, skill management.
- `/profile list|switch <id>|reset` — inspect or switch the active operator profile for the chat.
- `/curator` — review local automation suggestions and accept/reject without executing the action.
- `/codex [--model <id>] [--cwd <relative-path>] [--write] <prompt>` — queue a single-shot Codex work unit; results return as a background job card. Supported overrides are `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`, `gpt-5.3-codex`, `gpt-5.3-codex-spark`, and `gpt-5.2`.
- `/approve`, `/new` — fast-path shortcuts for approvals and session reset.

## Memory model

Telclaude uses three memory layers for the private persona:

1. **Semantic memory** — durable entries in the relay database (`profile`, `interests`, `meta`, `threads`). This is the authoritative store.
2. **Episodic archive** — relay-owned summaries of private turns used for recent and query-relevant shared-history recall.
3. **Compiled Claude working memory** — a generated `MEMORY.md` file materialized into Claude's local project-memory path before a query starts.

The agent never owns the source of truth. The relay assembles a scoped memory bundle, injects it into the prompt as read-only data, materializes the compiled `MEMORY.md`, and then captures successful turns back into the episodic archive. Automatic memory extraction is conservative: explicit durable facts are promoted automatically, while secrets and instruction-like content are rejected or sanitized.

Inspect the current private memory bundle with:

```bash
pnpm dev memory context --chat-id <telegram-chat-id> --query "oauth vault refresh"
pnpm dev memory context --chat-id <telegram-chat-id> --markdown
```

`--chat-id` resolves that chat's active operator profile before reading memory. Private memory is stored under `telegram:<profile-id>` sources, so switching `/profile` changes the semantic and episodic memory namespace used by normal replies, scheduled private runs, and local memory inspection.

## Configuration
- Default path: `~/.telclaude/telclaude.json` (override with `TELCLAUDE_CONFIG` or `--config`).
- Security profiles:
  - `simple` (default): sandbox + secret filter + rate limits + audit.
  - `strict`: adds Haiku observer, approval workflow, and tiered tool gates.
  - `test`: disables all enforcement; requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`.
- Operator profiles:
  - Configure top-level `profiles[]` entries with `id`, `label`, optional `description`, `soulPath`, `allowedSkills`, and `defaultModel`.
  - `soulPath` points to a profile-specific prompt overlay.
  - `allowedSkills` narrows private-agent skill loading for that profile; omit it to allow all private skills.
  - `defaultModel` uses `{ "providerId": "anthropic", "modelId": "claude-sonnet-4-5-20250929" }` and is overridden by explicit chat `/model` choices.
  - Telegram admins switch a chat with `/profile switch <id>` and return to the implicit default with `/profile reset`.
- Permission tiers:
  - `READ_ONLY`: read/search/web only; no writes.
  - `WRITE_LOCAL`: read/write/edit/bash with destructive commands blocked.
  - `SOCIAL`: file tools + Bash + WebFetch/WebSearch; Bash trust-gated by actor; protected paths blocked.
  - `FULL_ACCESS`: unrestricted tools but every request needs human approval.
  - Set per-user under `security.permissions.users`; `defaultTier` stays `READ_ONLY`.
- Optional group guardrail:
  - `telegram.groupChat.requireMention: true` to ignore group/supergroup messages unless they mention the bot or reply to it.
- OpenAI/GitHub key exposure (tier-based):
  - FULL_ACCESS tier automatically gets configured API keys (OpenAI, GitHub) exposed to sandbox.
  - READ_ONLY and WRITE_LOCAL tiers never get keys.
  - Configure keys via `telclaude secrets setup-openai` / `telclaude secrets setup-git` or env vars.
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
telclaude maintenance vault-daemon

# Add a credential
telclaude vault add http api.openai.com --type bearer --label "OpenAI"
# (prompts for token securely)

# List credentials
telclaude vault list
```

See `docs/architecture.md` for vault design rationale. CLI reference: `telclaude vault --help`.

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
telclaude dev network list
telclaude dev network add ha --host 192.168.1.100 --ports 8123
telclaude dev network test http://192.168.1.100:8123/api
```

Metadata endpoints (169.254.169.254) and link-local addresses remain blocked regardless of allowlist.

## External providers (sidecars)
Telclaude integrates with private REST API sidecars via relay-proxied requests. Agents never call provider endpoints directly (enforced at both application and firewall layers).

**Built-in provider:** Google Services (Gmail, Calendar, Drive, Contacts) -- 4 services, 20 actions with approval-gated mutations. Setup: `telclaude providers setup google --base-url http://google-services:3002`.

**Configuration:**
- Add providers to `telclaude.json` under `providers[]` (id, baseUrl, services list).
- See `docs/providers.md` for the full integration guide, including how to add new providers.

**Required endpoints:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/health` | GET | Health check (returns JSON with status field) |
| `/v1/schema` | GET | Action catalog for auto-discovery and skill docs |
| `/v1/fetch` | POST | Dispatch service action (body: `{ service, action, params }`) |

Optional: `/v1/challenge/respond` (POST) for OTP/2FA completion.

## Hermes wrapper (no-fork)

Telclaude can drive a pinned, unmodified upstream Hermes runtime instead of the Claude Agent SDK for the private persona — without forking, patching, or monkeypatching Hermes. The relay stays the security envelope; Hermes is the agent loop running behind it. Everything still flows through the same isolation, redaction, approval, and memory-authority guarantees.

**Contained runtime (Docker).** The `docker/docker-compose.hermes.yml` overlay adds a `tc-hermes-contained` container (non-root uid `10000`, all capabilities dropped, read-only root, noexec tmpfs) on a dedicated **internal** network (`telclaude-hermes-relay`, default `192.0.2.0/24`) that holds exactly two members: the relay and the Hermes container. Model-provider hosts are pinned to a blackhole IP so Hermes cannot reach any model endpoint directly — inference is routed through the relay's OpenAI Codex proxy, and the relay serves a live MCP bridge (memory, providers, attachments, outbound) over a relay-internal HTTP endpoint. Bring it up with:

```bash
TELCLAUDE_HERMES_API_SERVER_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
TELCLAUDE_HERMES_PRIVATE_RUNTIME=1 \
docker compose -f docker/docker-compose.yml -f docker/docker-compose.hermes.yml up -d telclaude tc-hermes-contained
```

**MCP bridge & side-effect ledger.** The relay-owned MCP bridge exposes a fixed set of relay-scoped tools (provider read/prepare/execute, memory search/write, attachment get, outbound prepare/execute, audit note). It is not an agent tool allowlist: each connection is bound to an opaque, TTL-limited authority handle, and provider/outbound writes are two-phase (prepare → human approval → execute) with one-time, Ed25519-signed, request-bound approval tokens (params-hash + JTI replay protection, self-approval blocked). Memory access is domain-scoped, so the private Hermes runtime can never read social memory.

**Proof spine.** Cutover from the SDK runtime to Hermes is gated by signed evidence, not trust. The `telclaude hermes` command group generates and evaluates these artifacts:
- **No-fork proof** — the pinned checkout is present, pinned, and byte-clean before and after a wrapper run (no diff, no source replacement, no monkeypatch), with an optional signed runner attestation.
- **Feature probes** — a per-surface matrix (headless execution, approval continuation, served-MCP containment, model relay, edge adapters, providers, skills allowlist, workflows, browser/computer broker) backed by readable, attested evidence.
- **Network probes** — proof that direct egress to providers, the vault, model providers, and DNS/metadata exfil is denied while the relay control path is allowed, under a `contained-internal` posture.
- **Parity roster + cutover check** — `telclaude hermes cutover-check` (strict by default) fails closed unless every workflow in scope is inventoried, fixtured, decision-resolved, queue-owned, rollback-rehearsed, and (for a complete cutover) every canonical parity row is backed or explicitly descoped. Non-descopable rows (`cutover`, `redaction`, `private-chat`, `approval-tokens`, `identity-migration`, `memory`, `skills`) can never be waived.

Strict cutover is all-or-nothing per approved workflow bundle — there is no gradual, partially-proven replacement. See `docs/architecture.md` for the trust-boundary rationale.

## CLI reference

### Core
| Command | Description |
|---------|-------------|
| `telclaude relay [--profile simple\|strict\|test] [--dry-run]` | Start the relay |
| `telclaude quickstart` | Interactive first-time setup |
| `telclaude doctor [--network] [--secrets]` | Health check |
| `telclaude status [--json]` | Show relay status |
| `telclaude runtimes status [--json]` | Show Claude Code and Codex runtime readiness |

### Authentication & access control
| Command | Description |
|---------|-------------|
| `telclaude link <user-id> \| --list \| --remove <chat-id>` | Manage identity links |
| `telclaude maintenance totp-daemon [--socket-path <path>]` | Start TOTP daemon |
| `telclaude auth totp-setup <user-id>` | Set up TOTP for a user |
| `telclaude auth totp-disable <user-id>` | Disable TOTP for a user |
| `telclaude maintenance reset-auth [--force]` | Reset auth state |
| `telclaude admin ban <chat-id> [-r <reason>]` | Block a chat |
| `telclaude admin unban <chat-id>` | Restore access |
| `telclaude auth force-reauth <chat-id>` | Invalidate TOTP session |
| `telclaude admin list-bans` | Show banned chats |

### Credential vault
| Command | Description |
|---------|-------------|
| `telclaude maintenance vault-daemon` | Start vault daemon |
| `telclaude vault list` | List stored credentials |
| `telclaude vault add http <host> --type <type> [--label <name>]` | Add credential |
| `telclaude vault remove http <host>` | Remove credential |
| `telclaude vault test http <host>` | Test credential injection |

### API key & service setup
| Command | Description |
|---------|-------------|
| `telclaude secrets setup-openai` | Configure OpenAI API key |
| `telclaude secrets setup-git` | Configure Git credentials |
| `telclaude secrets setup-github-app` | Configure GitHub App |
| `telclaude secrets setup-google` | Configure Google OAuth credentials (for Google Services sidecar) |

### Network & providers
| Command | Description |
|---------|-------------|
| `telclaude dev network list` | List private endpoints |
| `telclaude dev network add <label> (--host <ip> \| --cidr <range>) [--ports <ports>]` | Add endpoint |
| `telclaude dev network remove <label>` | Remove endpoint |
| `telclaude dev network test <url>` | Test endpoint access |
| `telclaude providers init <id> [--services <csv>]` | Scaffold a provider sidecar |
| `telclaude providers list` | List configured providers |
| `telclaude providers add <id> --base-url <url> --services <csv>` | Add a custom provider |
| `telclaude providers edit <id> --base-url <url> --services <csv>` | Edit a provider |
| `telclaude providers remove <id>` | Remove a provider |
| `telclaude providers refresh` | Refresh provider schema and runtime skill state |
| `telclaude providers schema [id]` | Fetch provider schema |
| `telclaude providers query <id> <svc> <act>` | Query external provider |
| `telclaude providers doctor [id]` | Check provider health |
| `telclaude providers setup google --base-url <url>` | Configure Google provider end-to-end |

### Hermes wrapper
All commands live under the `telclaude hermes` group; most accept `--json`. Cutover evaluators such as `cutover-check` use exit `0` for safe/pass, `1` for semantic failure, and `2` for unreadable or unsafe inputs; generator commands report their own status in JSON.

| Command | Description |
|---------|-------------|
| `telclaude hermes doctor [--pin <pin>] [--probes] [--compat-lock]` | Check pinned Hermes wrapper readiness |
| `telclaude hermes inventory [--out <path>]` | Emit the Phase 0 wrapper inventory |
| `telclaude hermes generate [--write] [--dry-run] [--pin <pin>]` | Generate Hermes wrapper profile artifacts |
| `telclaude hermes fixtures [--write]` | Generate parity fixture result artifacts |
| `telclaude hermes probes [--pin <pin>] [--out <path>]` | Generate the canonical feature-probe matrix from observed evidence |
| `telclaude hermes probe <surface> [--allow-run] [--out <path>]` | Evaluate a single feature probe |
| `telclaude hermes network-probes [--allow-run] [--posture <posture>]` | Run gated network isolation probes and write cutover evidence |
| `telclaude hermes prove --upstream-clean [--p0]` | Generate fail-closed no-fork proof artifacts; `--p0` requires an existing proof bundle and evidence inputs |
| `telclaude hermes proof-bundle --inventory <path> --scope-manifest <path> --decision-log <path> --compatibility-lockfile <path> --feature-probe-matrix <path> --fixture-results <path> --nofork-proof-file <path> --network-probe-bundle <path> --queue-snapshot <path> --rollback-evidence <path>` | Build a byte-bound cutover proof bundle from strict evidence artifacts |
| `telclaude hermes cutover-scope --inventory <path>` | Generate a fail-closed cutover scope skeleton from an inventory snapshot |
| `telclaude hermes decision-log [--inventory <path>]` | Generate a fail-closed cutover decision log draft |
| `telclaude hermes compat-lock --dry-run [--pin <pin>]` | Generate a Hermes compatibility lockfile draft |
| `telclaude hermes queue-snapshot [--inventory <path>]` | Build cutover queue ownership evidence |
| `telclaude hermes rollback-rehearsal [--allow-run]` | Generate relay-observed private-runtime rollback evidence |
| `telclaude hermes cutover-check [--strict] [--dry-run] [--scoped]` | Evaluate strict cutover evidence; strict mode is the default |
| `telclaude hermes private-runtime status [--json]` | Show the relay-observed private-runtime effective mode |
| `telclaude hermes private-runtime set <mode>` | Set durable private-runtime mode (`hermes` \| `legacy`) via operator RPC |
| `telclaude hermes live-mcp probe-tokens` | Issue served-MCP containment probe tokens through the relay admin socket |

### Media & messaging
| Command | Description |
|---------|-------------|
| `telclaude send <chatId> [message] [--media <path>] [--caption <text>]` | Send message/media |
| `telclaude send-file --path <path> [--filename <name>]` | Send workspace file to Telegram |
| `telclaude send-local-file --path <path> [--filename <name>]` | Backward-compatible alias for sending workspace files |
| `telclaude send-attachment --ref <ref>` | Send provider attachment via ref token |
| `telclaude fetch-attachment --provider <id> --id <attachment-id>` | Download provider attachment |
| `telclaude generate-image <prompt> [-s <size>] [-q <quality>]` | Generate image (requires OpenAI) |
| `telclaude text-to-speech <text> [-v <voice>] [-f <format>]` | Text-to-speech (requires OpenAI) |

### Memory, cron & Curator
| Command | Description |
|---------|-------------|
| `telclaude memory read --chat-id <id> --categories profile,interests` | Read memory entries for the chat's active profile |
| `telclaude memory context --chat-id <id> [--markdown]` | Render the compiled private memory bundle |
| `telclaude memory write "fact" --chat-id <id> --category meta` | Write memory under the chat's active profile |
| `telclaude maintenance cron status` | Cron scheduler status |
| `telclaude maintenance cron list [--all] [--json]` | List cron jobs |
| `telclaude maintenance cron add --name <n> --every <dur>\|--cron <expr>` | Add cron job |
| `telclaude maintenance cron run <id>` | Run cron job immediately |
| `telclaude curator scan\|list\|show\|accept\|reject` | Review local Curator suggestions |
| `telclaude curator sign-producer --item item.json --producer-kind codex --producer-id codex:<id>` | Sign a Codex/Claude Curator item through the vault |
| `telclaude curator submit-signed --item item.json --envelope envelope.json` | Verify and submit a signed producer Curator item |

### Diagnostics
| Command | Description |
|---------|-------------|
| `telclaude diagnose-sandbox-network` | Debug sandbox network issues |
| `telclaude integration-test [--all] [--agents]` | Run SDK integration tests (optional direct agent transport check with `--agents`) |
| `telclaude reset-db [--force]` | Delete SQLite database (requires `TELCLAUDE_ENABLE_RESET_DB=1`) |

## Usage example
Run strict profile with approvals and TOTP:
```bash
pnpm dev maintenance totp-daemon &
pnpm dev relay --profile strict
# In Telegram (allowed chat):
# 1) bot replies with /approve CODE for admin claim
# 2) run /auth setup to bind TOTP
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
| Sandbox unavailable (native) | seatbelt/bubblewrap/rg/socat missing | Install deps (see Requirements section above) |
| TOTP fails | Daemon not running or clock drift | Start `telclaude maintenance totp-daemon`; sync device time |
| SDK/observer errors | Claude CLI missing or not logged in | `brew install anthropic-ai/cli/claude && claude login` (Docker: `docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login`) |
| Vault not injecting | Daemon not running or host not configured | Start `telclaude maintenance vault-daemon`; check `vault list` |

## Community
- Issues & discussions: open GitHub issues; we triage weekly.
- Changelog: see `CHANGELOG.md`.

## Acknowledgments

Inspired by [Clawdis](https://github.com/steipete/clawdis) by [@steipete](https://github.com/steipete).

## Disclaimer

Provided as-is for authorized use only. Use at your own risk.

## License

MIT
