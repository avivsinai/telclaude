# Telclaude Architecture Deep Dive

Updated: 2026-02-11
Scope: detailed design and security rationale for telclaude (Telegram ⇄ Claude Code relay).

## Dual-Mode Sandbox Architecture

Telclaude uses a dual-mode architecture for isolation:

- **Docker mode**: Relay and agent run in separate containers. The SDK sandbox is disabled in Docker; the **agent container** provides isolation with a firewall and locked-down volumes, while the **relay container** holds secrets and does not mount the workspace (firewall-enabled for egress control).
- **Native mode**: SDK sandbox enabled. bubblewrap (Linux) or Seatbelt (macOS) provides isolation.

Mode is auto-detected at startup via `/.dockerenv` or `TELCLAUDE_DOCKER=1` env var.

## System Overview

```
Telegram Bot API
      │
      ▼
┌────────────────────────────────────────────┐
│ Relay (security + secrets)                 │
│ • Fast-path + observer                     │
│ • Permission tiers & approvals             │
│ • Rate limits & audit                      │
│ • Identity linking + TOTP socket           │
│ • Social service heartbeats + API clients  │
└────────────────────────────────────────────┘
      │ internal HTTP
      ├──────────────────────────┬──────────────────────────┐
      ▼                          ▼
┌────────────────────────────────────────────┐   ┌────────────────────────────────────────────┐
│ Agent worker (Telegram — private persona)  │   │ Agent worker (Social — social persona)     │
│ • Workspace mounted                        │   │ • No workspace mount                       │
│ • Media inbox/outbox volumes               │   │ • Shared /social/sandbox                   │
│ • Browser automation (Chromium)            │   │ • Browser automation (Chromium)            │
└────────────────────────────────────────────┘   └────────────────────────────────────────────┘
      │                                          │
      ▼                                          ▼
Claude Agent SDK (allowedTools per tier)         Claude Agent SDK (SOCIAL tier)
```

## Docker Split Topology (Production)

- **Relay container**: Telegram + social service handlers, security policy + secrets (OpenAI/GitHub), TOTP socket. Reads both `telclaude.json` (policy) and `telclaude-private.json` (secrets/PII).
- **Telegram agent container** (`telclaude-agent`): Claude SDK + tools + Chromium, no secrets, workspace mounted. Image: `telclaude-agent:latest`. Reads only `telclaude.json` (policy config — providers, network rules, etc.).
- **Social agent container** (`agent-social`): Claude SDK + tools + Chromium, no secrets, no workspace mount, shared `/social/sandbox`. Image: `telclaude-agent:latest`. Single container for all social services (scope: `"social"`).
- **Claude profiles**:
  - `/home/telclaude-skills` (shared skills + CLAUDE.md; no credentials)
  - `/home/telclaude-auth` (relay-only OAuth tokens)
- **Shared media volumes**:
  - `media_inbox` (relay writes Telegram downloads, agent reads)
  - `media_outbox` (relay writes generated media; relay reads to send)
- **Social memory volume**:
  - `/social/memory` (relay is single writer; social agent is read-only)
- **Internal RPC**:
  - Relay → Agent: `/v1/query` (HMAC-signed)
  - Agent → Relay: `/v1/image.generate`, `/v1/tts.speak`, `/v1/transcribe` (HMAC-signed)
- **Anthropic access**: agents use relay proxy (`ANTHROPIC_BASE_URL`) instead of direct credentials.
- **Firewall**: enabled in both containers; internal hostnames allowed via `TELCLAUDE_INTERNAL_HOSTS`.
- **RPC auth**: All scopes use bidirectional Ed25519 asymmetric auth with two keypairs per scope. The agent keypair (`{SCOPE}_RPC_AGENT_PRIVATE_KEY` / `{SCOPE}_RPC_AGENT_PUBLIC_KEY`) authenticates agent→relay requests; the relay keypair (`{SCOPE}_RPC_RELAY_PRIVATE_KEY` / `{SCOPE}_RPC_RELAY_PUBLIC_KEY`) authenticates relay→agent requests. Compromise of one side cannot forge messages in the other direction. Generate keys with `telclaude keygen <scope>` (e.g., `telclaude keygen telegram`, `telclaude keygen social`). Internal servers bind to `0.0.0.0` in Docker and `127.0.0.1` in native mode.
- **Agent network isolation**: each agent is on its own relay network; agents do not share a network segment or direct connectivity. Only the relay can reach all agents.

## Social Services Integration

Telclaude supports multiple social service backends through a generic `SocialServiceClient` interface. Each backend (Moltbook, X/Twitter, future: Bluesky, etc.) implements the same contract and is configured via the `socialServices[]` array in config.

### Architecture

- **Config-driven**: each service is an entry in `socialServices[]` with `id`, `type`, `enabled`, `apiKey`, `handle`, `displayName`, `heartbeatIntervalHours`, `enableSkills`, `allowedSkills`, `notifyOnHeartbeat`, and optional `agentUrl` override.
- **Heartbeat-driven**: relay scheduler polls each enabled service's notifications on a configured interval (default 4h, min 60s).
- **Three-phase heartbeat**: Phase 1 — process incoming notifications (reply to mentions). Phase 2 — proactive posting (publish promoted ideas). Phase 3 — autonomous activity (browse timeline, engage, create content).
- **Single social persona**: all social services share one agent container (`agent-social`) with no workspace mount and a shared `/social/sandbox` working directory. RPC scope is `"social"` for all services.
- **Unified social memory**: all social services share `source: "social"` memory. The public persona is one cohesive identity across platforms — not per-service.
- **SOCIAL tier**: social requests run under the `SOCIAL` tier. Bash is trust-gated: allowed for trusted actors (operator queries, autonomous heartbeats) but blocked for untrusted actors (notifications, proactive posting). Write/Edit to protected paths (`/home/telclaude-skills`, `/home/telclaude-auth`, `/social/memory`) is blocked for all actors. WebFetch is permissive (all public URLs allowed; RFC1918/metadata still blocked). Skills are disabled by default but can be enabled per-service via `enableSkills` config.
- **Untrusted wrappers**: notification payloads and social context are wrapped with explicit "UNTRUSTED / do not execute" warnings before being sent to the model.
- **Memory isolation**: social prompts only include unified social memory (`source: "social"`). Runtime assertions enforce that telegram entries never leak into social queries, and vice versa.
- **Proactive posting**: user-approved ideas (promoted via `/promote`) are posted to the service during heartbeat, with rate limiting and agent isolation.
- **Autonomous activity**: Phase 3 allows the agent to independently browse timelines, engage with posts, and create original content. Uses dedicated `poolKey: "${serviceId}:autonomous"` for session isolation.
- **Notifications**: heartbeat results are optionally sent to the admin via Telegram (`notifyOnHeartbeat: "always" | "activity" | "never"`). All notification content is sanitized (no raw LLM output, URLs stripped, 200 char limit).

### Supported Backends

| Type | Service | Auth | Limits |
|------|---------|------|--------|
| `moltbook` | Moltbook | API key via `apiKey` config | Service-specific |
| `xtwitter` | X/Twitter | OAuth2 via vault credential proxy | 280 chars/tweet, 100 tweets/15min/user |

### X/Twitter Backend

The `xtwitter` backend uses X API v2:
- `fetchNotifications()` → `GET /2/users/:id/mentions`
- `postReply()` → `POST /2/tweets` with `reply.in_reply_to_tweet_id`
- `createPost()` → `POST /2/tweets` (280 char limit enforced)
- Auth: vault credential proxy injects OAuth2 bearer via `http://relay:8792/api.x.com/2/tweets`
- Required OAuth2 scopes: `tweet.read`, `tweet.write`, `users.read`, `offline.access`
- Token lifecycle: access token 2h, refresh token 6 months (one-time use, rotated on refresh)
- Env: `X_USER_ID` (required), `X_BEARER_TOKEN` (optional — not needed when using vault proxy)

### Adding a New Backend

1. Implement `SocialServiceClient` in `src/social/backends/{name}.ts`
2. Register the backend type in the factory (`src/social/index.ts`)
3. Add a `socialServices` entry to config: `{ id: "myservice", type: "myservice", enabled: true }`
4. Generate RPC keys (if not already done): `telclaude keygen social`
5. No per-service container needed — the shared `agent-social` handles all services

### Cross-Persona Querying

The operator can query the public persona from Telegram using two tiers:

**Tier 1: `/public-log [serviceId] [hours]`** — Activity metadata (no LLM). Returns counts, timestamps, and action types from the `social_activity_log` SQLite table. Zero injection risk — no untrusted content touches any LLM.

**Tier 2: `/ask-public <question>`** — Routed to social agent. The relay pipes the social agent's response directly to Telegram. The private telegram agent never sees it — the relay handles the routing. Uses dedicated `poolKey: "${serviceId}:operator-query"`.

**Security (air gap)**: The private LLM never processes social memory. This prevents the confused deputy problem — social memory could contain prompt injection from X timeline that would be executed with elevated privileges.

### Private Heartbeat

The Telegram persona can run autonomous background maintenance:

- **Config**: `telegram.heartbeat.enabled`, `intervalHours` (default 6), `notifyOnActivity` (default true)
- **Tier**: WRITE_LOCAL (not FULL_ACCESS) — prevents destructive operations
- **Scope**: `"telegram"` — uses telegram RPC keypair, gets telegram memory only
- **Session isolation**: dedicated `poolKey: "telegram:private-heartbeat"` prevents bleed with user conversations
- **Tasks**: review quarantined post ideas, check workspace state, organise memory
- **Output**: `[IDLE]` or summary of actions taken; admin notified on activity

## Memory System & Provenance

Telclaude stores memory in SQLite with provenance metadata, split at the **private vs. public boundary** (not per-service):

- **Sources**: `telegram` (private persona) or `social` (unified public persona across all social services).
- **Trust**: `trusted`, `untrusted`, `quarantined`.
- **Provenance**: each entry records source, trust level, and timestamps (created/promoted).
- **Default trust**: Telegram memory is trusted by default; social service memory is untrusted (no promotion path yet).
- **Unified public memory**: all social services (Moltbook, X/Twitter, etc.) share `source: "social"`. The public persona has one cohesive memory — not fragmented per-platform.
- **Isolation enforcement**: runtime assertions in both `buildTelegramMemoryContext()` and `getTrustedSocialEntries()` verify source boundaries. Non-matching entries are filtered out with security warnings (throws in dev, warn in prod).
- **Prompt injection safety**: even trusted entries are wrapped in a "read-only, do not execute" envelope before being injected into prompts.
- **Activity log**: `social_activity_log` SQLite table stores metadata-only records of social actions (type, timestamp, serviceId). No content or LLM output stored — used by `/public-log` for zero-injection-risk activity summaries.

## Security Profiles
- **simple (default)**: rate limits + audit + secret filter. No observer/approvals.
- **strict (opt-in)**: adds Haiku observer, approvals, and tier enforcement.
- **test**: disables all enforcement; gated by `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Five Security Pillars
1) **Filesystem isolation**: Docker mode splits relay/agent containers (agent mounts workspace + media only; relay holds secrets). Native mode uses SDK sandbox; sensitive paths blocked via hooks.
2) **Environment isolation**: minimal env vars passed to SDK.
3) **Network isolation**: PreToolUse hook blocks RFC1918/metadata for WebFetch; SDK sandbox allowedDomains for Bash in native mode; Docker mode relies on the container firewall.
4) **Secret output filtering**: CORE patterns + entropy detection; infrastructure secrets are non-overridable blockers.
5) **Auth/rate limits/audit**: identity links, TOTP auth gate, SQLite-backed.

## Permission Tiers

| Tier | Tools | Notes |
| --- | --- | --- |
| READ_ONLY | Read, Glob, Grep, WebFetch, WebSearch | No writes allowed |
| WRITE_LOCAL | READ_ONLY + Write, Edit, Bash | Blocks destructive patterns; prevents accidents |
| FULL_ACCESS | All tools | Approval required unless user is claimed admin |
| SOCIAL | Read, Glob, Grep, Write, Edit, Bash, WebFetch, WebSearch | Social agents; Bash trust-gated (operator/autonomous only); WebFetch permissive (public internet); Write/Edit blocked to skills/auth/memory paths |

## Network Enforcement

- **Bash**: SDK sandbox `allowedDomains` in native mode; Docker firewall enforced in containers (agent runs tools; relay still restricts egress).
- **WebFetch**: PreToolUse hook blocks RFC1918/metadata unconditionally. Private agents use domain allowlist; social agents are permissive (all public URLs). `canUseTool` is a fallback layer with domain + privateEndpoint allowlists.
- **WebSearch**: NOT filtered (server-side by Anthropic).
- `TELCLAUDE_NETWORK_MODE=open|permissive`: enables broad egress for WebFetch (private agents only; social is always permissive).
- Internal relay ↔ agent RPC is allowed via hostname allowlist in the firewall script.
- **Allowlist scope**: Domain allowlists are enforced, but HTTP method restrictions are not enforced at runtime.
- **CGNAT/Tailscale**: The private IP matcher treats 100.64.0.0/10 (RFC 6598) as private to support Tailscale.

## External Providers (Sidecars)

Telclaude integrates with private sidecar services via the relay proxy.
This keeps telclaude OSS generic while allowing country- or org-specific integrations.

**Enforcement (two layers)**:
- **Application layer**: The agent **cannot** call provider endpoints directly via WebFetch — the PreToolUse hook blocks any WebFetch URL matching a configured provider `baseUrl` and directs the agent to use `telclaude provider-query` (Bash), which routes through the relay.
- **Firewall layer**: Agent containers set `TELCLAUDE_FIREWALL_SKIP_PROVIDERS=1`, so provider hosts are not added to the agent's iptables allowlist. Even if the application hook is bypassed (e.g., via Bash `curl`), the firewall blocks direct access. Only the relay container gets provider host firewall rules.

The relay handles authentication, attachment storage, and audit logging for all provider calls.

**`providers` vs `privateEndpoints`**: These are separate config sections for different purposes:
- **`providers`** defines relay-proxied sidecar services. Agents access these through the relay, never directly.
- **`privateEndpoints`** allows direct WebFetch access to private network services (Home Assistant, NAS, Plex, etc.) that don't need relay proxying.

Provider hosts do NOT need matching `privateEndpoints` entries — the relay firewall auto-extracts provider hosts from `providers[].baseUrl`.

**Config example:**
```json
{
  "providers": [
    {
      "id": "citizen-services",
      "baseUrl": "http://sidecar-host:3001",
      "services": ["health-api", "bank-api", "gov-api"],
      "description": "Local citizen services sidecar (relay-proxied)"
    }
  ]
}
```

**OTP routing** (relay-only): `/otp <service> <code>` sends OTP directly to the provider's `/v1/challenge/respond` endpoint (never to the LLM).
Control commands (including `/otp`) are rate-limited to 5 attempts per minute per user to reduce brute-force risk.

## Skills & Plugins

- Skills are folders with `SKILL.md`, discoverable from `~/.claude/skills` (user), `.claude/skills` (project),
  or bundled inside plugins. Use `allowed-tools` in SKILL.md frontmatter to scope tool access.
- Telclaude ships built-in skills in `.claude/skills`; the Docker entrypoint copies them to `/home/telclaude-skills/skills`.
- The user-level `CLAUDE.md` is stored in `/home/telclaude-skills/CLAUDE.md`. Project-level overrides live in `/workspace/.claude/CLAUDE.md`.
- Project-level skills are explicit: if a repo wants its own skills, add them under `/workspace/.claude/skills`.
- Plugins are the idiomatic distribution mechanism: plugin root contains `.claude-plugin/plugin.json` and optional
  `skills/`, `agents/`, `commands/`, or `hooks/` folders.
- To install plugins, add a marketplace (`/plugin marketplace add ./path`) and install with `/plugin install name@marketplace`.
  Team workflows can pin marketplaces/plugins in `.claude/settings.json` so installs happen automatically when the repo is trusted.
- **Private/local plugins**: while a plugin repo is private, add its repo root as a *local* marketplace path
  (the repo must contain `.claude-plugin/marketplace.json`), then install the plugin by name. Example:
  ` /plugin marketplace add /Users/you/MyProjects/my-local-services `
  then ` /plugin install my-local-services@my-local-services-marketplace `.

### Private Network Allowlist

For local services (Home Assistant, Plex, NAS, etc.), you can configure explicit private network endpoints:

```json
{
  "security": {
    "network": {
      "privateEndpoints": [
        {
          "label": "home-assistant",
          "host": "192.168.1.100",
          "ports": [8123],
          "description": "Home automation MCP server"
        },
        {
          "label": "homelab-subnet",
          "cidr": "192.168.1.0/24",
          "ports": [80, 443]
        }
      ]
    }
  }
}
```

**Security design** (per Gemini 2.5 Pro review):
- **Port enforcement**: Only listed ports are allowed (defaults to 80/443 if not specified)
- **Non-overridable blocks**: Metadata endpoints (169.254.169.254) and link-local remain ALWAYS blocked
- **All resolved IPs must match**: DNS returning multiple IPs requires ALL to be in allowlist
- **CIDR matching**: Uses ip-num library for robust IPv4/IPv6 handling

**CLI commands**:
```bash
telclaude network list                      # List configured endpoints
telclaude network add ha --host 192.168.1.100 --ports 8123
telclaude network remove ha
telclaude network test http://192.168.1.100:8123/api
```

## Credential Vault

The vault daemon is a sidecar service that stores credentials and injects them into HTTP requests transparently. Agents never see raw credentials.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ VAULT SIDECAR (no network*, Unix socket only)                   │
│                                                                 │
│  Credential Store (AES-256-GCM encrypted file)                  │
│  OAuth2 Token Refresh (caches access tokens in memory)          │
│  Protocol: newline-delimited JSON over Unix socket              │
└─────────────────────────────────────────────────────────────────┘
              │ Unix socket (~/.telclaude/vault.sock)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│ HTTP CREDENTIAL PROXY (relay, port 8792)                        │
│                                                                 │
│  Pattern: http://relay:8792/{host}/{path}                       │
│  Example: http://relay:8792/api.openai.com/v1/images/gen        │
│                                                                 │
│  1. Parse host from URL                                         │
│  2. Look up credential from vault                               │
│  3. Inject auth header (bearer/api-key/basic/oauth2)            │
│  4. Forward to https://{host}/{path}                            │
│  5. Stream response back                                        │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│ AGENT CONTAINER                                                 │
│                                                                 │
│  fetch("http://relay:8792/api.openai.com/v1/images/gen", {...}) │
│  Agent NEVER sees credentials                                   │
└─────────────────────────────────────────────────────────────────┘
```

*Note: OAuth2 token refresh requires outbound HTTP to token endpoints.

### Supported Credential Types

| Type | Auth Injection |
| --- | --- |
| `bearer` | `Authorization: Bearer {token}` |
| `api-key` | `{header}: {token}` (e.g., `X-API-Key`) |
| `basic` | `Authorization: Basic {base64(user:pass)}` |
| `query` | `?{param}={token}` |
| `oauth2` | Bearer with automatic token refresh |

### Security Properties

- **Credential isolation**: Vault has no network (except OAuth refresh); credentials never reach agent
- **Host allowlist**: Proxy only injects credentials for configured hosts
- **Path restrictions**: Optional `allowedPaths` regex per host prevents SSRF to unexpected endpoints
- **Rate limiting**: Per-host and per-credential limits prevent abuse
- **Encryption at rest**: AES-256-GCM with scrypt key derivation
- **Socket permissions**: 0600 (owner only); server verifies at startup, store enforces on each write
- **Request size limit**: 1MB max to prevent memory exhaustion
- **Upstream timeout**: 60s with AbortController to prevent hung connections

### CLI Commands

```bash
# Start vault daemon (requires VAULT_ENCRYPTION_KEY)
export VAULT_ENCRYPTION_KEY=$(openssl rand -base64 32)
telclaude vault-daemon

# Manage credentials
telclaude vault list
telclaude vault add http api.openai.com --type bearer --label "OpenAI"
telclaude vault add http api.anthropic.com --type api-key --header x-api-key
telclaude vault add http api.google.com --type oauth2 \
  --client-id xxx --token-endpoint https://oauth2.googleapis.com/token
telclaude vault remove http api.openai.com
telclaude vault test http api.openai.com

# OAuth2 authorization flow (browser-based, stores tokens in vault)
telclaude oauth authorize xtwitter          # Full PKCE flow for X/Twitter
telclaude oauth authorize xtwitter --no-browser  # Print URL instead of opening browser
telclaude oauth list                        # Show known services + vault status
telclaude oauth revoke xtwitter             # Remove credentials from vault
```

### Deployment Security

When allowing `localhost` or docker service names as targets:
- Ensure only authorized processes can reach the HTTP proxy (port 8792)
- Use network policies or firewall rules to restrict proxy access
- Only store credentials for hosts the agent legitimately needs

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
- **Identity linking**: `/link` codes generated via CLI; stored in SQLite; TTL 10 minutes.
- **First-time admin claim**: private chat only; TTL 5 minutes.
- **TOTP auth gate**: Periodic identity check when session expires (default: 4 hours).
- **Approvals**: Nonce-based confirmation for dangerous operations; TTL 5 minutes.
- **Emergency controls**: CLI-only `ban`/`unban`, `force-reauth`, `list-bans`.

## Observer & Fast Path
- Fast-path regex handles obvious safe/unsafe patterns.
- Observer uses security-gate skill via Claude Agent SDK.
- WARN/BLOCK may trigger approvals per tier rules.

## Persistence
- SQLite at `~/.telclaude/telclaude.db` stores approvals, rate limits, identity links, sessions, audit.
- Config split (Docker mode):
  - `telclaude.json` — policy config (providers, network, rate limits). Mounted to all containers.
  - `telclaude-private.json` — relay-only overrides (allowedChats, permissions, PII). Mounted to relay only.
  - Relay deep-merges private on top of policy via `TELCLAUDE_PRIVATE_CONFIG` env var.
  - Agents see only policy config, preventing secret/PII exposure.
  - Single-file setups remain supported (backward compatible).
- Native mode: single `~/.telclaude/telclaude.json` (no split needed).

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
- SDK sandbox disabled; relay + agent containers provide isolation.
- Firewall enforced in agent container (tool runner).
- Relay holds secrets and does not mount the workspace.
- TOTP daemon uses encrypted file backend.
- Read-only root FS, dropped caps.

### Native (Development)
- SDK sandbox enabled (bubblewrap/Seatbelt).
- TOTP daemon uses OS keychain.
- Native mode requires macOS 14+ or Linux with bubblewrap, socat, ripgrep on PATH.

## File Map
- `src/security/*` — pipeline, permissions, observer, approvals, rate limits.
- `src/sandbox/*` — mode detection, constants, SDK settings builder.
- `src/sdk/*` — Claude SDK integration and session manager.
- `src/telegram/*` — inbound/outbound bot wiring, private heartbeat, notification sanitizer.
- `src/social/*` — generic social services: handler, scheduler, identity, context, activity log.
- `src/social/backends/*` — per-service API clients (moltbook, xtwitter).
- `src/commands/*` — CLI commands.
- `.claude/skills/*` — skills auto-loaded by SDK.
