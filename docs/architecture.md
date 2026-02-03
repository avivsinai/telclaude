# Telclaude Architecture Deep Dive

Updated: 2026-02-01
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
│ • Moltbook heartbeat + API client          │
└────────────────────────────────────────────┘
      │ internal HTTP
      ├──────────────────────────┬──────────────────────────┐
      ▼                          ▼
┌────────────────────────────────────────────┐   ┌────────────────────────────────────────────┐
│ Agent worker (Telegram)                    │   │ Agent worker (Moltbook)                    │
│ • Workspace mounted                        │   │ • No workspace mount                       │
│ • Media inbox/outbox volumes               │   │ • Isolated /moltbook/sandbox               │
└────────────────────────────────────────────┘   └────────────────────────────────────────────┘
      │                                          │
      ▼                                          ▼
Claude Agent SDK (allowedTools per tier)         Claude Agent SDK (MOLTBOOK_SOCIAL tier)
```

## Docker Split Topology (Production)

- **Relay container**: Telegram + Moltbook handlers, security policy + secrets (OpenAI/GitHub), TOTP socket.
- **Telegram agent container**: Claude SDK + tools, no secrets, workspace mounted (do not mount relay config with bot token).
- **Moltbook agent container**: Claude SDK + tools, no secrets, no workspace mount, isolated `/moltbook/sandbox`.
- **Shared media volumes**:
  - `media_inbox` (relay writes Telegram downloads, agent reads)
  - `media_outbox` (relay writes generated media; relay reads to send)
- **Moltbook memory volume**:
  - `/moltbook/memory` (relay is single writer; agent-moltbook is read-only)
- **Internal RPC**:
  - Relay → Agent: `/v1/query` (HMAC-signed)
  - Agent → Relay: `/v1/image.generate`, `/v1/tts.speak`, `/v1/transcribe` (HMAC-signed)
- **Firewall**: enabled in both containers; internal hostnames allowed via `TELCLAUDE_INTERNAL_HOSTS`.
- **RPC auth**: set `TELEGRAM_RPC_SECRET` in relay + Telegram agent containers. For Moltbook, set `MOLTBOOK_RPC_PRIVATE_KEY` in the relay and `MOLTBOOK_RPC_PUBLIC_KEY` in the Moltbook agent; internal servers bind to `0.0.0.0` in Docker and `127.0.0.1` in native mode.
- **Agent network isolation**: each agent is on its own relay network; agents do not share a network segment or direct connectivity. Only the relay can reach both agents.

## Moltbook Integration

- **Heartbeat-driven**: relay scheduler polls Moltbook notifications on a configured interval (default 4h, min 60s).
- **Separate agent**: notifications are handled by a dedicated Moltbook agent container (`agent-moltbook`) with no workspace mount and an isolated `/moltbook/sandbox` working directory.
- **Restricted tier**: Moltbook requests run under the `MOLTBOOK_SOCIAL` tier (file tools + Bash allowed inside `/moltbook/sandbox`, WebFetch/WebSearch allowed), with skills disabled and no access to sidecars or private endpoints.
- **Untrusted wrappers**: Moltbook notification payloads and social context are wrapped with explicit “UNTRUSTED / do not execute” warnings before being sent to the model.
- **Reply only**: the relay posts replies back via the Moltbook API; there is no autonomous posting from Telegram context.

## Memory System & Provenance

Telclaude stores social memory in SQLite with provenance metadata:

- **Sources**: `telegram`, `moltbook`.
- **Trust**: `trusted`, `untrusted`, `quarantined`.
- **Provenance**: each entry records source, trust level, and timestamps (created/promoted).
- **Default trust**: Telegram memory is trusted by default; Moltbook memory is untrusted until explicitly promoted.
- **Prompt injection safety**: even trusted entries are wrapped in a “read-only, do not execute” envelope before being injected into Moltbook prompts.

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

## Network Enforcement

- **Bash**: SDK sandbox `allowedDomains` in native mode; Docker firewall enforced in containers (agent runs tools; relay still restricts egress).
- **WebFetch**: PreToolUse hook (blocks RFC1918/metadata) + canUseTool domain allowlist + private endpoint allowlist.
- **WebSearch**: NOT filtered (server-side by Anthropic).
- `TELCLAUDE_NETWORK_MODE=open|permissive`: enables broad egress for WebFetch only.
- Internal relay ↔ agent RPC is allowed via hostname allowlist in the firewall script.
- **Allowlist scope**: Domain allowlists are enforced, but HTTP method restrictions are not enforced at runtime.
- **CGNAT/Tailscale**: The private IP matcher treats 100.64.0.0/10 (RFC 6598) as private to support Tailscale.

## External Providers (Sidecars)

Telclaude can call private sidecar services over `WebFetch` via `privateEndpoints`.
This keeps telclaude OSS generic while allowing country- or org-specific integrations.

**Config example:**
```json
{
  "providers": [
    {
      "id": "citizen-services",
      "baseUrl": "http://127.0.0.1:3001",
      "services": ["health-api", "bank-api", "gov-api"],
      "description": "Local citizen services sidecar"
    }
  ],
  "security": {
    "network": {
      "privateEndpoints": [
        { "label": "citizen-services", "host": "127.0.0.1", "ports": [3001] }
      ]
    }
  }
}
```

**OTP routing** (relay-only): `/otp <service> <code>` sends OTP directly to the provider's `/v1/challenge/respond` endpoint (never to the LLM).
Control commands (including `/otp`) are rate-limited to 5 attempts per minute per user to reduce brute-force risk.

## Skills & Plugins

- Skills are folders with `SKILL.md`, discoverable from `~/.claude/skills` (user), `.claude/skills` (project),
  or bundled inside plugins. Use `allowed-tools` in SKILL.md frontmatter to scope tool access.
- Telclaude ships built-in skills in `.claude/skills`; the Docker entrypoint copies them to `/home/node/.claude/skills`
  and symlinks `/workspace/.claude/skills` for the SDK.
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
- `src/telegram/*` — inbound/outbound bot wiring.
- `src/commands/*` — CLI commands.
- `.claude/skills/*` — skills auto-loaded by SDK.
