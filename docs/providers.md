# Provider Integration Guide

How external service providers (sidecars) integrate with telclaude. For the security rationale behind this design, see `architecture.md` (External Providers, Two-layer provider enforcement).

## Overview

Providers are separate containers that expose REST APIs for domain-specific services (Google Workspace, CRMs, proprietary APIs). They run as Docker sidecar containers alongside the relay and agent containers. Agents **never** call provider endpoints directly -- all requests route through the relay's provider proxy.

## Provider Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Agent Container                                                 │
│                                                                 │
│  telclaude provider-query --provider google                     │
│    --service gmail --action search --user-id tg:123             │
│                                                                 │
│  (Bash CLI command — routed to relay via HTTP)                  │
└─────────────────────────────────────────────────────────────────┘
              │ HTTP (relay proxy)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Relay Container                                                 │
│                                                                 │
│  Provider Proxy (src/relay/provider-proxy.ts)                   │
│  1. Resolve provider by ID                                      │
│  2. Inject x-actor-user-id header                               │
│  3. Forward to provider sidecar                                 │
│  4. Intercept attachments: strip base64, store, return refs     │
│  5. For action-type: mint approval token via vault keypair      │
│  6. Audit log the request                                       │
└─────────────────────────────────────────────────────────────────┘
              │ HTTP (internal network)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Provider Sidecar (e.g., google-services)                        │
│                                                                 │
│  Fastify REST server                                            │
│  GET  /v1/health — per-service health status                    │
│  GET  /v1/schema — action catalog for LLM discovery             │
│  POST /v1/fetch  — dispatch service action                      │
│                                                                 │
│  OAuth tokens read from vault via Unix socket                   │
└─────────────────────────────────────────────────────────────────┘
              │ HTTPS (external)
              ▼
          External API (googleapis.com, etc.)
```

**Enforcement is two-layer** (see `architecture.md`):
1. **Application layer**: PreToolUse hook blocks WebFetch URLs matching provider base URLs; agents must use the relay-proxied CLI command.
2. **Firewall layer**: Agent containers exclude provider hosts from iptables allowlist. Even `curl` from Bash is blocked at kernel level.

## Required Endpoints

Every provider sidecar must implement these three endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/health` | GET | Health check. Returns `{ status: "ok" }` or `{ status: "degraded", services: {...} }`. Used by `telclaude provider-health`. |
| `/v1/schema` | GET | Action catalog. Returns services array with actions, types, params. Used by the external-provider skill for LLM discovery. |
| `/v1/fetch` | POST | Dispatch a service action. Body: `{ service, action, params }`. Header: `x-actor-user-id`. |

Optional:
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/challenge/respond` | POST | OTP/2FA completion. Handled via Telegram `/otp`, never by the LLM. |

## Adding a New Provider

### 1. Define the sidecar

Create a Fastify REST server. The Google Services sidecar (`src/google-services/`) is the canonical reference:

```
src/your-provider/
  server.ts       — Fastify routes: /v1/health, /v1/schema, /v1/fetch
  actions.ts      — Action registry (id, service, type, description, params, scope)
  types.ts        — Zod schemas for request/response
  config.ts       — Environment-based config (port, vault socket, data dir)
  health.ts       — Per-service health state machine
  token-manager.ts — OAuth token retrieval from vault socket
  handlers/       — Per-service dispatch (one file per service)
  index.ts        — Entry point
```

### 2. Action registry

Define actions as `ActionDefinition` objects with two types:

| Type | Behavior | Approval Required |
|------|----------|-------------------|
| `read` | Read-only queries (search, list, get). No side effects. | No |
| `action` | Mutating operations (create, update, delete). | Yes (Ed25519-signed approval token) |

Each action specifies:
- `id` — Unique within service (e.g., `search`, `create_draft`)
- `service` — Service identifier (e.g., `gmail`, `calendar`)
- `type` — `read` or `action`
- `description` — Human/agent-readable description
- `params` — Parameter schema (type, required, description, default)
- `scope` — Required OAuth scope

### 3. Approval flow (for action-type operations)

Action-type requests require an Ed25519-signed approval token:

1. Agent calls `telclaude provider-query` for an action-type operation.
2. Relay detects `type: "action"` and returns `{ status: "error", errorCode: "APPROVAL_REQUIRED", approvalNonce: "<nonce>" }`.
3. Relay sends approval request to operator via Telegram (`/approve <nonce>` or `/deny <nonce>`).
4. On approval, relay mints a signed token binding: service, action, params hash, actor, expiry.
5. Agent retries with the approval token. Provider verifies signature, checks JTI replay store, validates params hash.

Token properties:
- Ed25519 signature (vault keypair)
- 5-minute TTL
- JTI replay protection (SQLite store with automatic cleanup)
- Params hash binding (SHA-256 of canonical JSON) prevents token reuse for different operations

### 4. Docker integration

Add the sidecar to `docker/docker-compose.yml`:

```yaml
your-provider:
  build:
    context: ..
    dockerfile: docker/Dockerfile.your-provider
  image: telclaude-your-provider:latest
  container_name: telclaude-your-provider
  environment:
    - PORT=3003
    - TELCLAUDE_VAULT_SOCKET=/run/vault/vault.sock
    - DATA_DIR=/data
  volumes:
    - your-provider-data:/data:rw
    - vault-socket:/run/vault:ro     # Shared vault socket for OAuth tokens
  networks:
    - relay-your-provider-net        # Internal only (relay <-> provider)
    - your-provider-egress           # Outbound to external API
  cap_drop: [ALL]
  read_only: true
  healthcheck:
    test: ["CMD", "node", "-e", "fetch('http://localhost:3003/v1/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"]
```

Network isolation:
- Create an **internal** bridge network for relay-to-provider communication.
- Create a separate **egress** network for outbound API calls.
- Add the relay to the internal network.
- Add the provider container name to `TELCLAUDE_INTERNAL_HOSTS`.

### 5. Relay configuration

Add the provider to `telclaude.json`:

```json
{
  "providers": [
    {
      "id": "your-provider",
      "baseUrl": "http://your-provider:3003",
      "services": ["service-a", "service-b"],
      "description": "Human/agent-readable description of what this provider does"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique provider identifier (used in CLI `--provider` flag) |
| `baseUrl` | string | yes | Internal URL (`http://<container-name>:<port>`) |
| `services` | string[] | yes | List of service identifiers this provider handles |
| `description` | string | yes | Human/agent-readable description |

The PreToolUse hook automatically blocks direct WebFetch to provider base URLs, and `TELCLAUDE_FIREWALL_SKIP_PROVIDERS=1` on agent containers excludes provider hosts from the firewall allowlist.

### 6. Skill injection

The external-provider skill auto-discovers providers:

1. On relay startup, `refreshExternalProviderSkill()` fetches `/v1/schema` from each configured provider.
2. A minimal summary (IDs + URLs + service lists) is cached and injected into agent system prompts via `<available-providers>` tags.
3. Full schema is written to the skill's `references/provider-schema.md` for detailed LLM tool generation.

When the agent sees `<available-providers>`, it uses the external-provider skill to query providers via `telclaude provider-query`.

## Reference Implementation: Google Services

The Google Services sidecar (`src/google-services/`) demonstrates the full pattern:

**4 services, 20 actions:**

| Service | Actions | Types |
|---------|---------|-------|
| Gmail | search, read_message, read_thread, list_labels, download_attachment, create_draft | 5 read, 1 action |
| Calendar | list_events, search_events, get_event, freebusy, list_calendars, create_event | 5 read, 1 action |
| Drive | search, list_files, read_metadata, download, list_shared | 5 read |
| Contacts | search, list, get | 3 read |

**Key implementation files:**
- `src/google-services/actions.ts` — Full action registry with param schemas and OAuth scopes
- `src/google-services/server.ts` — Fastify routes (/v1/health, /v1/schema, /v1/fetch)
- `src/google-services/approval.ts` — Ed25519 token verification + JTI replay store
- `src/google-services/token-manager.ts` — OAuth token retrieval from vault socket
- `src/google-services/handlers/` — Per-service dispatch (gmail.ts, calendar.ts, drive.ts, contacts.ts)

**Setup:** `telclaude setup-google` configures Google OAuth credentials in the vault.

## CLI Commands

| Command | Description |
|---------|-------------|
| `telclaude provider-query --provider <id> --service <svc> --action <act> --user-id <uid>` | Query a provider action |
| `telclaude provider-health [provider-id]` | Check provider health status |
| `telclaude setup-google` | Configure Google OAuth credentials |
