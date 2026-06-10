# Provider Integration Guide

How external service providers (sidecars) integrate with telclaude. For the security rationale behind this design, see `architecture.md` (External Providers, Two-layer provider enforcement).

## Overview

Providers are separate containers that expose REST APIs for domain-specific services (Google Workspace, CRMs, proprietary APIs). They run as Docker sidecar containers alongside the relay. Hermes and delegated runtimes **never** call provider endpoints directly -- all requests route through the relay's provider proxy or served-MCP bridge.

## Provider Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Contained Hermes Runtime                                        │
│                                                                 │
│  tc_provider_read / tc_provider_prepare_write                   │
│  tc_provider_execute_write                                      │
│                                                                 │
│  (served MCP call — scoped by relay authority handle)           │
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
1. **Application layer**: Hermes only receives provider capability through relay-owned served-MCP tools bound to an authority handle; it cannot choose provider scope or call provider URLs directly.
2. **Firewall layer**: contained runtime networks deny direct provider reachability. Even a shell escape cannot reach provider hosts without crossing the relay.

## Two Relay-Side Consumers, One Sidecar Contract

Provider sidecars are runtime-agnostic. The same `/v1/health`, `/v1/schema`, and `/v1/fetch` contract serves relay-side consumers without exposing provider URLs or credentials to Hermes:

1. **Operator/admin CLI path** — trusted operator tooling issues `telclaude providers ...`, and the relay's provider proxy (`src/relay/provider-proxy.ts`, `proxyProviderRequest`) forwards to `/v1/fetch` with `x-actor-user-id`.
2. **Hermes MCP path** — the contained Hermes runtime never calls providers directly. It calls relay-owned served-MCP tools (`tc_provider_read`, `tc_provider_prepare_write`, `tc_provider_execute_write`) on the relay-internal live MCP server. Those tools resolve through `resolveTelclaudeProviderOperation` and reuse the **same** `proxyProviderRequest` / `/v1/fetch` proxy. Writes are staged in a two-phase side-effect ledger (`src/hermes/mcp/side-effect-ledger.ts`) — `prepare` → human approval → `execute`. At execute time the relay mints a per-request sidecar approval token and forwards it to `/v1/fetch`, so the sidecar's verification logic is identical.

The implications for a provider author: implement the sidecar contract once. Read actions execute immediately through the relay. Hermes ledger execution arrives with `approvalMode: "preapproved-ledger"` and a relay-minted sidecar token at execute time. Provider scoping is enforced relay-side (`authority.providerScopes` in `src/hermes/mcp/bridge.ts`), not in the sidecar.

## Required Endpoints

Every provider sidecar must implement these three endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/health` | GET | Health check. Returns `{ status: "ok" }` or `{ status: "degraded", services: {...} }`. Used by `telclaude providers doctor`. |
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

1. Hermes calls `tc_provider_prepare_write` for an action-type operation, or an operator uses the trusted provider CLI path.
2. Relay detects `type: "action"` and returns `{ status: "error", errorCode: "approval_required", approvalNonce: "<nonce>" }`.
3. Relay sends approval request to operator via Telegram (`/approve <nonce>` or `/deny <nonce>`).
4. On approval, relay mints a signed token binding: service, action, params hash, actor, expiry.
5. The relay executes with the approval token. Provider verifies signature, checks JTI replay store, validates params hash.

Token properties:
- Ed25519 signature (vault keypair)
- 5-minute TTL
- JTI replay protection (SQLite store with automatic cleanup)
- Params hash binding (SHA-256 of canonical JSON) prevents token reuse for different operations

The sidecar should reject unsigned action attempts with `approval_required`; the relay obtains approval and sends `x-approval-token` only after the action is bound to an approved ledger record. The token verification logic is unchanged across operator and Hermes-originated actions.

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

For built-in setups, prefer the CLI:

```bash
telclaude providers setup google --base-url http://google-services:3002
```

That command:
- stores OAuth credentials in the vault
- registers the provider in `telclaude.json`
- adds the matching private-endpoint allowlist entry
- runs `telclaude providers doctor google`

If you are wiring a provider manually, treat the raw config and private-endpoint steps below as the escape hatch.

Add the provider to `telclaude.json`:

**Allowlist the provider host as a private endpoint first.** `validateProviderBaseUrl` (`src/providers/provider-validation.ts`) refuses any provider whose `baseUrl` is not matched by `security.network.privateEndpoints`. Run:

```bash
telclaude dev network add your-provider \
  --host your-provider \
  --ports 3003
```

(or edit `security.network.privateEndpoints` directly). Without this step, provider validation fails at startup with `No private endpoints configured. Configure a provider via \`telclaude providers add <id>\`.` even when the sidecar itself is healthy.

Then add the provider entry itself:

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
| `id` | string | yes | Unique provider identifier (used by `telclaude providers ...` commands) |
| `baseUrl` | string | yes | Internal URL (`http://<container-name>:<port>`) |
| `services` | string[] | yes | List of service identifiers this provider handles |
| `description` | string | yes | Human/agent-readable description |

Hermes provider access is only through served-MCP tools. The contained network denies direct provider reachability, and the relay firewall keeps provider hosts outside general runtime egress.

The provider host must also be allowlisted under `security.network.privateEndpoints`. Example:

```json
{
  "security": {
    "network": {
      "privateEndpoints": [
        {
          "label": "provider-your-provider",
          "host": "your-provider",
          "ports": [3003],
          "description": "Your Provider sidecar"
        }
      ]
    }
  }
}
```

### 6. Skill injection

The external-provider skill auto-discovers providers:

1. On relay startup, `refreshExternalProviderSkill()` fetches `/v1/schema` from each configured provider.
2. A minimal summary (IDs + URLs + service lists) is cached and injected into agent system prompts via `<available-providers>` tags.
3. Full schema is written to the skill's `references/provider-schema.md` for detailed LLM tool generation.

When the agent sees `<available-providers>`, it uses the external-provider skill to query providers via `telclaude providers query`.

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

**Setup:** `telclaude providers setup google --base-url http://google-services:3002` configures Google OAuth, provider config, and the network allowlist in one flow.

## CLI Commands

| Command | Description |
|---------|-------------|
| `telclaude providers init <id> [--services <csv>]` | Scaffold a provider sidecar under `src/<id>-services/` and `docker/Dockerfile.<id>` without mutating config |
| `telclaude providers list` | List configured providers |
| `telclaude providers add <id> --base-url <url> --services <csv>` | Add a custom provider and private endpoint allowlist entry |
| `telclaude providers edit <id> --base-url <url> --services <csv>` | Edit an existing provider and refresh runtime skill state |
| `telclaude providers remove <id>` | Remove provider config and its matching private endpoint |
| `telclaude providers refresh` | Refresh schema-derived runtime skill state |
| `telclaude providers schema [id]` | Fetch provider schema for one provider or all configured providers |
| `telclaude providers query <id> <svc> <act> [--user-id <uid>]` | Query a provider action |
| `telclaude providers doctor [id]` | Run provider health, schema, network, and OAuth checks |
| `telclaude providers setup google --base-url <url>` | Configure Google OAuth credentials and finish integration |
