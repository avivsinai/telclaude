# Google Services Sidecar — Design Document

**Date:** 2026-02-25
**Status:** Approved (Codex GO — 2026-02-25)
**Scope:** v1 — Gmail, Calendar, Drive, Contacts (read + smart actions)

## Problem

The private Telegram agent needs read-only access to personal Google services (Gmail, Calendar, Drive, Contacts), plus approval-gated smart actions (draft emails, create events). This must fit telclaude's security model: agents never see raw credentials, all API auth goes through the relay/vault boundary.

## Decision

Build a **custom thin REST sidecar** (`google-services`) using TypeScript + `googleapis` + `google-auth-library`. Follows the israel-services pattern (Fastify REST API, `/v1/fetch`, `/v1/health`, `/v1/schema`), but uses Google REST APIs instead of browser automation.

### Why custom over existing MCP servers

- workspace-mcp (taylorwilsdon) is Python, speaks MCP protocol (not REST), and exposes 100+ tools (attack surface)
- aaronsb's TypeScript MCP covers our 4 services but still speaks MCP, not our REST contract
- `googleapis` npm handles 90% of Google API complexity; we add ~500-800 lines for the REST server
- Full control over read/action separation and approval enforcement

### Why NOT:

- No MCP protocol bridging needed
- No Python dependency in our TypeScript stack
- No upstream churn risk from external MCP servers
- No 100+ tool attack surface to filter

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Agent (private persona, FULL_ACCESS tier)                    │
│                                                              │
│  telclaude provider-query \                                  │
│    --provider google --service gmail \                        │
│    --action search --params '{"q":"from:boss"}'              │
└──────────────────────────────────────────────────────────────┘
         │ relay-proxied CLI (existing pattern)
         ▼
┌──────────────────────────────────────────────────────────────┐
│ Relay                                                        │
│  • Routes to google-services sidecar via provider-proxy      │
│  • Generates x-approval-token for action-type requests       │
│  • Strips/stores attachments from responses                  │
│  • Audit logs all queries                                    │
│  • Rate limits per-user                                      │
└──────────────────────────────────────────────────────────────┘
         │ internal HTTP (Docker network)
         ▼
┌──────────────────────────────────────────────────────────────┐
│ google-services sidecar (NEW)                                │
│                                                              │
│  Fastify REST API                                            │
│  ├── POST /v1/fetch    — execute service action              │
│  ├── GET  /v1/health   — per-service health + token status   │
│  └── GET  /v1/schema   — action catalog for LLM discovery    │
│                                                              │
│  Service Handlers (TypeScript)                               │
│  ├── gmail.ts     — search, read, threads, labels, draft     │
│  ├── calendar.ts  — events, freebusy, calendars, create      │
│  ├── drive.ts     — search, list, metadata, download         │
│  └── contacts.ts  — search, list, get                        │
│                                                              │
│  Token Manager                                               │
│  └── Requests tokens from vault via Unix socket              │
│      Vault handles refresh + encrypted storage               │
└──────────────────────────────────────────────────────────────┘
         │ Unix socket (vault)           │ HTTPS
         ▼                               ▼
┌─────────────────────┐      googleapis.com
│ Vault Sidecar       │      (Gmail, Calendar,
│ (existing)          │       Drive, People APIs)
│                     │
│ google credentials: │
│ ├── clientId        │
│ ├── clientSecret    │
│ ├── refreshToken    │
│ ├── tokenEndpoint   │
│ └── scope           │
└─────────────────────┘
```

## Read vs. Action Separation

Every action is tagged as `read` or `action`:

```typescript
type ActionType = "read" | "action";

// Read — always allowed, no approval needed
{ service: "gmail",    action: "search",           type: "read" }
{ service: "gmail",    action: "read_message",     type: "read" }
{ service: "gmail",    action: "read_thread",      type: "read" }
{ service: "gmail",    action: "list_labels",      type: "read" }
{ service: "gmail",    action: "download_attachment", type: "read" }
{ service: "calendar", action: "list_events",      type: "read" }
{ service: "calendar", action: "search_events",    type: "read" }
{ service: "calendar", action: "get_event",        type: "read" }
{ service: "calendar", action: "freebusy",         type: "read" }
{ service: "calendar", action: "list_calendars",   type: "read" }
{ service: "drive",    action: "search",           type: "read" }
{ service: "drive",    action: "list_files",       type: "read" }
{ service: "drive",    action: "read_metadata",    type: "read" }
{ service: "drive",    action: "download",         type: "read" }
{ service: "drive",    action: "list_shared",      type: "read" }
{ service: "contacts", action: "search",           type: "read" }
{ service: "contacts", action: "list",             type: "read" }
{ service: "contacts", action: "get",              type: "read" }

// Action — requires x-approval-token from relay
{ service: "gmail",    action: "create_draft",     type: "action" }
{ service: "calendar", action: "create_event",     type: "action" }
```

**Enforcement:** The sidecar checks the `x-approval-token` header for action-type requests. Without a valid token, it returns `403 Approval Required`. The relay generates this token after the user approves via Telegram (`/approve <nonce>`).

### Approval Token Specification

The approval token is a signed, one-time-use, request-bound structure using Ed25519 (same signing infrastructure as vault session tokens).

**Wire format:** `v1.<claims_b64url>.<sig_b64url>`

Where:
- `claims_b64url` = base64url(JSON claims)
- `sig_b64url` = Ed25519 signature over `approval-v1\n<claims_b64url>`

**Claims (JSON):**
```json
{
  "ver": 1,
  "iss": "telclaude-vault",
  "aud": "google-services",
  "iat": 1767049500,
  "exp": 1767049800,
  "jti": "9f9c8d7e6b5a4c3d",
  "approvalNonce": "abc123ef",
  "actorUserId": "telegram:123456",
  "providerId": "google",
  "service": "gmail",
  "action": "create_draft",
  "paramsHash": "sha256:3f3b6f..."
}
```

**Claim validation rules:**
- `ver` must equal `1`
- `aud` must equal sidecar id (`google-services`)
- `exp - iat <= 300` (TTL max 5 minutes)
- `jti` unique per token (replay prevention)
- `service` + `action` must match request body
- `actorUserId` must match `x-actor-user-id` header
- `paramsHash` must match canonical request hash

**Canonical hash binding (prevents param substitution):**
```typescript
// Hash input object:
const hashInput = {
  service: request.service,
  action: request.action,
  params: request.params,
  actorUserId: headers["x-actor-user-id"],
};
// Algorithm: RFC 8785 (JCS) deterministic JSON serialization
// paramsHash = "sha256:" + hex(sha256(canonicalize(hashInput)))
```

**Vault API extension (option A — new `sign-payload` / `verify-payload` endpoints):**

The existing vault `sign-token` emits `v3:scope:sessionId:...` session tokens. Approval tokens have a different format (arbitrary claims + signature). Rather than overloading the session token format, add two new vault protocol messages:

```typescript
// Request: sign arbitrary payload with Ed25519 master key
{ type: "sign-payload", payload: "<claims_b64url>", prefix: "approval-v1" }
// Response: { type: "sign-payload", signature: "<sig_b64url>" }

// Request: verify payload signature
{ type: "verify-payload", payload: "<claims_b64url>", signature: "<sig_b64url>", prefix: "approval-v1" }
// Response: { type: "verify-payload", valid: true/false }
```

The `prefix` parameter ensures approval signatures cannot be confused with session token signatures (domain separation).

**Signing and verification path:**
1. Relay receives `/approve <nonce>` and consumes approval nonce (existing flow)
2. Relay computes `paramsHash`, builds claims JSON, base64url-encodes it
3. Relay calls vault `sign-payload` with the claims and `prefix: "approval-v1"`
4. Relay forwards request to sidecar with `x-approval-token: v1.<claims>.<sig>` header
4. Sidecar verifies signature using vault public key (cached at startup)
5. Sidecar validates all claims (ver, aud, exp, actor, service, action, paramsHash)
6. Sidecar atomically records `jti` as used before executing action
7. If `jti` already seen → reject as replay

**Replay storage:** SQLite at `/data/approval_jti.sqlite`:
```sql
CREATE TABLE used_approval_tokens (
  jti TEXT PRIMARY KEY,
  exp INTEGER NOT NULL,
  used_at INTEGER NOT NULL
);
-- Periodic cleanup: DELETE FROM used_approval_tokens WHERE exp < now()
```

**Failure codes:**
| Code | Error | Meaning |
|------|-------|---------|
| 403 | `approval_required` | Missing or malformed token |
| 403 | `approval_expired` | Token past TTL |
| 403 | `approval_mismatch` | Claim doesn't match request (actor/service/action/hash) |
| 409 | `approval_replayed` | `jti` already used |

**Logging:** Never log token or signature. Log only: `approvalNonce`, `jti` (first 8 chars), `actorUserId`, `service`, `action`, decision.

**Security properties:**
- One-time use (jti in SQLite, checked atomically before execution)
- Time-limited (5 min TTL, enforced at sidecar)
- Actor-bound (actorUserId claim)
- Request-bound (service + action + paramsHash with RFC 8785 canonicalization)
- Cryptographically signed (Ed25519, same keypair as session tokens)
- Cannot be forged by agent (signing key lives in vault, never exposed)

## OAuth2 Scopes

### Per-action scope mapping (exact URIs)

**Gmail:**
| Action | Scope |
|--------|-------|
| `search`, `read_message`, `read_thread`, `list_labels`, `download_attachment` | `gmail.readonly` |
| `create_draft` (action) | `gmail.compose` |

**Calendar:**
| Action | Scope |
|--------|-------|
| `list_events`, `search_events`, `get_event` | `calendar.events.readonly` |
| `list_calendars` | `calendar.calendarlist.readonly` |
| `freebusy` | `calendar.freebusy` |
| `create_event` (action, self-only) | `calendar.events.owned` |

**Drive:**
| Action | Scope |
|--------|-------|
| `search`, `list_files`, `read_metadata`, `list_shared` | `drive.metadata.readonly` |
| `download` | `drive.readonly` |

**Contacts:**
| Action | Scope |
|--------|-------|
| `search`, `list`, `get` | `contacts.readonly` |

### Consent bundles (incremental authorization)

| Bundle | Scopes | When Requested |
|--------|--------|----------------|
| `read_core` | `gmail.readonly`, `calendar.events.readonly`, `calendar.calendarlist.readonly`, `calendar.freebusy`, `drive.metadata.readonly`, `contacts.readonly` | Default (setup-google) |
| `read_plus_download` | `read_core` + `drive.readonly` | When agent first tries `drive.download` |
| `actions_v1` | `read_plus_download` + `gmail.compose` + `calendar.events.owned` | When agent first tries an action-type request |

**Notes:**
- `calendar.events.owned` (not `calendar.events`) — narrower scope, self-only events, no attendee mutation.
- `drive.metadata.readonly` for search/list (no content), `drive.readonly` only when file download is needed.
- For personal use (<100 users), no Google verification needed. Users click through "unverified app" warning during initial consent.

## Token Management (Vault-Backed)

### Setup flow

```
User runs: telclaude setup-google

1. CLI generates OAuth2 PKCE authorization URL
2. Opens browser → user logs into Google, grants consent
3. Google redirects to localhost callback with auth code
4. CLI exchanges code for access_token + refresh_token
5. CLI stores in vault via Unix socket:
   vault.store("oauth2", "googleapis.com", {
     type: "oauth2",
     clientId,
     clientSecret,
     refreshToken,
     tokenEndpoint: "https://oauth2.googleapis.com/token",
     scope: "<all scopes>"
   })
6. Vault encrypts at rest (AES-256-GCM)
```

### Runtime token flow

```
1. google-services sidecar receives /v1/fetch request
2. Calls vault: getToken("googleapis.com")
3. Vault checks cache → if expired, refreshes via Google token endpoint
4. Vault returns fresh access_token + expiresAt
5. Sidecar calls Google API with Authorization: Bearer <token>
6. Returns response to relay
```

### Token invalidation handling

Error taxonomy:

| Google Error | Classification | Sidecar Behavior | Relay Behavior |
|-------------|---------------|-------------------|----------------|
| `invalid_grant` (revoked/expired refresh) | **permanent** | Return `401 { error: "reauth_required" }` | Notify user via Telegram; health → `auth_expired` |
| `invalid_client` (client ID changed) | **permanent** | Return `401 { error: "config_invalid" }` | Alert admin; health → `config_error` |
| HTTP 5xx from Google token endpoint | **transient** | Retry with exponential backoff (3 attempts, 1s/2s/4s) | If all retries fail: `503 { error: "token_refresh_failed" }` |
| HTTP 429 (rate limited) | **transient** | Respect Retry-After header | Return `429` to relay; health tracks rate limit state |
| Network error to token endpoint | **transient** | Retry with backoff | `503 { error: "upstream_unreachable" }` |

Health state transitions:
- `ok` → `auth_expired`: on `invalid_grant` (sticky until re-auth)
- `ok` → `degraded`: on transient errors (auto-recovers)
- `degraded` → `ok`: on next successful request
- `auth_expired` → `ok`: on successful token refresh after re-auth

## Docker Deployment

### New container: google-services

```yaml
google-services:
  image: telclaude-google:latest
  networks:
    - relay-google        # relay ↔ google-services
    - google-egress       # google-services → googleapis.com
  volumes:
    - vault-socket:/run/vault:ro
    - google-data:/data   # health state, attachment cache
  environment:
    - TELCLAUDE_VAULT_SOCKET=/run/vault/vault.sock
    # NO Google secrets here — clientId/clientSecret live in vault only
  user: "1000:1000"
  read_only: true
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  tmpfs:
    - /tmp:size=64M
  healthcheck:
    test: ["CMD", "node", "-e", "fetch('http://localhost:3002/v1/health')"]
    interval: 30s
    timeout: 10s
  deploy:
    resources:
      limits:
        memory: 256M
```

### Image: ~200MB

```dockerfile
FROM node:22-bookworm-slim
# No Chromium, no Playwright, no Xvfb
# Just: Fastify + googleapis + google-auth-library
```

### Network isolation

| Network | Who | Direction |
|---------|-----|-----------|
| `relay-google` | relay, google-services | relay → sidecar |
| `google-egress` | google-services | sidecar → googleapis.com (iptables allowlist) |

Agent containers have NO access to google-services — must go through relay.

### Container count: 5 → 6

```
telclaude (relay) — existing
telclaude-agent (private) — existing
agent-social (social) — existing
totp — existing
vault — existing
google-services — NEW
```

## Relay Integration (Minimal Changes)

### 1. Provider config

```json
{
  "providers": [
    {
      "id": "google",
      "baseUrl": "http://google-services:3002",
      "services": ["gmail", "calendar", "drive", "contacts"]
    }
  ]
}
```

### 2. PreToolUse hook

Block direct WebFetch to `googleapis.com` — force `provider-query` route. Already generic in the existing hook; just need to add google-services to provider list.

### 3. Approval gate for actions

Extend existing approval flow with signed approval tokens (see "Approval Token Specification" above):
- Agent calls `provider-query --action create_draft --params '...'`
- Relay detects action type = "action" (by querying sidecar schema at startup)
- Relay sends Telegram: "Agent wants to create a Gmail draft to boss@company.com — Subject: Q3 Report. /approve ABC123"
- User replies `/approve ABC123`
- Relay signs approval token via vault (claims: actor + service + action + params_hash, 5min TTL)
- Relay forwards request to sidecar with `x-approval-token` header
- Sidecar verifies signature + all bindings before executing

### 4. Health aggregation

Include google-services health in relay's health endpoint.

## Action Catalog (v1)

### Gmail

| Action | Type | Params | Returns |
|--------|------|--------|---------|
| `search` | read | `q` (Gmail syntax), `maxResults`, `labelIds` | Message summaries |
| `read_message` | read | `messageId`, `format` (full/metadata/minimal) | Full message |
| `read_thread` | read | `threadId` | Thread with all messages |
| `list_labels` | read | — | All labels |
| `download_attachment` | read | `messageId`, `attachmentId` | Attachment data (signed URL) |
| `create_draft` | action | `to`, `subject`, `body`, `cc`, `bcc` | Draft ID |

### Calendar

| Action | Type | Params | Returns |
|--------|------|--------|---------|
| `list_events` | read | `calendarId`, `timeMin`, `timeMax`, `maxResults` | Events |
| `search_events` | read | `q`, `timeMin`, `timeMax` | Matching events |
| `get_event` | read | `calendarId`, `eventId` | Event details |
| `freebusy` | read | `timeMin`, `timeMax`, `calendarIds` | Availability |
| `list_calendars` | read | — | All calendars |
| `create_event` | action | `calendarId`, `summary`, `start`, `end`, `description`, `location` | Event ID (self-only, no attendees in v1) |

### Drive

| Action | Type | Params | Returns |
|--------|------|--------|---------|
| `search` | read | `q` (Drive syntax), `maxResults` | File summaries |
| `list_files` | read | `folderId`, `maxResults`, `orderBy` | Files in folder |
| `read_metadata` | read | `fileId` | File metadata |
| `download` | read | `fileId`, `mimeType` (for export) | File content (signed URL) |
| `list_shared` | read | `maxResults` | Shared-with-me files |

### Contacts

| Action | Type | Params | Returns |
|--------|------|--------|---------|
| `search` | read | `query`, `maxResults` | Matching contacts |
| `list` | read | `pageSize`, `pageToken` | All contacts |
| `get` | read | `resourceName` | Contact details |

## /v1/schema Response Format

```json
{
  "services": [
    {
      "id": "gmail",
      "name": "Gmail",
      "actions": [
        {
          "id": "search",
          "type": "read",
          "description": "Search emails using Gmail search syntax",
          "params": {
            "q": { "type": "string", "required": true, "description": "Gmail search query" },
            "maxResults": { "type": "number", "required": false, "default": 10 }
          }
        }
      ]
    }
  ]
}
```

## /v1/health Response Format

Default (coarse — no sensitive details):
```json
{
  "status": "healthy",
  "services": {
    "gmail": { "status": "ok" },
    "calendar": { "status": "ok" },
    "drive": { "status": "auth_expired" },
    "contacts": { "status": "ok" }
  },
  "token": { "status": "valid" },
  "uptimeSeconds": 86400
}
```

Debug mode (`?debug=true`, requires `x-actor-user-id` header):
```json
{
  "status": "degraded",
  "services": {
    "gmail": { "status": "ok", "lastSuccess": "2026-02-25T12:00:00Z", "failureCount": 0 },
    "calendar": { "status": "ok", "lastSuccess": "2026-02-25T12:00:00Z", "failureCount": 0 },
    "drive": { "status": "auth_expired", "lastAttempt": "2026-02-25T11:00:00Z", "failureCount": 3 },
    "contacts": { "status": "ok", "lastSuccess": "2026-02-25T12:00:00Z", "failureCount": 0 }
  },
  "token": {
    "status": "valid",
    "expiresAt": "2026-02-25T13:00:00Z",
    "scopes": ["gmail.readonly", "calendar.events.readonly", "drive.readonly", "contacts.readonly"]
  },
  "uptimeSeconds": 86400
}
```

## /v1/fetch Request/Response

### Request

```json
{
  "service": "gmail",
  "action": "search",
  "params": { "q": "from:boss subject:quarterly", "maxResults": 5 }
}
```

Headers:
- `x-actor-user-id: admin` (required)
- `x-approval-token: <token>` (required for action-type requests)

### Response

```json
{
  "status": "ok",
  "data": {
    "messages": [
      {
        "id": "18e5a1b2c3d",
        "threadId": "18e5a1b2c3d",
        "subject": "Q3 Quarterly Review",
        "from": "boss@company.com",
        "date": "2026-02-24T09:30:00Z",
        "snippet": "Please review the attached..."
      }
    ],
    "resultSizeEstimate": 5
  },
  "attachments": [],
  "confidence": 1.0
}
```

## Security Properties

| Property | How Enforced |
|----------|-------------|
| Agent never sees Google OAuth tokens | Vault holds tokens; sidecar requests via Unix socket |
| Agent cannot call Google APIs directly | PreToolUse hook blocks WebFetch to googleapis.com |
| Action requests require user approval | Ed25519-signed approval token: actor+service+action+params bound, one-time use, 5min TTL |
| Token refresh is automatic | Vault handles refresh; sidecar gets fresh token per request |
| Token revocation is detected | Vault returns token_invalid; health endpoint reports auth_expired |
| Attachments stored securely | Relay strips inline base64; stores in media outbox with signed URLs |
| Network isolation | Docker networks: agent cannot reach sidecar; sidecar can only reach googleapis.com |

## Dependencies (npm)

- `fastify` — REST server (already used in israel-services)
- `googleapis` — Google API client (handles API complexity)
- `google-auth-library` — OAuth2 token management (refresh, validation)
- `zod` — Request/response validation (already used project-wide)

## Out of Scope (v1)

- WhatsApp (no ToS-compliant read API)
- Notion, Slack, iCloud (future services, separate sidecars)
- Google Docs/Sheets/Slides content editing
- Gmail send (only draft creation)
- Multi-account support (single Google account per deployment)
- Web UI for OAuth flow (CLI only)

## References

- [israel-services sidecar](../../../workspace/telclaude/) — reference implementation for sidecar pattern
- [Gmail API scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)
- [Calendar API scopes](https://developers.google.com/workspace/calendar/api/auth)
- [Drive API scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [People API](https://developers.google.com/people/api/rest)
- [taylorwilsdon/google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp) — reference for tool catalog and read-only mode
- [c0webster/hardened-google-workspace-mcp](https://github.com/c0webster/hardened-google-workspace-mcp) — reference for security hardening patterns
