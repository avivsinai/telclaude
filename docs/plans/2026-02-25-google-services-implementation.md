# Google Services Sidecar — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Google-services sidecar (Gmail, Calendar, Drive, Contacts) with vault-backed tokens and approval-gated actions.

**Architecture:** Fastify REST sidecar (`/v1/fetch`, `/v1/health`, `/v1/schema`) using `googleapis` npm. Vault holds OAuth tokens. Relay proxies requests. Agent never sees credentials. Ed25519-signed approval tokens for write actions.

**Tech Stack:** TypeScript, Fastify, googleapis, google-auth-library, Zod, SQLite (better-sqlite3), Vitest

**Design doc:** `docs/plans/2026-02-25-google-services-sidecar-design.md`

---

## Phase 1: Vault Extension — sign-payload / verify-payload

The vault needs two new protocol messages for signing approval token claims. This is the foundation everything else depends on.

### Task 1: Vault protocol schemas

**Files:**
- Modify: `src/vault-daemon/protocol.ts`
- Test: `tests/vault-daemon/protocol.test.ts`

**Step 1: Write failing test for new request schemas**

Add to `tests/vault-daemon/protocol.test.ts`:

```typescript
describe("sign-payload request", () => {
  it("accepts valid sign-payload request", () => {
    const result = VaultRequestSchema.safeParse({
      type: "sign-payload",
      payload: "eyJhbGciOiJFZDI1NTE5In0",
      prefix: "approval-v1",
    });
    expect(result.success).toBe(true);
  });

  it("rejects sign-payload without prefix", () => {
    const result = VaultRequestSchema.safeParse({
      type: "sign-payload",
      payload: "eyJhbGciOiJFZDI1NTE5In0",
    });
    expect(result.success).toBe(false);
  });
});

describe("verify-payload request", () => {
  it("accepts valid verify-payload request", () => {
    const result = VaultRequestSchema.safeParse({
      type: "verify-payload",
      payload: "eyJhbGciOiJFZDI1NTE5In0",
      signature: "c2lnbmF0dXJl",
      prefix: "approval-v1",
    });
    expect(result.success).toBe(true);
  });
});
```

**Step 2: Run test to verify it fails**

Run: `pnpm vitest run tests/vault-daemon/protocol.test.ts`
Expected: FAIL — `sign-payload` not in discriminated union

**Step 3: Add schemas to protocol.ts**

In `src/vault-daemon/protocol.ts`, add request schemas before the `VaultRequestSchema` discriminatedUnion:

```typescript
const SignPayloadRequestSchema = z.object({
  type: z.literal("sign-payload"),
  payload: z.string().min(1),
  prefix: z.string().min(1),
});

const VerifyPayloadRequestSchema = z.object({
  type: z.literal("verify-payload"),
  payload: z.string().min(1),
  signature: z.string().min(1),
  prefix: z.string().min(1),
});
```

Add them to `VaultRequestSchema` discriminatedUnion. Add response schemas:

```typescript
const SignPayloadResponseSchema = z.object({
  type: z.literal("sign-payload"),
  signature: z.string(),
});

const VerifyPayloadResponseSchema = z.object({
  type: z.literal("verify-payload"),
  valid: z.boolean(),
});
```

Add to `VaultResponseSchema`. Export types.

**Step 4: Run test to verify it passes**

Run: `pnpm vitest run tests/vault-daemon/protocol.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/vault-daemon/protocol.ts tests/vault-daemon/protocol.test.ts
git commit -m "feat(vault): add sign-payload/verify-payload protocol schemas"
```

---

### Task 2: Vault server handlers for sign-payload / verify-payload

**Files:**
- Modify: `src/vault-daemon/server.ts`
- Test: `tests/vault-daemon/server.test.ts` (create if needed)

**Step 1: Write failing test**

```typescript
import { describe, it, expect } from "vitest";
// Test will use the vault server's handleRequest function directly

describe("sign-payload handler", () => {
  it("signs payload with domain-separated prefix", async () => {
    // Setup: ensure signing keys exist
    const signResult = await handleRequest({
      type: "sign-payload",
      payload: "dGVzdF9wYXlsb2Fk", // base64url("test_payload")
      prefix: "approval-v1",
    });
    expect(signResult.type).toBe("sign-payload");
    expect(signResult.signature).toBeDefined();
    expect(typeof signResult.signature).toBe("string");
  });
});

describe("verify-payload handler", () => {
  it("verifies valid signature", async () => {
    const signed = await handleRequest({
      type: "sign-payload",
      payload: "dGVzdA",
      prefix: "test-prefix",
    });
    const verified = await handleRequest({
      type: "verify-payload",
      payload: "dGVzdA",
      signature: signed.signature,
      prefix: "test-prefix",
    });
    expect(verified.type).toBe("verify-payload");
    expect(verified.valid).toBe(true);
  });

  it("rejects signature with wrong prefix (domain separation)", async () => {
    const signed = await handleRequest({
      type: "sign-payload",
      payload: "dGVzdA",
      prefix: "approval-v1",
    });
    const verified = await handleRequest({
      type: "verify-payload",
      payload: "dGVzdA",
      signature: signed.signature,
      prefix: "different-prefix",
    });
    expect(verified.valid).toBe(false);
  });
});
```

**Step 2: Run test — expect FAIL**

Run: `pnpm vitest run tests/vault-daemon/server.test.ts`

**Step 3: Implement handlers in server.ts**

In `handleRequest()` switch statement, add:

```typescript
case "sign-payload": {
  const keys = await getOrCreateSigningKeys();
  // Domain separation: sign "prefix\npayload" not just payload
  const message = `${request.prefix}\n${request.payload}`;
  const signature = signTokenPayload(keys.privateKey, message);
  return { type: "sign-payload", signature };
}

case "verify-payload": {
  const keys = await getOrCreateSigningKeys();
  const message = `${request.prefix}\n${request.payload}`;
  const valid = verifyTokenSignature(keys.publicKey, message, request.signature);
  return { type: "verify-payload", valid };
}
```

**Step 4: Run test — expect PASS**

Run: `pnpm vitest run tests/vault-daemon/server.test.ts`

**Step 5: Commit**

```bash
git add src/vault-daemon/server.ts tests/vault-daemon/server.test.ts
git commit -m "feat(vault): implement sign-payload/verify-payload handlers"
```

---

### Task 3: Vault client methods

**Files:**
- Modify: `src/vault-daemon/client.ts`
- Modify: `src/vault-daemon/index.ts` (re-export)

**Step 1: Add client methods**

In `src/vault-daemon/client.ts`, add to the VaultClient class:

```typescript
async signPayload(payload: string, prefix: string): Promise<{ ok: true; signature: string } | { ok: false; error: string }> {
  const response = await this.send({ type: "sign-payload", payload, prefix });
  if (response.type === "sign-payload") {
    return { ok: true, signature: response.signature };
  }
  return { ok: false, error: response.error ?? "Unknown error" };
}

async verifyPayload(payload: string, signature: string, prefix: string): Promise<{ ok: true; valid: boolean } | { ok: false; error: string }> {
  const response = await this.send({ type: "verify-payload", payload, signature, prefix });
  if (response.type === "verify-payload") {
    return { ok: true, valid: response.valid };
  }
  return { ok: false, error: response.error ?? "Unknown error" };
}
```

Re-export from `src/vault-daemon/index.ts` if needed.

**Step 2: Run typecheck**

Run: `pnpm typecheck`
Expected: PASS

**Step 3: Commit**

```bash
git add src/vault-daemon/client.ts src/vault-daemon/index.ts
git commit -m "feat(vault): add signPayload/verifyPayload client methods"
```

---

## Phase 2: OAuth Registry — Add Google Service

### Task 4: Register Google in OAuth registry

**Files:**
- Modify: `src/oauth/registry.ts`

**Step 1: Add Google service definition**

Add to the `SERVICES` array in `src/oauth/registry.ts`:

```typescript
{
  id: "google",
  displayName: "Google",
  authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenEndpoint: "https://oauth2.googleapis.com/token",
  defaultScopes: [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
    "https://www.googleapis.com/auth/calendar.freebusy",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/contacts.readonly",
  ],
  confidentialClient: true,
  vaultTarget: "googleapis.com",
  vaultLabel: "Google OAuth2",
  userIdEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
  userIdJsonPath: "email",
},
```

**Step 2: Run typecheck + existing tests**

Run: `pnpm typecheck && pnpm vitest run tests/oauth/`
Expected: PASS

**Step 3: Commit**

```bash
git add src/oauth/registry.ts
git commit -m "feat(oauth): register Google service in OAuth registry"
```

---

### Task 5: CLI setup-google command

**Files:**
- Create: `src/commands/setup-google.ts`
- Modify: `src/cli/program.ts` (register command)

**Step 1: Create setup-google command**

Model after `src/commands/setup-openai.ts`. The command should:
1. Prompt for Google Cloud `client_id` and `client_secret` (from Google Cloud Console)
2. Store them temporarily, then run OAuth2 PKCE flow via `src/oauth/flow.ts`
3. Store the resulting credentials in vault as `oauth2` type with target `googleapis.com`
4. Support `--delete`, `--show`, `--check` flags
5. Support `--scopes` flag for incremental authorization (default: `read_core`)

```typescript
// src/commands/setup-google.ts
import { Command } from "commander";
import { authorize } from "../oauth/flow.js";
import { getService } from "../oauth/registry.js";
import { getVaultClient } from "../vault-daemon/client.js";

export function registerSetupGoogleCommand(program: Command): void {
  program
    .command("setup-google")
    .description("Configure Google OAuth2 credentials for Gmail, Calendar, Drive, Contacts")
    .option("--delete", "Remove stored Google credentials")
    .option("--show", "Show current Google auth status")
    .option("--check", "Verify Google credentials are working")
    .option("--scopes <bundle>", "Scope bundle: read_core, read_plus_download, actions_v1", "read_core")
    .action(async (opts) => {
      // Implementation follows setup-openai.ts pattern
    });
}
```

**Step 2: Register in CLI program**

In `src/cli/program.ts`, import and call `registerSetupGoogleCommand(program)`.

**Step 3: Run typecheck**

Run: `pnpm typecheck`

**Step 4: Commit**

```bash
git add src/commands/setup-google.ts src/cli/program.ts
git commit -m "feat(cli): add setup-google OAuth2 command"
```

---

## Phase 3: Google-Services Sidecar — Core

This is the main new package. Create it as a subdirectory: `src/google-services/`.

### Task 6: Sidecar project scaffold

**Files:**
- Create: `src/google-services/index.ts` (entry point)
- Create: `src/google-services/config.ts` (env vars + validation)
- Create: `src/google-services/types.ts` (shared types)

**Step 1: Create types.ts with Zod schemas**

```typescript
// src/google-services/types.ts
import { z } from "zod";

export const ActionType = z.enum(["read", "action"]);
export type ActionType = z.infer<typeof ActionType>;

export const ServiceId = z.enum(["gmail", "calendar", "drive", "contacts"]);
export type ServiceId = z.infer<typeof ServiceId>;

export const FetchRequestSchema = z.object({
  service: ServiceId,
  action: z.string().min(1),
  params: z.record(z.unknown()).default({}),
});
export type FetchRequest = z.infer<typeof FetchRequestSchema>;

export const FetchResponseSchema = z.object({
  status: z.enum(["ok", "error"]),
  data: z.unknown().optional(),
  error: z.string().optional(),
  attachments: z.array(z.unknown()).default([]),
  confidence: z.number().default(1.0),
});

export interface ActionDefinition {
  id: string;
  service: ServiceId;
  type: ActionType;
  description: string;
  params: Record<string, { type: string; required: boolean; description: string; default?: unknown }>;
  scope: string;
}

export const HealthStatus = z.enum(["ok", "degraded", "auth_expired", "config_error"]);
```

**Step 2: Create config.ts**

```typescript
// src/google-services/config.ts
import { z } from "zod";

const ConfigSchema = z.object({
  port: z.coerce.number().default(3002),
  vaultSocketPath: z.string().default("/run/vault/vault.sock"),
  dataDir: z.string().default("/data"),
  sidecarId: z.string().default("google-services"),
});

export function loadConfig() {
  return ConfigSchema.parse({
    port: process.env.PORT,
    vaultSocketPath: process.env.TELCLAUDE_VAULT_SOCKET,
    dataDir: process.env.DATA_DIR,
  });
}
export type Config = ReturnType<typeof loadConfig>;
```

**Step 3: Run typecheck**

Run: `pnpm typecheck`

**Step 4: Commit**

```bash
git add src/google-services/
git commit -m "feat(google): scaffold sidecar types and config"
```

---

### Task 7: Action registry

**Files:**
- Create: `src/google-services/actions.ts`
- Test: `tests/google-services/actions.test.ts`

**Step 1: Write test**

```typescript
import { describe, it, expect } from "vitest";
import { getAction, getActionsForService, isActionType } from "../src/google-services/actions.js";

describe("action registry", () => {
  it("finds gmail search action", () => {
    const action = getAction("gmail", "search");
    expect(action).toBeDefined();
    expect(action!.type).toBe("read");
  });

  it("returns undefined for unknown action", () => {
    expect(getAction("gmail", "nonexistent")).toBeUndefined();
  });

  it("identifies action types correctly", () => {
    expect(isActionType("gmail", "create_draft")).toBe("action");
    expect(isActionType("gmail", "search")).toBe("read");
  });

  it("lists all gmail actions", () => {
    const actions = getActionsForService("gmail");
    expect(actions.length).toBeGreaterThan(0);
    expect(actions.some(a => a.id === "search")).toBe(true);
  });
});
```

**Step 2: Run test — expect FAIL**

**Step 3: Implement actions.ts**

Define the complete action registry from the design doc's action catalog. Every action from the 4 services with their type, params, and required scope.

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```bash
git add src/google-services/actions.ts tests/google-services/actions.test.ts
git commit -m "feat(google): action registry with read/action type tagging"
```

---

### Task 8: Approval token verification

**Files:**
- Create: `src/google-services/approval.ts`
- Test: `tests/google-services/approval.test.ts`

**Step 1: Write tests**

```typescript
describe("approval token verification", () => {
  it("rejects missing token for action-type requests", () => { ... });
  it("rejects expired token", () => { ... });
  it("rejects token with wrong service", () => { ... });
  it("rejects token with wrong action", () => { ... });
  it("rejects token with wrong params hash", () => { ... });
  it("rejects token with wrong actor", () => { ... });
  it("rejects replayed token (same jti)", () => { ... });
  it("accepts valid token for action request", () => { ... });
  it("allows read requests without token", () => { ... });
});
```

**Step 2: Implement approval.ts**

Key components:
- `canonicalHash(request)` — RFC 8785 JSON canonicalization + SHA-256
- `verifyApprovalToken(token, request, headers, vaultPublicKey)` — 7-step verification
- `JtiStore` class — SQLite-backed replay prevention (`/data/approval_jti.sqlite`)
- Token parsing: split `v1.<claims>.<sig>`, decode claims, validate structure

Use `better-sqlite3` for the JTI store (synchronous, fast, no async overhead).

**Step 3: Run tests — expect PASS**

**Step 4: Commit**

```bash
git add src/google-services/approval.ts tests/google-services/approval.test.ts
git commit -m "feat(google): approval token verification with replay prevention"
```

---

### Task 9: Token manager (vault client wrapper)

**Files:**
- Create: `src/google-services/token-manager.ts`
- Test: `tests/google-services/token-manager.test.ts`

Thin wrapper around vault client that:
1. Calls `vault.getToken("googleapis.com")` to get fresh access token
2. Handles error classification (invalid_grant vs transient)
3. Tracks health state per-service
4. Caches vault public key (for approval token verification)

**Commit message:** `feat(google): token manager with vault integration and error taxonomy`

---

### Task 10: Health store

**Files:**
- Create: `src/google-services/health.ts`
- Test: `tests/google-services/health.test.ts`

State machine: `ok` ↔ `degraded`, `ok` → `auth_expired` (sticky). Per-service tracking (lastSuccess, failureCount, lastAttempt). Coarse vs debug response formatting.

**Commit message:** `feat(google): health store with per-service state machine`

---

## Phase 4: Service Handlers

Each handler translates `/v1/fetch` requests into Google API calls using the `googleapis` npm package.

### Task 11: Gmail handler

**Files:**
- Create: `src/google-services/handlers/gmail.ts`
- Test: `tests/google-services/handlers/gmail.test.ts`

Actions: `search`, `read_message`, `read_thread`, `list_labels`, `download_attachment`, `create_draft`

Use `google.gmail({ version: "v1", auth: oauthClient })`. Each action is a function that:
1. Validates params with Zod
2. Calls the appropriate Gmail API method
3. Transforms response to our schema
4. Returns attachments metadata (relay handles storage)

**Commit message:** `feat(google): Gmail handler — search, read, threads, labels, draft`

---

### Task 12: Calendar handler

**Files:**
- Create: `src/google-services/handlers/calendar.ts`
- Test: `tests/google-services/handlers/calendar.test.ts`

Actions: `list_events`, `search_events`, `get_event`, `freebusy`, `list_calendars`, `create_event`

Use `google.calendar({ version: "v3", auth: oauthClient })`.

**Commit message:** `feat(google): Calendar handler — events, freebusy, create`

---

### Task 13: Drive handler

**Files:**
- Create: `src/google-services/handlers/drive.ts`
- Test: `tests/google-services/handlers/drive.test.ts`

Actions: `search`, `list_files`, `read_metadata`, `download`, `list_shared`

Use `google.drive({ version: "v3", auth: oauthClient })`. Download action returns base64 content for small files, streams for large files (relay strips inline content).

**Commit message:** `feat(google): Drive handler — search, list, metadata, download`

---

### Task 14: Contacts handler

**Files:**
- Create: `src/google-services/handlers/contacts.ts`
- Test: `tests/google-services/handlers/contacts.test.ts`

Actions: `search`, `list`, `get`

Use `google.people({ version: "v1", auth: oauthClient })`.

**Commit message:** `feat(google): Contacts handler — search, list, get`

---

## Phase 5: Fastify Server

### Task 15: Server with /v1/fetch, /v1/health, /v1/schema

**Files:**
- Create: `src/google-services/server.ts`
- Test: `tests/google-services/server.test.ts`

**Step 1: Write integration test**

```typescript
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { buildServer } from "../src/google-services/server.js";

describe("google-services server", () => {
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await buildServer({ /* test config with mocked vault */ });
    await server.ready();
  });

  afterAll(async () => { await server.close(); });

  it("GET /v1/health returns coarse status", async () => {
    const res = await server.inject({ method: "GET", url: "/v1/health" });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBeDefined();
    expect(body.services).toBeDefined();
    expect(body.services.gmail).toBeDefined();
  });

  it("GET /v1/schema returns action catalog", async () => {
    const res = await server.inject({ method: "GET", url: "/v1/schema" });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.services).toBeInstanceOf(Array);
    expect(body.services.some(s => s.id === "gmail")).toBe(true);
  });

  it("POST /v1/fetch requires x-actor-user-id", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/fetch",
      payload: { service: "gmail", action: "search", params: { q: "test" } },
    });
    expect(res.statusCode).toBe(401);
  });

  it("POST /v1/fetch rejects action without approval token", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/v1/fetch",
      headers: { "x-actor-user-id": "admin" },
      payload: { service: "gmail", action: "create_draft", params: { to: "x@y.com", subject: "hi", body: "test" } },
    });
    expect(res.statusCode).toBe(403);
  });
});
```

**Step 2: Implement server.ts**

Fastify server with 3 routes:
- `GET /v1/health` — calls health store
- `GET /v1/schema` — returns action registry formatted for LLM
- `POST /v1/fetch` — validates request, checks approval for actions, dispatches to handler, returns response

**Step 3: Run tests**

Run: `pnpm vitest run tests/google-services/server.test.ts`

**Step 4: Create index.ts entry point**

```typescript
// src/google-services/index.ts
import { buildServer } from "./server.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const server = await buildServer(config);
await server.listen({ port: config.port, host: "0.0.0.0" });
```

**Step 5: Commit**

```bash
git add src/google-services/server.ts src/google-services/index.ts tests/google-services/server.test.ts
git commit -m "feat(google): Fastify server with /v1/fetch, /v1/health, /v1/schema"
```

---

## Phase 6: Relay Integration

### Task 16: Approval token generation in relay

**Files:**
- Create: `src/relay/approval-token.ts`
- Test: `tests/relay/approval-token.test.ts`

Implements:
- `generateApprovalToken(claims, vaultClient)` — builds claims, calls vault `signPayload`, returns `v1.<claims>.<sig>`
- `canonicalHash(hashInput)` — RFC 8785 deterministic JSON + SHA-256
- Integration with existing approval flow (`/approve` command handler)

**Commit message:** `feat(relay): approval token generation for provider actions`

---

### Task 17: Provider proxy approval header forwarding

**Files:**
- Modify: `src/relay/provider-proxy.ts`
- Modify: `src/relay/capabilities.ts` (if action type detection needed)

Extend `proxyProviderRequest()`:
1. Query sidecar schema at startup to know which actions are `action` type
2. For `action` type requests, require approval flow before forwarding
3. Pass `x-approval-token` header to sidecar

**Commit message:** `feat(relay): forward approval tokens to provider sidecars`

---

### Task 18: Provider config for Google

**Files:**
- Modify: `docker/telclaude.json`

Add google provider to config:

```json
{
  "id": "google",
  "baseUrl": "http://google-services:3002",
  "services": ["gmail", "calendar", "drive", "contacts"]
}
```

**Commit message:** `config: add google-services provider`

---

## Phase 7: Docker

### Task 19: Dockerfile for google-services

**Files:**
- Create: `docker/Dockerfile.google-services`

```dockerfile
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --prod=false
COPY tsconfig.json ./
COPY src/google-services/ src/google-services/
COPY src/vault-daemon/client.ts src/vault-daemon/protocol.ts src/vault-daemon/index.ts src/vault-daemon/
RUN pnpm exec tsc --project tsconfig.google-services.json

FROM node:22-bookworm-slim
RUN groupadd -g 1000 app && useradd -u 1000 -g app -m app
WORKDIR /app
COPY --from=builder /app/dist/google-services/ ./dist/
COPY --from=builder /app/node_modules/ ./node_modules/
USER 1000:1000
EXPOSE 3002
CMD ["node", "dist/index.js"]
```

**Commit message:** `docker: add Dockerfile for google-services sidecar`

---

### Task 20: Docker Compose integration

**Files:**
- Modify: `docker/docker-compose.yml`

Add google-services service, relay-google network, google-egress network, google-data volume. Add vault-socket volume mount. Wire healthcheck.

**Commit message:** `docker: add google-services to compose with network isolation`

---

## Phase 8: Integration Testing

### Task 21: End-to-end integration test

**Files:**
- Create: `tests/google-services/integration.test.ts`

Test the full flow:
1. Start sidecar with mocked vault
2. Make read request → success (no approval needed)
3. Make action request without token → 403
4. Make action request with valid token → success
5. Replay same token → 409
6. Health endpoint reflects service state

**Commit message:** `test(google): end-to-end integration tests`

---

### Task 22: Typecheck, lint, format

**Files:**
- Modify: `tsconfig.json` (add google-services paths if needed)

Run: `pnpm typecheck && pnpm lint && pnpm format`

Fix any issues.

**Commit message:** `chore: fix lint/format for google-services`

---

## Task Dependency Graph

```
Phase 1 (vault)          Phase 2 (oauth)
  T1 → T2 → T3            T4 → T5
       ↓                       ↓
Phase 3 (sidecar core)   ─────────
  T6 → T7 → T8 → T9 → T10
                    ↓
Phase 4 (handlers)
  T11, T12, T13, T14 (parallel)
              ↓
Phase 5 (server)
  T15
   ↓
Phase 6 (relay)
  T16 → T17 → T18
   ↓
Phase 7 (docker)
  T19 → T20
   ↓
Phase 8 (integration)
  T21 → T22
```

**Parallelizable tasks:**
- T4 + T1 (oauth registry + vault protocol — independent)
- T11 + T12 + T13 + T14 (all 4 service handlers — independent)
- T19 + T16 (dockerfile + relay approval token — independent)

**Total: 22 tasks across 8 phases**
