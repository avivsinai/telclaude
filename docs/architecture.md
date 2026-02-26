# Telclaude Architecture

Design rationale for telclaude (Telegram ⇄ Claude Code relay). This document explains WHY the system works the way it does. For operational details (config fields, CLI commands, deployment), see `CLAUDE.md`.

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

                                  ┌────────────────────────────────────────────┐
                                  │ Google Services Sidecar (Fastify REST API) │
                                  │ • 4 services: Gmail, Calendar, Drive,      │
                                  │   Contacts (20 actions)                    │
                                  │ • Approval-gated write operations          │
                                  │ • JTI replay prevention (SQLite)           │
                                  └────────────────────────────────────────────┘
                                        │ Unix socket (vault)      │ HTTPS
                                        ▼                          ▼
                                  ┌──────────────┐          googleapis.com
                                  │ Vault Sidecar │
                                  └──────────────┘
```

The relay connects to the Google sidecar via the `relay-google` Docker network. The sidecar connects to the vault via Unix socket (for OAuth tokens and approval signature verification) and to `googleapis.com` via the `google-egress` network. Agents cannot reach the sidecar directly.

The relay is the security boundary — it holds all secrets, enforces tiers/rate limits, and mediates every interaction between Telegram, external APIs, and agent workers. Agents are untrusted compute: they see only their allowed tools and never touch raw credentials.

## Trust Boundaries

### Relay ↔ Agent Split

The relay and agents are separate trust domains. The relay is the only component with access to secrets (API keys, Telegram token, OAuth credentials). Agents are treated as potentially compromised — they can only act through tiered tool access and relay-proxied API calls. This means a prompt injection that compromises the agent cannot exfiltrate secrets or escalate privileges beyond the user's tier.

In Docker, this maps to separate containers on isolated networks. In native mode, the SDK sandbox provides equivalent isolation. Both modes enforce the same invariant: agents never see raw credentials.

### Private ↔ Public Persona Split

The private persona (Telegram agent) and public persona (social agent) are air-gapped at the memory and network level:
- Each agent runs on its own relay network — agents cannot reach each other directly.
- Memory is split at the private/public boundary: the Telegram agent sees only `source: "telegram"` memory; the social agent sees only `source: "social"` memory.
- The relay mediates all cross-persona queries (e.g., `/ask-public` routes through the relay, never through the Telegram agent).

### Relay ↔ Google Sidecar Split

The Google services sidecar sits on two isolated Docker networks: `relay-google` (relay communication) and `google-egress` (outbound to `googleapis.com` only, enforced by iptables rules in `init-firewall.sh`). Agent containers have no route to the sidecar — all Google queries flow through the relay, which handles approval gating, attachment storage, and audit logging. The sidecar connects to the vault via Unix socket for OAuth token retrieval and approval token signature verification, but never sees raw OAuth credentials in its environment.

This prevents the **confused deputy problem**: social memory could contain prompt injection from a public timeline. If the private agent processed that memory, the injected instructions would execute with elevated privileges (workspace access, FULL_ACCESS tools). The air gap ensures untrusted social content never reaches the privileged private context.

## Security Model

Five pillars, each addressing a distinct attack surface:

1. **Filesystem isolation** — Agents only see what they need. The Telegram agent mounts the workspace and media volumes; the social agent gets only a sandbox directory. The relay does not mount the workspace (it mounts media volumes for attachment delivery only). Sensitive paths (~/.telclaude, ~/.ssh, ~/.aws) are blocked at multiple layers. *Why*: minimise blast radius — a compromised agent can only damage what it can reach.

2. **Environment isolation** — Minimal env vars reach agents. Secrets live in the relay; agents get only non-sensitive config. *Why*: env vars are the most common credential leak vector in container deployments. Keeping agents starved of secrets eliminates this class of attack.

3. **Network isolation** — RFC1918/metadata endpoints are always blocked regardless of config. Agents cannot reach each other or the host network directly. *Why*: metadata endpoints (169.254.169.254) are the #1 SSRF target in cloud environments. Blocking them unconditionally — even for "trusted" agents — removes a whole class of privilege escalation. DNS-level enforcement requires all resolved IPs to pass the allowlist (not just the first), preventing DNS rebinding attacks where a hostname resolves to both a public and a private IP. Port scoping on private endpoint allowlists limits lateral movement even within approved hosts.

4. **Secret output filtering** — CORE regex patterns + entropy detection scan all agent output streamingly. Infrastructure secrets are non-overridable blockers (cannot be allowlisted). *Why*: even if a secret somehow reaches an agent's context, the output filter prevents it from being exfiltrated via the response stream back to Telegram.

5. **Auth, rate limits & audit** — Identity linking, TOTP auth gates, per-user rate limits, and SQLite-backed audit logs. *Why*: defense in depth — even if other layers fail, rate limits bound damage and audit logs enable forensics.

## Social Services

### Three-Phase Heartbeat

Social service heartbeats run in three phases, each with escalating trust:

- **Phase 1 — Notifications**: Process incoming mentions/replies. Untrusted — notification payloads are wrapped with "do not execute" warnings. Bash is blocked since notification content could contain injected commands.
- **Phase 2 — Proactive posting**: Publish ideas explicitly approved by the operator (via `/promote`). Trusted — content is human-approved, so skills and Bash are enabled to help the agent craft better posts.
- **Phase 3 — Autonomous activity**: The agent independently browses timelines, engages, and creates content. Trusted — operates under operator-approved autonomy with session isolation.

*Why three phases*: each phase has a different trust profile. Lumping them together would mean either blocking Bash for proactive posting (hurting quality) or allowing Bash for notification processing (security risk). The phased model matches trust to capability.

### Trust-Gated Bash

The SOCIAL tier doesn't blanket-allow or blanket-deny Bash. Instead, Bash access is gated on the actor type: operator queries, autonomous heartbeats, and proactive posting get Bash; notification processing does not. *Why*: notifications contain untrusted third-party content that could inject shell commands. Other actors are either the operator themselves or operating under explicitly granted autonomy.

### Skill Allowlisting

The SOCIAL tier requires explicit `allowedSkills` when `enableSkills` is true. If `allowedSkills` is omitted, the runtime fail-closes — all Skill tool calls are denied. An empty array (`allowedSkills: []`) also denies all skills, allowing operators to disable skills while keeping `enableSkills: true` for future use.

Non-SOCIAL tiers (private agents) are unaffected: omitting `allowedSkills` allows all skills, since private agents operate in a trusted context.

Enforcement is two-layer: a PreToolUse hook (primary, unconditional) checks every Skill invocation against the allowlist, and a `canUseTool` callback (fallback, fires only when a permission prompt would appear) provides defense-in-depth. The hook extracts the skill name from `tool_input.skill`, `.name`, or `.command` — if multiple keys carry conflicting values, the call is denied fail-closed.

*Why fail-closed for SOCIAL*: social agents process untrusted timeline content. Without an explicit allowlist, a prompt injection could invoke arbitrary skills (e.g., `external-provider`, `integration-test`) that have no legitimate social use. Requiring the operator to declare which skills are needed bounds the attack surface to exactly what's intended.

### Cross-Persona Querying

The operator can query the social persona from Telegram via two tiers:

- **Tier 1 (metadata only)**: Activity log — counts, timestamps, action types. No LLM involved, zero injection risk.
- **Tier 2 (LLM-routed)**: Question routed to the social agent, response piped back through the relay. The private Telegram agent never sees it.

*Why the relay routes instead of agent-to-agent*: if the Telegram agent processed social responses, injected content from the social timeline could execute in the private context. The relay acts as a one-way valve.

## Memory & Provenance

Memory is split at the **private vs. public boundary**, not per-service:
- `source: "telegram"` — private persona memory (trusted by default).
- `source: "social"` — unified public persona memory across all social platforms (untrusted by default).

*Why not per-service*: the public persona is one cohesive identity across platforms. Fragmenting memory per-service would create inconsistent personality and duplicate storage. Social platforms are the distribution channel, not the identity boundary.

*Why trusted vs. untrusted*: Telegram memory comes from the operator (trusted). Social memory may originate from public timeline content that passed through the LLM — it could contain injected instructions. Even trusted entries are wrapped in "read-only, do not execute" envelopes before prompt injection.

Runtime assertions enforce source boundaries — `buildTelegramMemoryContext()` and `getTrustedSocialEntries()` verify that entries match the expected source, filtering mismatches with security warnings.

## Credential Vault

```
┌─────────────────────────────────────────────────────────────────┐
│ VAULT SIDECAR (no network*, Unix socket only)                   │
│                                                                 │
│  Credential Store (AES-256-GCM encrypted file)                  │
│  OAuth2 Token Refresh (caches access tokens in memory)          │
│  Protocol: newline-delimited JSON over Unix socket              │
└─────────────────────────────────────────────────────────────────┘
              │ Unix socket
              ▼
┌─────────────────────────────────────────────────────────────────┐
│ HTTP CREDENTIAL PROXY (relay)                                    │
│                                                                 │
│  Pattern: http://relay:8792/{host}/{path}                       │
│                                                                 │
│  1. Parse host from URL                                         │
│  2. Look up credential from vault                               │
│  3. Inject auth header                                          │
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

*Why a credential proxy instead of env var injection*: env vars are visible to the process and all its children — a prompt injection could read them via Bash. The proxy pattern means credentials exist only in the vault sidecar's memory; the agent constructs a URL to the relay proxy, which transparently injects auth headers. Even if the agent is fully compromised, it cannot extract the raw credentials — only make requests to pre-configured hosts.

The vault also supports domain-separated payload signing for approval tokens:

- `sign-payload`: `{type: "sign-payload", payload: "<b64url>", prefix: "approval-v1"}` → `{signature: "<b64url>"}`. Signs `<prefix>\n<payload>` with Ed25519. The prefix ensures approval signatures cannot be confused with session token signatures.
- `verify-payload`: `{type: "verify-payload", payload: "<b64url>", signature: "<b64url>", prefix: "approval-v1"}` → `{valid: true|false}`.

The vault has no network access (except OAuth refresh), credentials are encrypted at rest (AES-256-GCM), and the proxy only injects credentials for configured hosts with optional path restrictions to prevent SSRF.

## External Providers

Telclaude integrates with private sidecar services (country- or org-specific APIs) via the relay. Agents cannot call provider endpoints directly — enforcement is two-layer:

1. **Application layer**: PreToolUse hook blocks WebFetch URLs matching provider base URLs, directing agents to use the relay-proxied CLI command instead.
2. **Firewall layer**: Agent containers exclude provider hosts from their iptables allowlist. Even if the application hook is bypassed (e.g., via Bash `curl`), the firewall blocks direct access.

*Why two layers*: application-layer hooks can be bypassed by creative tool use (Bash subshells, environment manipulation). The firewall is a kernel-level backstop that the agent process cannot circumvent. Neither layer alone is sufficient — the hook provides good error messages, the firewall provides hard enforcement.

*Why relay-proxied*: the relay handles authentication, attachment storage, and audit logging. Direct agent access would require exposing provider credentials to agents and forgoing audit trails.

Google is the first concrete provider implementation. It adds a third enforcement layer beyond hook + firewall: **approval tokens** for write operations. Action-type requests (e.g., `create_draft`, `create_event`) require a cryptographically signed, one-time-use token that binds the authorization to the exact operation. This means even if the relay is tricked into proxying a request, the sidecar independently verifies that the user approved that specific action with those specific parameters.

**Providers vs. private endpoints**: these serve different purposes. Providers are relay-proxied services where the relay adds auth and audit. Private endpoints (Home Assistant, NAS) allow direct agent WebFetch access to trusted local services that don't need relay mediation.

## Google Services Sidecar

The Google services sidecar is a Fastify REST API that provides structured access to Gmail, Calendar, Drive, and Contacts. It exposes three endpoints: `POST /v1/fetch` (dispatch actions), `GET /v1/health` (per-service health), and `GET /v1/schema` (action catalog for LLM tool generation).

### Read vs. Action Separation

Every action is tagged as `read` (18 actions: search, list, get, download) or `action` (2 actions: `gmail.create_draft`, `calendar.create_event`). Read actions execute immediately. Action-type requests require an `x-approval-token` header containing a cryptographically signed authorization.

### Approval Token System

Approval tokens use Ed25519 signatures with the format `v1.<claims_b64url>.<sig_b64url>`. Claims include: `ver`, `iss`, `aud`, `iat`, `exp`, `jti`, `approvalNonce`, `actorUserId`, `providerId`, `service`, `action`, `subjectUserId`, `paramsHash`.

The signing uses domain separation: the Ed25519 signature covers `approval-v1\n<claims_b64url>`, not the raw claims. This ensures approval signatures cannot be confused with session token signatures using the same vault keypair.

**Token flow:**
1. Agent requests an action-type operation via `provider-query`
2. Relay detects action type, generates an approval nonce, and sends Telegram prompt
3. User approves via `/approve <nonce>`
4. Relay builds claims (including SHA-256 canonical hash of request params), calls `vault.signPayload`
5. Relay forwards request to sidecar with `x-approval-token` header
6. Sidecar performs 7-step verification
7. On success, executes the Google API call

**7-step verification:**
1. Parse token format (`v1.<claims>.<sig>`)
2. Verify Ed25519 signature (domain-separated)
3. Decode and validate claims structure (Zod schema)
4. Check expiration and TTL (max 300s)
5. Match service + action + actor against request
6. Verify params hash binding (SHA-256 of canonical JSON)
7. Atomic JTI record in SQLite (replay prevention)

*Why params hash binding*: without it, an attacker who intercepts an approval token for "draft to alice@example.com" could modify the params to "draft to attacker@evil.com" and reuse the same token. The canonical hash (recursive key sort + SHA-256) makes the token non-transferable between requests.

### Health State Machine

Per-service health tracking: `ok` ↔ `degraded` (after 3+ consecutive failures), `ok` → `auth_expired` (sticky until re-auth via `setup-google`). The `auth_expired` state is sticky because it indicates a permanent credential problem (revoked refresh token) that cannot self-heal.

## Message Flow (strict profile)

The 13-step inbound pipeline defines the security architecture in action:

1. Telegram message received.
2. Ban check.
3. Admin claim flow (if no admin configured).
4. TOTP auth gate.
5. Control-plane commands handled.
6. Infrastructure secret block.
7. Rate-limit check.
8. Observer: structural checks + fast path, then LLM classification if needed.
9. Approval gate (per tier/classification).
10. Session lookup/resume.
11. Tier lookup (identity links/admin claim).
12. SDK query with tiered allowedTools.
13. Streaming reply to Telegram; audit logged.

*Why this order*: cheap checks first (ban, auth, rate limit), expensive checks later (LLM observer). Infrastructure secret blocking (step 6) runs before the observer (step 8) because the observer itself uses an LLM — if the message contains a secret, we must block it before it reaches any model. Tier lookup (step 11) runs after approval (step 9) so that approval decisions can factor in the classification without yet knowing the tier.

## Design Decisions

Key decisions and the alternatives that were rejected:

**One isolation boundary (Docker OR SDK sandbox, not both)**: Running both Docker container isolation AND SDK sandbox creates confusing failure modes — sandbox denials inside a container are hard to debug, and the two layers can conflict on filesystem/network policy. Per Anthropic's own guidance: "effective sandboxing requires both filesystem and network isolation" but within a single boundary.

**Relay holds secrets, not agents**: The alternative — injecting secrets into agent containers via env vars or mounted files — means any prompt injection that achieves code execution can exfiltrate credentials. The relay-as-proxy pattern ensures credentials never enter the agent's address space.

**Single social persona across platforms**: The alternative — per-service personas with separate memory — would fragment the public identity and create inconsistencies ("who am I on Moltbook vs. X?"). One persona with unified memory across all platforms is simpler and more coherent.

**Memory provenance at private/public boundary, not per-service**: Per-service memory (separate stores for Moltbook, X, etc.) would require complex merging logic and create split-brain identity. The real trust boundary is private (operator) vs. public (potentially adversarial), not "which platform."

**PreToolUse hooks as PRIMARY enforcement (not canUseTool)**: `canUseTool` only fires when a permission prompt would appear — in `acceptEdits` mode, auto-approved calls bypass it entirely. PreToolUse hooks run unconditionally. Using `canUseTool` as primary enforcement would leave a gap in permissive SDK modes.

**Trust-gated Bash (not blanket allow/deny)**: Blanket-deny Bash for social agents would prevent useful automation in proactive posting. Blanket-allow would expose notification processing to shell injection. Gating on actor trust level gives both capability and safety.

**Credential proxy (not env var injection)**: Env vars are accessible to any process in the container. The proxy pattern keeps credentials in a separate address space (vault sidecar), making exfiltration impossible even with full agent compromise.

**Bidirectional Ed25519 RPC auth**: Using shared HMAC keys means compromise of either side allows impersonation of both. Asymmetric keys with separate agent/relay keypairs ensure that compromise of the agent's private key cannot forge relay→agent messages, and vice versa.

**Config split (policy vs. secrets)**: The alternative — a single config file mounted everywhere — would expose PII (allowedChats, user permissions) and relay-only secrets to agent containers. Splitting into policy config (all containers) and private config (relay-only) means agent compromise cannot leak operator identity or chat permissions.

**Per-chat session keys with identity binding**: The alternative — shared sessions or global pool keys — would allow cross-chat session bleed (one user's conversation context leaking to another) and make audit trails ambiguous. Per-chat session IDs with identity-bound tiers ensure each conversation is isolated and attributable.

**Approval tokens (not session-level auth)**: Session tokens would allow any approved action to be replayed or modified. Per-request approval tokens bind the cryptographic authorization to the exact operation (service, action, params hash, actor). A compromised agent cannot reuse or modify an approved token — changing any parameter invalidates the hash. This is defense-in-depth on top of network isolation.

**Two-layer provider enforcement (hook + firewall)**: Application-layer hooks provide clear error messages but can be bypassed by creative Bash usage (subshells, environment manipulation). The firewall is kernel-level and cannot be circumvented from userspace. Neither layer alone is sufficient — together they provide both UX and hard enforcement.

## Invariants

Things that must always be true, regardless of configuration:

1. **Private LLM never processes social memory.** The Telegram agent never sees `source: "social"` entries. Enforced by runtime assertions.
2. **Agents never see raw credentials.** All external API auth goes through the vault credential proxy. No credential env vars in agent containers.
3. **Agents cannot reach other agents.** Each agent is on its own relay network. Only the relay can communicate with all agents.
4. **RFC1918/metadata always blocked.** Private IP ranges (including CGNAT 100.64.0.0/10 for Tailscale) and cloud metadata endpoints (169.254.169.254) are blocked regardless of any config setting, even in `permissive` network mode.
5. **Infrastructure secrets are non-overridable blocks.** The secret output filter's core patterns cannot be allowlisted or disabled. They block before any other processing.
6. **PreToolUse hooks run unconditionally.** Even in `acceptEdits` mode, even when `canUseTool` is bypassed. This is the primary enforcement layer.
7. **Social notification content is always untrusted.** Notification payloads are wrapped with injection warnings before reaching the model, and Bash is blocked for notification processing.
8. **Memory source boundaries are enforced at runtime.** Assertions verify that telegram contexts contain only telegram memory and social contexts contain only social memory. Mismatches throw in dev, warn in prod.
9. **SOCIAL skill invocations require an explicit allowlist.** When `enableSkills` is true for a SOCIAL service, `allowedSkills` must be set. Omitting it denies all Skill calls at runtime (fail-closed). Enforced by PreToolUse hook (primary) and canUseTool (fallback).
10. **Google sidecar approval tokens are one-time use.** JTI replay prevention via SQLite atomic insert. Time-limited (≤5 min TTL), actor-bound, request-bound (params hash), cryptographically signed (Ed25519 with domain separation).
