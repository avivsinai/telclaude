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

The relay is the security boundary — it holds all secrets, enforces tiers/rate limits, and mediates every interaction between Telegram, external APIs, memory, and agent workers. Agents are untrusted compute: they see only their allowed tools, never touch raw credentials, and do not own memory as a source of truth.

### Hermes Private Runtime (no-fork wrapper)

The private Telegram persona can run either as a direct Claude Agent SDK worker (legacy) or through a **pinned, no-fork wrapper around upstream Hermes**. The relay picks the path per `shouldUseHermesPrivateRuntime()`; when Hermes mode is active, private replies and heartbeats route through `HermesApiRuntimeAdapter` to a contained Hermes API server instead of initializing the SDK directly.

```
┌──────────────────────── telclaude-hermes-relay (internal, 192.0.2.0/24) ────────────────────────┐
│                                                                                                  │
│  telclaude (relay, 192.0.2.10)                          tc-hermes-contained (192.0.2.11)         │
│  • Live MCP server  :8793  ──── tools/call ───▶         • Hermes API server  :8642               │
│    (relay-internal HTTP, peer-bound to .11)             • non-root uid 10000, cap_drop ALL       │
│  • Live MCP admin (Unix socket)                         • read-only root, noexec tmpfs           │
│  • Relay conversation store (owns thread authority)     • curated skill allowlist only           │
│  • Side-effect ledger + approval tokens                 • model traffic ──┐                       │
│  • OpenAI Codex proxy  :8790  ◀── inference ────────────────────────────┘ (relay-only egress)    │
│                                                         model-provider hosts → 192.0.2.1 (blocked)│
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

Hermes is pinned to upstream ref `v2026.5.29` (version `0.15.1`) by image digest and proven unmodified before any cutover (see the no-fork proof below). The contained Hermes process never holds raw credentials, never reaches model providers directly, and exposes no agent-to-agent path: its only outward routes are the relay's live MCP server (for memory, providers, attachments, outbound) and the relay's OpenAI Codex proxy (for inference).

## Trust Boundaries

### Relay ↔ Agent Split

The relay and agents are separate trust domains. The relay is the only component with access to secrets (API keys, Telegram token, OAuth credentials). Agents are treated as potentially compromised — they can only act through tiered tool access and relay-proxied API calls. This means a prompt injection that compromises the agent cannot exfiltrate secrets or escalate privileges beyond the user's tier.

In Docker, this maps to separate containers on isolated networks. In native mode, the SDK sandbox provides equivalent isolation. Both modes enforce the same invariant: agents never see raw credentials, and durable memory authority stays in the relay rather than in Claude's local files.

### Codex Work Unit Boundary

Codex is a peer runtime, not a second stateful conversation loop. The `/codex` command and `telclaude background codex` create bounded background jobs that run `codex exec` with an explicit sandbox, confined working directory, `--ephemeral`, and `--ignore-user-config`. Results come back as background job output wrapped as untrusted data; they are not fed into the active Claude session unless the operator explicitly asks for a follow-up.

Write-capable Codex work requires FULL_ACCESS and still runs with workspace-write network access disabled. Model overrides are allowlisted to known executable Codex models so an invalid but syntactically plausible token fails before a job is queued.

**Execution + brokered inference auth (Docker).** The background runner lives in the relay, which mounts no workspace, so codex work units execute in the **agent** container (which has `/workspace` and the tool/network boundary) via a narrow internal-auth'd `POST /v1/codex-work-unit` — the relay never spawns codex locally. The agent's codex CLI is configured (via `-c` overrides, so it works under `--ephemeral`/`--ignore-user-config`) as a **custom HTTP `responses` model provider** pointed at the relay's `openai-codex-proxy`; the durable ChatGPT/Codex subscription credential stays relay/vault-only (vault target `openai-codex-oauth`). Before each run the agent mints a **short-lived, peer-bound, per-job** relay token from `POST /v1/codex-relay-token` (the relay is the sole holder of the HMAC signing secret `TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN`; the agent never holds it). The token is the only secret added to the otherwise-stripped codex child env, bound to the agent's observed peer and scoped to the job timeout. The proxy verifies the peer-bound token, strips it, and swaps in the vault credential before forwarding to the model backend. If the relay is configured but minting fails, the agent fails closed (no run). The relay-token shape is added to the streaming secret filter so a codex run cannot echo its own bearer back to Telegram.

### Relay ↔ Hermes Private Runtime Split

When the private persona runs as Hermes, the upstream agent is a **pinned, unmodified checkout** that the relay wraps rather than forks. The relay does not trust Hermes to enforce policy; instead it confines Hermes and keeps every privileged capability behind relay-owned APIs:

- **No-fork posture.** The wrapper proves the Hermes checkout matches the pinned upstream ref and version with no diff, patch, monkeypatch, or runtime source replacement. The proof (`no-fork-proof.ts`) runs git checks before and after a P0 wrapper run (`checkout.present/head/expectedRef/pinned/statusClean/diffClean/indexClean` plus post-run repeats) and binds them to a signed runner attestation. `hermesCheckoutClean` must be true.
- **Containment.** In Docker, Hermes runs in `tc-hermes-contained` on the isolated `telclaude-hermes-relay` network as a non-root user (uid 10000) with `cap_drop ALL`, no-new-privileges, a read-only root filesystem, and `noexec` tmpfs mounts. Model-provider hostnames resolve to a blackhole address (`192.0.2.1`), so direct egress fails at the network layer.
- **Served MCP, not a tool allowlist.** Hermes does not get raw tools for privileged work. The relay hosts a relay-internal **live MCP server** that exposes nine scoped tools (`tc_provider_read`, `tc_provider_prepare_write`, `tc_provider_execute_write`, `tc_memory_search`, `tc_memory_write`, `tc_attachment_get`, `tc_outbound_prepare`, `tc_outbound_execute`, `tc_audit_note`). The server strips any client-supplied authority/connection/provenance fields and resolves the caller's authority from an opaque, peer-bound handle — Hermes cannot name its own scope, memory source, or outbound channels.
- **Internal RPC auth, not network trust.** Relay ↔ Hermes control traffic is authenticated with bidirectional Ed25519 internal-response proofs (operator/relay keypairs), not by trusting the shared network.

*Why wrap instead of fork*: a fork accumulates drift and silently diverges from upstream security assumptions. Proving the checkout is byte-for-byte upstream means the security envelope — not patched agent code — is the only thing that changed, so the parity and cutover proofs reason about a known runtime.

### Private ↔ Public Persona Split

The private persona (Telegram agent) and public persona (social agent) are air-gapped at the memory and network level:
- Each agent runs on its own relay network — agents cannot reach each other directly.
- Memory is split at the private/public boundary: the Telegram agent sees only `source: "telegram"` memory; the social agent sees only `source: "social"` memory.
- The relay mediates all cross-persona queries (e.g., `/social ask` routes through the relay, never through the Telegram agent).

### Relay ↔ Google Sidecar Split

The Google services sidecar sits on two isolated Docker networks: `relay-google` (relay communication) and `google-egress` (outbound to `googleapis.com` only, enforced by iptables rules in `init-firewall.sh`). Agent containers have no route to the sidecar — all Google queries flow through the relay, which handles approval gating, attachment storage, and audit logging. The sidecar connects to the vault via Unix socket for OAuth token retrieval and approval token signature verification, but never sees raw OAuth credentials in its environment.

### Relay ↔ WhatsApp Bridge Split

The WhatsApp bridge is an edge transport, not an agent/provider runtime. The relay talks to it only over the dedicated `telclaude-relay-whatsapp` Docker network, and the bridge must not join agent, Hermes, provider, workspace, media, or vault networks. Outbound sends carry relay-generated one-shot bridge-session headers bound to the exact sidecar request digest; the request JSON does not contain reusable bridge credentials. Inbound WhatsApp listeners remain dark until CL-1 wraps messages as untrusted external content before `edge.ingest`.

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
- **Phase 2 — Proactive posting**: Publish ideas explicitly approved by the operator (via `/social promote`). Trusted — content is human-approved, so skills and Bash are enabled to help the agent craft better posts.
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
- `source: "telegram:<profile-id>"` — private persona memory for one operator profile. Legacy bare `telegram` rows are migrated to `telegram:default`.
- `source: "social"` — unified public persona memory across all social platforms.

Operator profiles are sub-namespaces inside the private side. The relay resolves the active profile server-side from the chat id; agents cannot choose an arbitrary private memory source. Normal Telegram replies, scheduled private runs, relay memory RPC, and local `memory read/context --chat-id` all read the resolved `telegram:<profile-id>` source only.

Within the private Telegram path, telclaude now uses three layers with clear authority:

1. **Semantic memory** — durable relay-owned entries (`profile`, `interests`, `meta`, `threads`). This is the source of truth.
2. **Episodic archive** — relay-owned summaries of successful private turns, scoped by chat/session and used for recent + relevant shared-history recall.
3. **Compiled Claude working memory** — a generated `MEMORY.md` file written into Claude's local project-memory path immediately before a query. This is a cache derived from the relay store, never an authority.

*Why three layers*: semantic memory is compact and durable, but too sparse to capture relationship continuity by itself. Episodic memory preserves the shared history needed to feel like a long-term collaborator. Claude's local `MEMORY.md` improves session continuity inside the SDK runtime, but allowing that file to become authoritative would create split-brain state and weaken relay control.

*Why not per-service*: the public persona is one cohesive identity across platforms. Fragmenting memory per-service would create inconsistent personality and duplicate storage. Social platforms are the distribution channel, not the identity boundary.

*Why trusted vs. untrusted*: Telegram-profile memory comes from the operator and the private collaboration loop. Social memory may originate from public timeline content that passed through the LLM — it could contain injected instructions. The relay therefore keeps private and public memory fully separated, and the private agent never loads `source: "social"` memory.

### Private Memory Flow

For private Telegram turns and private heartbeats, the relay:

1. Loads trusted semantic entries for the chat.
2. Loads recent and query-relevant episodic history for the same chat scope.
3. Builds a read-only prompt payload that explicitly says memory is data, not instructions.
4. Materializes a compiled `MEMORY.md` into Claude's local project-memory path.
5. Executes the Claude query.
6. Captures the successful turn back into the episodic archive.
7. Auto-promotes only explicit, high-signal durable memories from the user's text.

This means the agent gets aggressive recall without becoming the owner of memory state. The relay remains the compiler and gatekeeper.

### Memory Safety

The memory path has two distinct safety rules:

- **Semantic writes are strict** — memory entries are validated before storage. Instruction-like text, HTML/script content, and secret-like values are rejected.
- **Episodic recall is sanitized** — archived turn text is normalized, secrets are redacted, and instruction-like content is replaced with a neutral placeholder before it can be recalled into prompt context or compiled into Claude's local memory file.

This is the key invariant: memory may preserve continuity, but it must not become a prompt-injection persistence layer.

## Curator Inbox

Curator is a review-only inbox for automation suggestions. Local scans can create system-produced suggestions for cron hardening and skill hygiene. Claude Code and Codex producers can submit their own suggestions only through a vault-signed envelope: the producer signs the item claims, the relay verifies the domain-separated signature, and the stored item records `producerKind`/`producerId` for audit.

Curator never executes the proposed action. Accept/reject records operator intent and audit context; privileged mutations stay manual or go through the existing command-specific approval path.

## Telegram Cards

Inline-keyboard cards are durable SQLite rows, but Telegram is still the visible source of truth for the operator. The cards subsystem therefore treats the card `revision` as a **message-sync counter**, not as a generic state-mutation counter.

- **Revision only advances when the visible Telegram render changes.** Invisible metadata updates (for example, a refresh that would produce the same text + keyboard) must not invalidate the buttons the user still sees.
- **Callback taps are ACKed quickly.** The handler sends a fallback `answerCallbackQuery` within about 1.5 seconds if the action is still running, so Telegram does not leave the client spinner hanging on slow paths.
- **Execution re-checks liveness before commit.** A callback can start on an active card and finish after the card expires or is superseded; the handler re-reads the row after execution and fails closed rather than committing stale state.
- **Approval-scope cards require a live waiter.** If the relay restarted and the in-memory tool-approval waiter is gone, the card must fail closed and instruct the operator to retry the original action instead of silently recording an approval that no running request can consume.

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
1. Agent requests an action-type operation via `providers query`
2. Relay detects action type, generates an approval nonce, and sends Telegram prompt
3. User approves via `/approve <nonce>` (or inline ApprovalCard button)
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

Per-service health tracking: `ok` ↔ `degraded` (after 3+ consecutive failures), `ok` → `auth_expired` (sticky until re-auth via `providers setup google`). The `auth_expired` state is sticky because it indicates a permanent credential problem (revoked refresh token) that cannot self-heal.

## Hermes MCP Bridge

When the private persona runs as Hermes, the relay exposes its privileged capabilities through a relay-internal MCP server rather than as agent tools. This is the seam where a contained, untrusted Hermes runtime asks the relay to act on its behalf — and where every side effect is bound to a human approval.

### Authority Handles, Not Claimed Authority

Each Hermes connection is bound to an opaque authority handle (`tc_mcp_…`, stored as a SHA-256 hash) issued by an in-memory registry with a TTL (default 15 min). The handle carries the actor identity, domain, memory boundary, provider scopes, and outbound channels. On every request the live MCP server strips client-supplied authority/connection/provenance fields and re-resolves authority from the handle plus the validated connection — and, for HTTP transport, the peer address. A connection or peer mismatch fails resolution.

*Why opaque handles*: if the model could name its own scope (domain, memory source, provider list, outbound channel), a prompt injection could escalate by simply asserting a broader authority. Binding authority to a server-issued handle means the runtime can only exercise the scope the relay already decided it has. The registry also enforces the memory boundary directly — a social-domain handle can only touch social memory, a private-domain handle only the matching `telegram:<profile>` source.

### Two-Phase Side Effects

Provider writes and outbound messages are never executed inline. They flow through a side-effect ledger with a `prepare → approve → execute` lifecycle:

1. **Prepare.** `tc_provider_prepare_write` / `tc_outbound_prepare` stage an immutable record (`effect-<uuid>`) capturing the actor, approver slot, domain, target, and canonical `paramsHash`/`bodyHash`. Records carry a short TTL (default 5 min) and are `prepared` until executed or revoked.
2. **Approve.** The relay raises a human approval. The approval token (`v1.<claims>.<sig>`, Ed25519 via the vault, ≤60s TTL) binds the exact prepared record: actor, approver, domain, target, and the params/body/content hashes. The actor and approver must differ — self-approval is rejected.
3. **Execute.** `tc_provider_execute_write` / `tc_outbound_execute` reference the prepared record by `actionRef`. The ledger re-verifies the approval token against the record's binding, records the JTI in SQLite for one-time use, and only then dispatches to the provider sidecar or the outbound delivery dispatcher.

*Why two phases with hash binding*: a compromised runtime that intercepts an approval token cannot redirect or mutate the action. Changing any parameter changes the canonical hash, which no longer matches the token binding; replaying the token is blocked by the JTI store; and a prepared record that expires or is revoked fails closed at execute time. This is the same defense-in-depth as the Google sidecar approval tokens, extended to all Hermes-mediated writes and outbound sends.

### Cutover Proof Spine

Because the runtime is wrapped rather than forked, telclaude does not "trust the diff" — it proves complete parity before any production cutover. `telclaude hermes cutover-check` evaluates a strict gate pipeline (`evaluateCutoverCheck()`); all gates must pass for `status="safe"` (exit 0), any gate failure yields `status="fail"` (exit 1), and unparseable evidence yields `status="input_error"` (exit 2). The gates are:

- **workflow.scope / decisions.resolved** — every included workflow maps to live inventory, declares positive and negative fixtures plus required surfaces, and has no unresolved blocking decisions.
- **profileGeneration.proven** — the reproducible `HERMES_HOME` profile tree matches its digests and contains no Hermes source-replacement artifacts.
- **featureProbes.pass / lockfile.consistent** — a feature-probe matrix (CLI-headless launch, headless entrypoint streaming/session/approval/cancellation/redaction checks, approval continuation, API-server containment, model relay, edge adapters, providers, served-MCP, skills allowlist, workflows, network egress) is locked to the Hermes pin, with every required surface proven `pass`.
- **fixtures.pass** — every required positive and negative fixture declared by an included workflow has a recorded `pass` result with valid evidence (declaring a fixture in scope is not enough; it must actually have passed).
- **nofork.clean** — the no-fork proof's git and runner-attestation checks all pass and `hermesCheckoutClean` is true.
- **networkProbes.pass** — the five required isolation probes (`network.relay-control-allowed`, `network.direct-provider-denied`, `network.direct-vault-denied`, `network.direct-model-provider-denied`, `network.dns-exfil-denied`) all pass with posture `contained-internal`, backed by a firewall sentinel.
- **queues.owned / rollback.rehearsed** — no unowned pending work (approvals, cards, cron, social, provider, background jobs) and a rehearsed rollback path.
- **parity.rosterCovered** — for a complete (non-`--scoped`) cutover, every canonical row in the parity roster is either backed by acceptance proofs or explicitly descoped via an accepted `parity-descope:<row>` decision. A set of rows (`cutover`, `redaction`, `private-chat`, `approval-tokens`, `identity-migration`, `memory`, `skills`) is **non-descopable** — attempting to descope them fails loudly. A live strict cutover cannot be `--scoped`.

### Signed Evidence & Attestations

Cutover evidence is not self-asserted by the runtime. Sensitive probes (served-MCP memory air-gap, skills allowlist, network probes, edge adapters) carry an Ed25519 **runner attestation** signed with the operator relay key — which a contained agent cannot hold — over canonical-JSON digests of the evidence body. The evaluator independently re-runs a redaction/leak scan over the artifact bytes, checks attestation freshness (artifacts stale after 7 days), and, under a live cutover (`allowStaleAttestations=false`), requires the attestation to be present and valid.

Two probes deserve note because their *origin* is part of the proof:

- **served_mcp.memory** proves the cross-domain air gap from a contained peer: a social sentinel write is searchable on the social endpoint but returns zero on the private telegram endpoint, the server-observed peer IP matches the configured contained IP (not client-claimed), and secret/instruction writes are rejected with RPC errors.
- **skills.allowlist** proves PreToolUse enforcement from *inside* the container via docker-exec (not a host simulation): the allowlisted skill is present and invocable, non-allowlisted skills are absent and denied, and SOCIAL missing/empty allowlists fail closed.

*Why signed, origin-bound evidence*: a wrapped runtime is only as trustworthy as the proof that it is contained. Binding each probe to a relay-signed attestation and a server-observed origin means the cutover decision rests on evidence the contained agent could not have forged.

## Hermes Edge Channels & Trust Domains

Beyond Telegram and social, the Hermes runtime reaches WhatsApp, email, and AgentMail. These non-Telegram surfaces are mediated by **edge adapters** — a relay-owned layer that the contained agent talks to through the served MCP, never directly. The adapter contract (`src/hermes/edge-adapter-contract.ts`) pins five operations (`ingest`, `prepareOutbound`, `executeOutbound`, `status`, `ack`) and a fixed set of strict, versioned ref types (`ActorRef`, `ConversationRef`, `AttachmentRef`, `InboundEvent`, `PreparedOutbound`, `DeliveryReceipt`, `StatusView`). The agent only ever sees these refs: it never holds raw channel credentials, raw attachment bytes, or a raw transport handle.

### Trust Domains

Edge traffic is classified into four trust domains (`TrustDomainSchema`): `private` (operator), `household` (named family members on WhatsApp/email), `public` (untrusted inbound on public channels), and `public-social` (the isolated social persona, profile `tc-public-social`). The domain is part of the `ConversationRef` and drives authorization, not a claim the agent can assert. Domain boundaries are enforced in `TelclaudeEdgeRuntime` (`src/hermes/edge-adapter-runtime.ts`): household actors must carry a `strong_link` identity assurance and a strong-link provider account binding to release provider PII (a phone-number-only binding is rejected), cannot read private operator memory (`household.private-memory-denied`), and cannot reach another recipient's context (`household.cross-recipient-denied`); the `public-social` domain may not mount the private workspace, read private memory, or receive private provider scopes (`public-social.*-denied`). Attachments are domain-scoped — a quarantine ref authorized for one domain cannot be reused in another (`attachment.cross-domain-reuse-denied`).

### Channel Layer Split (CL-0 / CL-1)

The relay's channel layer separates authorization from transport at the `markExecuted` seam (`src/relay/edge-channel-connector.ts`):

- **CL-0 (authorization + delivery seam)** owns everything up to and including the side-effect commit, then dispatches to a pure transport sink. The `OutboundDeliveryDispatcher` (`src/relay/outbound-delivery-dispatcher.ts`) is the *only* thing `executeOutbound` calls after authorization; it imports neither the side-effect ledger nor ledger-execute. A connector (e.g. `whatsapp-edge-channel-connector.ts`) receives an already-authorized `PreparedOutbound`, takes recipients **verbatim** from `resolvedDestination` (never re-derived from the model body or conversation members), and resolves attachment bytes only through an owner-bound resolver pre-scoped to the prepared outbound's conversation — content drift or a wrong-conversation ref fails closed. Transports are pure sinks; authorization, hash re-derivation, replay, and idempotency are all decided upstream.
- **CL-1 (inbound ingress)** is the risk-wrap + pairing + air-gap layer that turns authenticated inbound transport messages into model-visible content. It is deliberately **dark** until wired: a connector's `startListener` throws rather than feed unwrapped inbound to the agent (`WHATSAPP_INBOUND_RISK_WRAP_REQUIRED`). Untrusted external content is wrapped before it reaches any model by `wrapExternalContent` / `assessRisk` (`src/security/external-content.ts`), which scan for injection patterns and homoglyphs, score risk, and emit a labelled envelope instructing the model to treat the content as data and never execute instructions found inside it.

*Why split authorization from transport*: a transport that could resolve its own recipients or read arbitrary quarantine bytes would let a compromised connector exfiltrate or misdeliver. Pinning recipients to the edge-validated `resolvedDestination` and binding attachment release to the prepared outbound means the delivery sink has no discretion — it can only send exactly what was authorized, exactly where it was authorized.

### Two-Phase Outbound

Edge outbound is the same `prepare → approve → execute` shape as the served-MCP side effects. `prepareOutbound` validates the request against the contract (rejecting any agent-supplied `authorizingActor`, `transportCredentials`, `policyResult`, `approvalToken`, or raw media fields), binds the destination to the conversation, and emits a `PreparedOutbound` carrying an `edgePreparedHash` over channel + resolved destination + body + media refs, plus an `idempotencyKey` and `sideEffectLedgerRef`. `executeOutbound` re-derives that hash and refuses if the binding was mutated (`outbound.recipient-body-bound`), refuses a replayed idempotency key (`outbound.replay-denied`), records the key in an in-memory ledger, and only then hands the prepared record to the dispatcher, which returns a contract-valid `DeliveryReceipt`. The agent cannot supply its own approval token to edge execution — edge-supplied tokens are rejected outright.

Each edge surface ships a probe (`src/hermes/edge-adapter-probes.ts`) that runs the real runtime through positive and negative fixtures and, on pass, signs the evidence with an Ed25519 **runner attestation** (`src/hermes/edge-adapter-attestation.ts`) over canonical digests of the surface, contract, custody, controls, and runtime observations — the same signed-evidence discipline as the rest of the cutover spine, so edge containment is proven, not asserted.

### Long-Lived & Cron Workflows

Cron and long-running workflows persist across the approval-gated boundary through a workflow-run ledger (`src/hermes/workflow-run-ledger.ts`, schema `telclaude.hermes.workflow-run-ledger.v1`). A run record pins a **server-derived** `authorityActor` (a `start` whose `authorityActorSource` is not `"server-derived"` is rejected), the profile, domain, scope, capabilities, budget, an immutable `idempotencyKey`, and a `freshnessDeadlineMs`. Starting with a duplicate idempotency key returns the existing run rather than a second one, so a re-fired cron tick (e.g. `cron.private.daily_brief`) delivers at most once; the run carries checkpoints and reaches a terminal `completed`/`failed`/`cancelled` state. A long-running workflow that hits an approval registers an authority-bound `approvalWaiter` against a `sideEffectLedgerRef` and moves to `waiting_approval`; on approval it is resumed **only from ledger state** (`resume`), which re-checks the freshness deadline (a stale resume fails closed) and re-checks authority (a revoked authority fails the run and clears queued capabilities and open waiters) before resolving the open waiters and returning the run to `running`. Retries record a backoff and bump the attempt counter; human takeover and compensation are first-class lifecycle states distinct from the terminal `completed`/`failed`/`cancelled` set. The `workflow.cron` and `workflow.longrun` feature probes (`src/hermes/workflow-probes.ts`) exercise exactly these paths — server-derived authority, background-delivery dedup, approval-waiter binding, approval-resume resolution, and stale-resume denial — as part of the cutover feature-probe matrix.

*Why a ledger across the boundary*: a long-lived run that paused for human approval cannot keep live in-process state across a relay restart or a multi-minute approval wait without becoming an authority the agent could replay or extend. Persisting the run as a server-owned record — with the authority server-derived, the resume gated on freshness and revocation, and side effects bound to ledger refs — means a paused workflow resumes with exactly the authority it had, and no more.

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
12. Model dispatch — either an SDK query with tiered `allowedTools`, or, when `shouldUseHermesPrivateRuntime()` is active, a Hermes API runtime call whose privileged capabilities are served through the relay-internal MCP bridge.
13. Streaming reply to Telegram; audit logged.

*Why this order*: cheap checks first (ban, auth, rate limit), expensive checks later (LLM observer). Infrastructure secret blocking (step 6) runs before the observer (step 8) because the observer itself uses an LLM — if the message contains a secret, we must block it before it reaches any model. Tier lookup (step 11) runs after approval (step 9) so that approval decisions can factor in the classification without yet knowing the tier. The two model-dispatch paths at step 12 share every preceding gate — the wrapper does not move the security boundary, only the runtime behind it.

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

**No-fork wrapper instead of a Hermes fork**: Forking upstream Hermes would let agent code drift from the security assumptions the envelope was designed around, and every upstream bump would be a merge. Wrapping a pinned, proven-unmodified checkout means the only thing that changed is the relay envelope, so parity and cutover proofs reason about a known runtime — and the no-fork proof fails closed if any diff, patch, monkeypatch, or runtime source replacement is detected.

**Served MCP instead of agent tool grants for Hermes**: Granting the contained Hermes runtime raw tools (and a tool allowlist) would put policy enforcement inside an untrusted process. Serving a fixed set of relay-owned MCP tools behind opaque, peer-bound authority handles keeps scope resolution, memory boundaries, and outbound channels in the relay. The runtime can only exercise the authority the relay already issued it.

**Strict all-or-nothing cutover with signed evidence**: Gradually swapping individual workflows onto Hermes would create a split runtime where some traffic is proven and some is not, and self-asserted evidence could be forged by a compromised runtime. Requiring a complete parity roster, relay-signed origin-bound attestations, and an independent redaction re-scan before `status="safe"` means cutover is a single, auditable, reversible decision over a fully proven surface.

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
11. **The Hermes runtime is the pinned upstream checkout, unmodified.** The no-fork proof requires `hermesCheckoutClean=true` (all git checks clean before and after a P0 run) and a signed runner attestation proving no diff, patch, monkeypatch, or runtime source replacement. Cutover fails closed otherwise.
12. **Hermes exercises only relay-served authority.** The contained runtime acts solely through the nine relay-owned MCP tools, bound to an opaque, peer-bound authority handle. Client-supplied authority/connection/provenance fields are stripped; a connection or peer mismatch fails resolution.
13. **Hermes-mediated side effects are two-phase and approval-bound.** Provider writes and outbound sends are prepared as immutable ledger records and executed only against a fresh, one-time (JTI-checked) approval token whose binding matches the record's canonical params/body/content hashes. Actor and approver must differ.
14. **Hermes model traffic is relay-mediated only.** Inference reaches the relay's OpenAI Codex proxy via a peer-bound token; model-provider hostnames resolve to a blackhole address inside the contained network, so direct egress fails at the network layer.
15. **Cutover evidence is signed and origin-bound.** Sensitive cutover probes carry an Ed25519 runner attestation signed with the operator relay key (which contained agents cannot hold), pass an independent redaction re-scan, and — under a live cutover — must be present, fresh (≤7 days), and valid. The served-MCP memory air gap and skills-allowlist enforcement are proven from the contained runtime's own observed origin.
