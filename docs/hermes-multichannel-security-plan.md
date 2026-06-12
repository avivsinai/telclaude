# Hermes Multichannel Secretless Plan

## Objective

Make the private/family agent useful enough to live in normal messaging surfaces by running one Hermes-backed agent profile across Telegram, WhatsApp, and email, while keeping Telclaude as the security authority.

The product goal is one continuous assistant reachable from multiple channels. The security goal is that channel reachability never implies broad authority.

## Target Shape

```
Telegram / WhatsApp / Email / Desktop
        |
        v
Telclaude edge + relay authority
        |
        | opaque authority handle, scoped tools, sanitized inbound refs
        v
Contained upstream Hermes profile
        |
        | relay-served MCP tools only
        v
Providers, outbound sends, memory, web, media, approvals
owned and executed by Telclaude relay/sidecars
```

Hermes may be the single conversational/runtime brain. It must not become the credential owner, policy owner, approval issuer, side-effect executor, or raw network boundary.

## Non-Negotiable Invariants

1. Runtime compute never receives raw provider credentials, OAuth refresh tokens, bank tokens, WhatsApp credentials, email credentials, browser cookies, TOTP seeds, vault credentials, or model-provider credentials.
2. The contained Hermes runtime does not directly reach provider sidecars, vault, home/LAN services, metadata endpoints, model providers, or connector bridges.
3. Every Hermes request to privileged capability goes through a relay-issued, opaque, peer-bound authority handle.
4. Hermes cannot choose its actor, profile, memory source, provider scopes, outbound channels, connector identity, or approval state.
5. Same agent does not mean same authority. Operator Telegram, operator WhatsApp, operator email, family WhatsApp, family email, and external email are distinct channel identities with server-derived trust domains.
6. Reads are typed, scoped, audited, rate-limited, and release-minimized by profile, channel identity, service, action class, read/write mode, and release policy. Provider reads can still leak sensitive information.
7. Writes are never inline. Provider writes and outbound sends use `prepare -> approve/step-up -> execute`.
8. Approval tokens are one-time, short-lived, JTI-checked, Ed25519-signed, and bound to the exact prepared record digest.
9. High-risk approvals require an independent step-up factor. For this slice, the factor is trusted TOTP freshness consumed by Telegram `/approve`; a separate approval channel remains a later hardening option for banking, public sharing, account changes, or provider PII release.
10. Public web access is relay-served public-web read capability, not raw container egress or authenticated browser sessions inside Hermes.
11. WhatsApp and email are edge transports. Their credentials live in relay-owned sidecars or gateway surfaces, never in the contained agent runtime.
12. Inbound channel content is untrusted data until CL-1 wraps it, deduplicates it, assigns identity/domain, quarantines attachments, and binds it to a relay conversation.
13. Web-derived and inbound-derived content cannot become trusted memory through prompt discipline alone. Memory writes must carry source/provenance and require relay policy or human confirmation before entering trusted operator or household memory.
14. Every slice that touches Hermes runtime startup, connector wiring, profile generation, or cutover evidence must preserve the no-fork proof: upstream checkout clean, no runtime source replacement, no monkeypatches, `nofork.clean` passing, and fresh strict cutover evidence.

## Current Local Reality To Preserve

The existing repo already has the right primitives:

- Contained upstream Hermes with relay as the security envelope.
- Relay-served MCP tools for provider read/write, memory, attachments, outbound, audit, web fetch/search, media, TTS, and skill requests.
- Opaque authority handles, memory-source enforcement, client authority stripping, provider scope checks, and capability scope checks.
- DNS-pinned public web fetch with private/metadata blocking, content-type allowlist, truncation, redaction, audit, and untrusted-content wrapping.
- Google sidecar with read/action separation and approval-token verification.
- Side-effect ledger with prepared records, canonical hashes, short TTLs, signed one-time approval tokens, replay denial, and self-approval denial.
- WhatsApp outbound connector shape with prepared outbound, resolved destination binding, owner-bound attachments, and one-shot bridge-session headers.
- WhatsApp inbound intentionally dark until CL-1 exists.

The plan should reuse those primitives rather than creating a parallel authorization system.

## Current Gaps To Close

1. The contained Hermes startup still receives relay/MCP/Codex bearer material and writes peer-bound model relay material into runtime-local files. That is not yet "no meaningful token exists in the container."
2. Private-domain Hermes currently gets all MCP capability scopes by default. That is too coarse for a family/multichannel profile.
3. Provider scopes are global private-runtime config, not per profile, channel identity, service, and action.
4. TOTP is a session identity gate, not a per-write fresh step-up gate.
5. Side-effect ledger records are in memory. JTI replay storage is durable, but pending prepared effects are not.
6. Google writes are currently limited to Gmail draft and self-only calendar event. Drive writes, Gmail send, sharing, deletion, and richer calendar changes are not implemented.
7. WhatsApp outbound is shaped but not product-wired. WhatsApp inbound CL-1 is not wired.
8. Email edge is documented in the Hermes proof matrix but needs the same concrete edge treatment as WhatsApp.
9. The current private memory source naming is Telegram-flavored; multichannel operator memory needs a server-owned profile source that does not imply Telegram-only authority.

## Architecture Decisions

### Decision 1: One Agent, Many Channel Authorities

Operator-owned Telegram, WhatsApp, and email can route to the same Hermes profile and memory namespace.

Family and external channels do not receive operator-private authority just because they speak to the same assistant. They get separate authority handles, separate memory boundaries, and separate provider release rules.

### Decision 2: Connectors Are Edge, Not Trust Boundary

Hermes connector support is useful for product coverage, but Telclaude must decide where connector credentials live.

Preferred mode:

- Telclaude owns Telegram, WhatsApp, and email connectors as relay edge sidecars.
- Edge sidecars normalize inbound events into relay conversations.
- Relay activates the appropriate Hermes profile with a scoped authority handle.
- Outbound sends return through `tc_outbound_prepare` and `tc_outbound_execute`.

Allowed compatibility mode:

- If a Hermes-native connector is necessary for parity, it runs only in a connector/edge sidecar or constrained connector profile.
- It gets no provider scopes, no vault access, no home/LAN egress, no write execution, and no raw cross-channel authority.
- It must emit sanitized events into Telclaude edge, not bypass edge policy.

Forbidden mode:

- Putting Telegram, WhatsApp, email, provider, browser, or bank credentials directly into the main contained Hermes runtime.

### Decision 3: Public Web Is Useful, But It Is Data

Public web search/fetch should be enabled for the operator-private profile through relay MCP tools. Web results are always untrusted external content. They can inform answers or proposed side effects; they cannot authorize actions or become trusted memory without human confirmation.

Implementation must enforce this at the relay memory boundary. Web and inbound channel data must be tagged as external-derived provenance, and trusted memory writes from those sources must require an explicit confirmation policy instead of relying on the agent prompt.

### Decision 4: Writes Need Fresh Step-Up

The existing approval-token and side-effect ledger pattern remains the core. Add fresh step-up before minting a side-effect approval token according to risk:

- Low-risk local reversible actions: approval card or `/approve`.
- Provider writes: fresh TOTP or passkey-backed approval.
- Public sharing, account changes, destructive actions: passkey or independent admin channel.
- Bank transfers/new payees: bank-native SCA plus relay step-up.

### Decision 5: Home Services Are Providers, Not Private Web Targets

For personal/family deployment, home/LAN stays blocked from Hermes. Home Assistant, NAS, cameras, locks, and similar services must be exposed as typed relay-owned home providers with read/write policies, not direct `WebFetch` private endpoints.

## Policy Matrix

| Surface | Read Policy | Write Policy | Step-Up | MVP Status |
| --- | --- | --- | --- | --- |
| Public web | Allow `tc_web_search` and `tc_web_fetch`; block private/metadata/LAN; wrap as untrusted | No arbitrary web POST or authenticated browser writes | None for ordinary reads; approval if private facts are being sent outward | Enable |
| Telegram operator | Operator-private channel; route to same Hermes profile | Outbound reply through Telegram relay | Existing approval for side effects | Existing |
| WhatsApp operator | Strong-linked phone maps to operator-private channel authority | Reply/send through prepared outbound only | Approval for ordinary sends; fresh step-up for provider PII or high-risk content | Wire outbound first |
| WhatsApp household | Household domain, no operator-private memory | Benign replies only; provider PII only with strong link and policy | Independent operator approval for sensitive releases | Wire after operator path |
| Email operator | Strong-linked email maps to operator-private channel authority | Draft/send through prepared outbound only | Draft approval; send needs stronger policy | Wire after connector custody |
| External email | Public/untrusted domain | No direct side effects; can propose drafts only | Operator approval required | Later |
| Gmail | Search/read/thread/labels/attachments with minimal scopes | Create draft now; send/modify/delete later as explicit actions | Fresh TOTP/passkey for writes | Draft only |
| Calendar | List/search/get/freebusy | Self-only create event now; attendees/delete/settings later | Fresh TOTP for create; stronger step-up for external attendees/delete | Self event only |
| Drive | Metadata/search/list/download with DLP/audit | Create/update/move/share/delete only after action registry exists | Fresh TOTP for normal writes; passkey for public share/delete | Read only |
| Contacts | Read only | Future create/update/delete/export as explicit actions | Fresh TOTP; export needs stronger approval | Read only |
| Banking | Read balances/transactions/beneficiaries through bank sidecar | Transfers/new payees only after durable ledger and bank-native SCA | Bank SCA plus relay step-up | Read only later |
| Home services | Relay home-provider state reads only | Low-risk reversible actions only by policy; safety/security actions mostly forbidden | Fresh step-up or physical confirmation | Later |

## Implementation Slices

### Slice 0: Baseline Proof And Ownership

Goal: make sure we are not building on a stale or partially proven Hermes posture.

Tasks:

1. Re-run relevant Hermes doctor/probe surfaces for current main.
2. Confirm live MCP, model relay, network containment, served MCP memory, side-effect ledger, edge WhatsApp, edge email, and Google provider probe status.
3. Produce a short current-state inventory: pass, fail, not wired, stale evidence.
4. Re-run the steady-state proof loop: `pnpm dev hermes doctor --probes --compat-lock --json`, `pnpm dev hermes prove --upstream-clean`, `pnpm dev hermes network-probes --allow-run` where egress posture changed, and `pnpm dev hermes verify-live`.

Exit criteria:

- We know which surfaces are code-complete vs. proof-stale.
- No implementation starts on a false assumption.
- Strict no-fork evidence is fresh for the runtime and profile-generation path being modified.

### Slice 1: Remove Runtime Token Custody

Goal: make "no meaningful token exists in the Hermes container" true enough to claim.

Tasks:

1. Replace startup delivery of root relay/MCP/Codex secrets with relay-minted, peer-bound, short-lived runtime handles.
2. Ensure any runtime-local token material is non-root, turn-scoped or activation-scoped, and useless outside the observed peer/session.
3. Remaining runtime handles must be non-authoritative relay handles, not bearer credentials that can exercise standing authority from inside `HERMES_HOME`.
4. Avoid writing reusable bearer material into `HERMES_HOME`.
5. Add leak scans for generated config/auth files.
6. Add negative probes for replaying runtime token material from the wrong peer, wrong session, expired token, and after authority revocation.

Exit criteria:

- Contained runtime has no provider/model/vault/connector credentials.
- Remaining runtime handles are short-lived, peer-bound, scoped, redacted, and replay-denied.

### Slice 2: Explicit Multichannel Profile Authority

Goal: make one Hermes agent reachable from many channels without collapsing authority.

Tasks:

1. Extend profile config with explicit `capabilityScopes`, `providerScopes`, `outboundChannels`, and channel identity bindings.
2. Make `providerScopes` precise enough to express provider ID, service surface, action, read/write mode, channel identity, profile, and release policy for Gmail, Calendar, Drive, Contacts, banking, and provider PII release.
3. Stop granting all MCP capability scopes by default to every private-domain runtime.
4. Add server-derived authority mapping:
   - operator Telegram -> operator-private profile
   - operator WhatsApp -> same operator-private profile after strong link
   - operator email -> same operator-private profile after strong link
   - family WhatsApp/email -> household profile/domain
   - external email -> public/untrusted domain
5. Rename or abstract memory source semantics so operator-private memory is profile-owned, not Telegram-owned in concept.
6. Add negative tests: household cannot read operator memory; external email cannot access provider scopes; client-supplied authority is ignored/denied.

Exit criteria:

- Same Hermes profile can serve multiple operator channels.
- Each inbound channel gets a server-derived authority handle with explicit scopes.

### Slice 3: Public Web For Operator-Private

Goal: make the agent able to browse public web usefully without raw egress.

Tasks:

1. Ensure private/operator profile gets explicit `web.search` and `web.fetch`.
2. Confirm live MCP tool wiring and web search provider config.
3. Add private-fact/PII outbound preflight for web queries and fetch URLs, beyond token-shaped secret filtering.
4. Keep DNS-pinned SSRF guard, redirect revalidation, content-type allowlist, redaction, truncation, audit, and external-content wrapping.
5. Add fixtures for allowed public fetch, denied RFC1918, denied metadata, denied mixed DNS, denied provider/vault/model host, denied private-fact outbound query.

Exit criteria:

- Operator can ask the agent to search/read public web.
- Web cannot be used as a private-data exfiltration path without explicit approval.

### Slice 4: Service Enrollment UX

Goal: make service setup feel like a product workflow, not manual machine work.

Tasks:

1. Add `/services` or dashboard flow for connector/provider status.
2. Relay initiates OAuth PKCE or provider setup.
3. Vault stores refresh tokens; sidecars expose health/auth status.
4. Hermes sees only service availability, schemas, and scoped tools.
5. Re-auth and scope expansion happen through relay UI, not Hermes browser sessions.

Exit criteria:

- Google/email/WhatsApp setup can be guided from the operator channel.
- No setup flow asks the agent to handle raw secrets.

### Slice 5: Google Useful Core

Goal: ship the first genuinely useful provider set.

Tasks:

1. Keep Gmail, Calendar, Drive, and Contacts reads.
2. Keep Gmail `create_draft` and Calendar self-only `create_event` behind approval.
3. Integrate fresh TOTP/passkey step-up into side-effect human approval before approval-token minting.
4. Improve WYSIWYS approval prompts: account, service, action, recipient/title/time/body/file, content hash, expiry, idempotency key.
5. Add Drive write actions only after action registry and tests exist.

Exit criteria:

- Reads work without exposing tokens to Hermes.
- First Google writes require fresh step-up and exact digest-bound execution.

### Slice 6: WhatsApp Outbound

Goal: let the same operator-private Hermes profile reply/send through WhatsApp safely.

Tasks:

1. Configure WhatsApp bridge as a relay edge sidecar on its own network.
2. Keep bridge credentials out of Hermes.
3. Register WhatsApp as an outbound channel only for authorized profile/channel identities.
4. Route outbound through `tc_outbound_prepare` and `tc_outbound_execute`.
5. Approval prompt shows exact recipient/thread/body/attachments/hash/TTL/idempotency key.
6. Add negative probes for wrong recipient, changed body, wrong conversation attachment, replayed idempotency key, missing sidecar, direct credential injection.
7. Bridge contract: implement `POST /v1/whatsapp/send` and `GET /health`; verify relay-issued `x-telclaude-whatsapp-session-key` and `x-telclaude-whatsapp-request-digest` against the exact request body before sending; pin the bridge image by digest once published.

Exit criteria:

- Operator can ask the same Hermes agent to send/reply on WhatsApp.
- Sends are edge-owned and side-effect-ledger-owned.

### Slice 7: WhatsApp And Email Inbound CL-1

Goal: safely let WhatsApp/email initiate conversations into the same Hermes-backed assistant.

Tasks:

1. Implement inbound listener pipeline: signature/auth verification, dedup, cursor/replay handling, attachment quarantine, risk wrapping, identity lookup, trust-domain assignment, and conversation token minting.
2. Strong-link operator WhatsApp/email to operator-private authority.
3. Strong-link family identities to household authority.
4. Treat external email as public/untrusted and proposal-only.
5. Add group handling rules before enabling WhatsApp group chats.
6. Wire the usable WhatsApp listener only in a follow-up slice: the bridge must POST signed inbound events to a relay endpoint, the endpoint calls the complete CL-1 pipeline, and `onInboundEvent` dispatches only sanitized events into Hermes.
7. Inbound bridge signing contract: compute HMAC over the post-schema-default canonical object that the relay verifies, including defaulted fields such as `attachments: []`; signing a sparse pre-default payload must fail closed.
8. Operator-only W-B may use a static operator address allowlist; Telegram `/approve` strong-link pairing and household/multi-number pairing remain separate Aviv-gated follow-up work.

Exit criteria:

- Inbound WhatsApp/email can reach Hermes only as sanitized, domain-bound, identity-bound content.
- No inbound channel can smuggle authority fields or raw credentials.

### Slice 8: Durable High-Risk Side Effects

Goal: prepare for bank writes, Drive sharing/deletion, email send, home safety actions.

Tasks:

1. Persist side-effect records durably, not only JTI replay state.
2. Add executing/executed/revoked/compensating states and provider result IDs.
3. Mark executing before dispatch where provider idempotency is available.
4. Require provider-side idempotency keys for bank, WhatsApp, email, Drive, and home writes.
5. Hash-chain or sign high-risk audit records.

Exit criteria:

- Relay restart cannot lose high-risk pending/executing state.
- Duplicate real-world effects are suppressed by relay and provider.

### Slice 9: Bank And Home Providers

Goal: add sensitive personal/family services only after the lower-risk path is proven.

Tasks:

1. Banking starts read-only through a dedicated sidecar.
2. Transfers require bank-native SCA, relay step-up, beneficiary policy, amount limits, and durable idempotency.
3. Home services are typed providers, not direct LAN browsing.
4. Low-risk home actions are allowlisted; safety/security actions require strong step-up or remain forbidden.

Exit criteria:

- Sensitive services follow the same secretless, typed, audited, step-up model.

## Verification Gates

Each slice must add narrow negative and positive tests before it is considered done.

Required gates:

1. No raw credential appears in Hermes env, config, auth files, logs, or generated artifacts.
2. Wrong-peer and expired runtime handles fail closed.
3. Client-supplied authority/profile/provider/memory/outbound fields fail closed.
4. Public web can fetch public content but cannot reach RFC1918, metadata, provider, vault, model, or bridge hosts.
5. Web content is wrapped as untrusted and cannot become trusted memory without human confirmation.
6. Google reads route through relay/sidecar only.
7. Google writes require fresh step-up and exact approval-token binding.
8. WhatsApp outbound cannot mutate recipient/body/attachment after approval.
9. WhatsApp/email inbound remains dark until CL-1 passes.
10. Household and external domains cannot read operator-private memory or provider PII.
11. Cutover/probe evidence is signed, fresh, and origin-bound where applicable.

## Initial Build Order

1. Slice 0: current-state proof.
2. Slice 1: remove runtime token custody.
3. Slice 2: explicit profile/channel authority.
4. Slice 3: public web for operator-private.
5. Slice 4: service enrollment UX.
6. Slice 5: Google useful core.
7. Slice 6: WhatsApp outbound.
8. Slice 7: WhatsApp/email inbound CL-1.
9. Slice 8: durable high-risk side effects.
10. Slice 9: bank/home providers.

## Definition Of Done For "Personal Agent MVP"

The MVP is done when:

1. The same Hermes-backed operator-private profile can be reached from Telegram and at least one additional strong-linked channel.
2. The agent can search/fetch public web through relay MCP tools.
3. The agent can read Google/Gmail/Calendar/Drive/Contacts through relay providers.
4. The agent can prepare at least Gmail draft and self-only calendar event writes with fresh step-up approval.
5. The agent can send/reply through WhatsApp outbound as an edge-owned prepared side effect.
6. No connector/provider/model/vault token is present in the contained Hermes runtime except non-root, short-lived, peer-bound handles with replay denial.
7. All privileged actions are auditable and replay-denied.
8. Household and external channels cannot reach operator-private authority.

## Explicit Non-Goals For MVP

1. Bank transfers.
2. Drive public sharing/deletion.
3. Email send without a separate approval policy.
4. WhatsApp group autonomy.
5. Authenticated browser sessions inside Hermes.
6. Direct LAN/Home Assistant/NAS access from Hermes.
7. Provider enrollment through an agent-held browser cookie.
8. Any use of prompt instructions as a security boundary.
