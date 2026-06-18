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
        | signed native container tools + relay-served capability tools
        v
Local scratch compute inside the hardened container
        |
        v
Providers, outbound sends, memory, authenticated services, browser egress, media, approvals
owned and executed by Telclaude relay/sidecars/brokers
```

Hermes may be the single conversational/runtime brain and may run useful in-container compute. It must not become the credential owner, policy owner, approval issuer, provider side-effect executor, or raw trust boundary.

## Non-Negotiable Invariants

1. Runtime compute never receives raw provider credentials, OAuth refresh tokens, bank tokens, WhatsApp credentials, email credentials, browser cookies, TOTP seeds, vault credentials, or model-provider credentials.
2. The contained Hermes runtime may run approved native tools inside the hardened container, but it does not directly reach provider sidecars, vault, home/LAN services, metadata endpoints, model providers, or connector bridges.
3. Every Hermes request to privileged capability goes through a relay-issued, opaque, peer-bound authority handle.
4. Hermes cannot choose its actor, profile, memory source, provider scopes, outbound channels, connector identity, or approval state.
5. Same agent does not mean same authority. Operator Telegram, operator WhatsApp, operator email, family WhatsApp, family email, and external email are distinct channel identities with server-derived trust domains.
6. Reads are typed, scoped, audited, rate-limited, and release-minimized by profile, channel identity, service, action class, read/write mode, and release policy. Provider reads can still leak sensitive information.
7. Writes are never inline. Provider writes and outbound sends use `prepare -> approve/step-up -> execute`.
8. Approval tokens are one-time, short-lived, JTI-checked, Ed25519-signed, and bound to the exact prepared record digest.
9. High-risk approvals require an independent step-up factor. For this slice, the factor is trusted TOTP freshness consumed by Telegram `/approve`; a separate approval channel remains a later hardening option for banking, public sharing, account changes, or provider PII release.
10. Public web access is an explicit capability. Ordinary search/fetch may be relay-served; interactive browsing must be brokered or egress-governed. Authenticated service cookies and write credentials stay outside the contained Hermes runtime.
11. WhatsApp and email are edge transports. Their credentials live in relay-owned sidecars or gateway surfaces, never in the contained agent runtime.
12. Inbound channel content is untrusted data until CL-1 wraps it, deduplicates it, assigns identity/domain, quarantines attachments, and binds it to a relay conversation.
13. Web-derived and inbound-derived content cannot become trusted memory through prompt discipline alone. Memory writes must carry source/provenance and require relay policy or human confirmation before entering trusted operator or household memory.
14. Every slice that touches Hermes runtime startup, connector wiring, profile generation, or cutover evidence must preserve the no-fork proof: upstream checkout clean, no runtime source replacement, no monkeypatches, `nofork.clean` passing, and fresh strict cutover evidence.
15. Native toolset expansion is not a weakening of the gate. `verify-live` must still fail closed unless the runtime's resolved toolset matches the signed expected allowlist for that profile.
16. Sub-agents are allowed only after a delegation proof shows child authority is inherited or narrowed, never widened, and that child runtime state cannot escape the same envelope.

## Current Local Reality To Preserve

The existing repo already has the right primitives:

- Contained upstream Hermes with relay as the security envelope.
- A hardened runtime envelope that can host native scratch compute once proven: non-root runtime, `cap_drop`, `no-new-privileges`, read-only root, noexec tmpfs, internal networks, provider/model host blocking, and relay-mediated credentials.
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
7. WhatsApp outbound and the operator-only WhatsApp inbound CL-1 bridge path are wired; household/group WhatsApp and email inbound remain pending.
8. Email edge is documented in the Hermes proof matrix but needs the same concrete edge treatment as WhatsApp.
9. The current private memory source naming is Telegram-flavored; multichannel operator memory needs a server-owned profile source that does not imply Telegram-only authority.
10. The contained Hermes profile is currently too narrow for normal Hermes usage: `api_server` is pinned to `[todo, skills, telclaudeRelay]`, while upstream Hermes expects terminal/process, file, browser, memory, code execution, delegation, cron, vision, and other tools to be available depending on platform/profile.
11. The hostile-peer live runner is still missing. Before widening native tools, the runtime must prove token isolation, relay-surface isolation, egress containment, filesystem custody, and self-modification denial from inside the container.
12. Browser scope is now full: Camoufox, interaction, and persistent logins/cookies are in scope. Persistent cookies are credential-class state and must be relay-owned, encrypted, domain/authority-scoped, approval-gated, and injected only into bounded browser contexts.
13. Browser egress is now intentionally no-MITM. The relay browser proxy validates CONNECT host/IP and policy before egress, but does not install a trusted CA in `tc-browser` or inspect HTTPS bodies. This preserves Camoufox compatibility with anti-bot targets at the cost of an accepted low-bandwidth, non-secret-shaped exfiltration residual comparable to `tc_web_fetch`.
14. The simplified browser design is sound only with the invisible relay controls M1-M6 and one host/state-change anchored confirm binding for sensitive hydrated-origin writes.

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

### Decision 3: Native Compute Is Allowed Inside The Hardened Envelope

The earlier "relay-served MCP tools only" target was too restrictive. It made the contained runtime safe, but not useful enough as a personal Hermes agent.

Approved direction:

- Enable native `terminal`, `process`, `file`, `code_execution`, and practical media/vision tools for operator-private Hermes after the W2 hostile-peer and runtime gates pass.
- Keep native compute bound to container-local scratch/workspace state, read-only curated mounts, no secret volumes, no Docker socket, no host home access, no provider/vault/model/connector/LAN reachability, and bounded CPU/memory/PID limits.
- Treat native `code_execution` as an accelerator for allowed local tool chains, not as a way to reach provider credentials or bypass relay policy.
- Keep `verify-live.runtime.toolset_inventory` as a signed allowlist gate. Widen the expected set deliberately; do not remove the gate.
- Keep privileged, durable, cross-boundary, connector, provider, outbound, memory, schedule, and approval actions relay-owned unless a separate proof explicitly moves a surface.

Native compute changes the blast radius, so it needs live hostile-peer evidence before production enablement. It does not require forbidding useful shell/code/file operations forever.

### Decision 4: Public Web Is Useful, But It Is Data

Public web search/fetch should be enabled for the operator-private profile. Simple public fetch/search can use relay MCP tools. JS-heavy or bot-hostile pages should use a browser broker or explicitly governed public egress path. Web results are always untrusted external content. They can inform answers or proposed side effects; they cannot authorize actions or become trusted memory without human confirmation.

Implementation must enforce this at the relay memory boundary. Web and inbound channel data must be tagged as external-derived provenance, and trusted memory writes from those sources must require an explicit confirmation policy instead of relying on the agent prompt.

Authenticated service browsing is not the default way to access Google, banking, WhatsApp, email, or home services. Those stay typed, relay-mediated providers/connectors with approval and step-up.

### Decision 5: Browser Uses A Simple UX With Relay-Side Session Controls

The user-facing browser shape is one brokered `tc_browse` tool family behind one `browse.use` authority. There is no global public-web allowlist, read/act split, read-mode GET/HEAD policy, TLS MITM, or per-click ledger.

A separate hardened browser plus relay-owned credentials handles process escape, SSRF, and credential theft. It does not by itself solve live authenticated-session authority, so the relay must enforce these invisible controls:

- M1: origin-bind egress for cookie-bearing contexts. While a context carries hydrated login state for an approved origin set, CONNECT targets must remain within that credential profile. Cross-origin top-level navigation forks a fresh cookie-less context.
- M2: hydrate only the target site's cookie state. Never hydrate a portfolio-wide cookie jar.
- M3: pin the CONNECT upstream socket to the validated IP, re-check private/non-overridable ranges at dial time, and preserve original SNI/Host.
- M4: enforce outbound client-to-upstream byte budgets plus per-actor and per-session rate caps at the CONNECT proxy.
- M5: run the shared web-egress secret/private-data preflight on broker-visible navigation URLs and typed/submitted strings.
- M6: create fresh ephemeral browser contexts and discard all browser storage on close except the relay-owned encrypted cookie store.
- Browser write confirm: on a sensitive hydrated origin, a state-changing or ambiguous commit freezes and requires host/state-change anchored approval bound to `sessionRef`, actor, approver, profile, hydrated origin scope, destination host, submitted-values hash, screenshot/attachment hash, TTL, and approval revision.

Catastrophic surfaces require fresh login every time through use-time noVNC/session-capture and do not receive standing sessions by default: primary-email root/admin, bank account-management/payee/admin, and security settings.

There is no relay CA, TLS termination, or HTTPS body inspection. Reopen TLS termination only if browser exfil residuals prove unacceptable in live probes or red-team tests, and accept the stealth cost explicitly before enabling it.

### Decision 6: Writes Need Fresh Step-Up

The existing approval-token and side-effect ledger pattern remains the core. Add fresh step-up before minting a side-effect approval token according to risk:

- Low-risk local reversible actions: approval card or `/approve`.
- Provider writes: fresh TOTP or passkey-backed approval.
- Public sharing, account changes, destructive actions: passkey or independent admin channel.
- Bank transfers/new payees: bank-native SCA plus relay step-up.

### Decision 7: Home Services Are Providers, Not Private Web Targets

For personal/family deployment, home/LAN stays blocked from Hermes. Home Assistant, NAS, cameras, locks, and similar services must be exposed as typed relay-owned home providers with read/write policies, not direct `WebFetch` private endpoints.

## Policy Matrix

| Surface | Read Policy | Write Policy | Step-Up | MVP Status |
| --- | --- | --- | --- | --- |
| Native container compute | Allow signed native `terminal`, `process`, `file`, `code_execution`, and useful media/vision tools inside hardened container after hostile-peer gates | Scratch/workspace writes only; no provider, connector, memory, approval, or outbound side effects except through relay tools | None for local scratch compute; relay approval for any external side effect | Enable after W2 |
| Delegation/sub-agents | Allow only after child authority inheritance/narrowing is proven | No child authority widening, recursive fanout beyond limits, or cross-profile memory/provider access | Same as parent authority plus child budget/TTL | After native compute proof |
| Public web/browser | Allow `tc_web_search`, `tc_web_fetch`, and brokered Camoufox `tc_browse` under one `browse.use` authority; browser egress is CONNECT-validated without TLS MITM; persistent login state is relay-owned credential-class browser state, not runtime state | No per-click ledger and no read/act split; sensitive hydrated-origin state changes require one host/state-change anchored browser approval binding; catastrophic surfaces require fresh use-time noVNC/session-capture, not standing cookies | None for ordinary public or unauthenticated browsing; approval to create/import/activate persistent login state; light confirm for sensitive authenticated writes | Full scope locked |
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

### Slice 3: Native Container Compute For Operator-Private

Goal: make Hermes useful again by enabling native in-container compute without making the runtime a credential or network boundary.

Tasks:

1. Build the live hostile-peer runner and make it mandatory for widened native-tool profiles.
2. Add an explicit profile/native-tool policy, starting with operator-private `terminal`, `process`, `file`, `code_execution`, and practical media/vision tools.
3. Update generated Hermes config by widening `platform_toolsets.api_server` and removing only the approved native toolsets from `agent.disabled_toolsets`.
4. Keep `verify-live.runtime.toolset_inventory` fail-closed, but point it at the widened signed expected set for the selected profile.
5. Provide a deliberate scratch/workspace mount for local compute. Keep rootfs read-only, curated skills read-only, no host home, no secret volumes, no Docker socket, no provider sidecar mounts, no connector bridge mounts.
6. Add terminal/code/file probes for env, config, auth, log, and filesystem custody: no root tokens, no raw provider credentials, no relay private config, no OAuth stores, no TOTP/vault material, no host SSH/cloud creds, no skill/config/auth self-modification, no symlink/path escape.
7. Add egress probes from terminal/code: no provider/vault/model/RFC1918/metadata/DNS-rebind/DoH/WebSocket/proxy/SMTP/IMAP/WhatsApp reachability except through approved relay/broker surfaces.
8. Add code-execution probes for bounded stdout/stderr, timeout/tool-call limits, child env scrubbing, no persistent daemons, and no plugin/import path injection.

Exit criteria:

- Operator-private Hermes can run shell/code/file tasks inside the container and produce useful artifacts.
- The runtime still has no raw service/model/provider/connector credentials and no direct privileged egress.
- `verify-live`, hostile-peer, no-fork, and network probes pass with the widened native toolset.

### Slice 4: Public Web And Browser Broker

Goal: make the agent browse public web usefully, including JS-heavy pages, bot-defended targets, authenticated sessions, and approved interactions, while keeping browser credentials, network egress policy, and authenticated-session authority in the relay.

Locked scope:

- Engine: Camoufox, not plain Playwright, because bot-defended targets are in scope.
- Tool surface: one brokered `tc_browse` tool family under one `browse.use` capability.
- No global public-web allowlist, no read/act split, no read-mode request policy, no TLS MITM, no per-click ledger.
- Persistent login cookies are in scope only as relay-owned credential-class state.
- Catastrophic surfaces require fresh use-time noVNC/session-capture and never get standing cookies by default.

Tasks:

1. Ensure private/operator profile gets explicit `web.search`, `web.fetch`, and `browse.use`.
2. Confirm live MCP tool wiring, web search provider config, and permissive public-fetch mode where intended.
3. Keep DNS-pinned SSRF guard, redirect revalidation, content-type allowlist, redaction, truncation, audit, and external-content wrapping for `tc_web_search`/`tc_web_fetch`.
4. Run browser execution in separate `tc-browser` trust domain, not inside `tc-hermes-contained`: relay-owned internal-only Camoufox container on its own network, no provider/connector/model/vault access, no secret volumes, no runtime-held cookies, no direct agent-container reachability.
5. Put Playwright/Camoufox client in relay-side browser broker. Hermes sees only `tc_browse` tool family and opaque `sessionRef`s.
6. Make `sessionRef` opaque, relay-issued, actor/profile/domain-bound, TTL-bound, and non-reusable across private/social/household authorities.
7. Force browser egress through relay-owned CONNECT proxy and kernel firewall backstop. Proxy validates CONNECT host/IP, blocks private/metadata/provider/vault/model reachability, pins dial to validated IP, rechecks blocked ranges at dial, preserves original SNI/Host, audits, and does not terminate TLS.
8. Make egress proxy session/context-aware. Broker supplies per-context credential/token bound to `{sessionRef, actor, hydratedOriginScope}`; proxy rejects browser tunnels without valid context identity.
9. Implement M1 origin-bound egress for cookie-bearing contexts; while hydrated session active, CONNECT targets limited to approved login-origin set; cross-origin top-level navigation forks fresh cookie-less context.
10. Implement M2 per-target cookie hydration; hydrate only navigated host's credential-profile storageState, never portfolio-wide jar.
11. Implement M3 rebind acceptance test and IPv6/NAT64 canonicalization hardening before deployment.
12. Implement M4 client-to-upstream byte budget plus per actor/session rate cap in CONNECT pipe.
13. Implement M5 shared egress preflight helper for broker-visible nav URLs and typed/submitted strings; helper shared with `tc_web_*`.
14. Implement M6 fresh ephemeral browser contexts; discard all service workers, IndexedDB, localStorage, HSTS, and other browser storage on close; persist only via relay-owned encrypted cookie store.
15. Add persistent browser credential store in relay, not `tc-browser`: encrypted at rest, domain/origin-set/authority-scoped, profile-bound, versioned, auditable, revocable, never exposed to Hermes.
16. Provision standing browser login state through one-time human session-capture (`enroll-session` pattern). Operator logs in through relay-owned hosted/noVNC browser; relay captures Playwright `storageState`; no password/passkey/OTP seed/recovery credential stored. Mid-task re-auth/CAPTCHA/passkey/password prompts fail to human reprovisioning.
17. Mark catastrophic surfaces in credential-profile policy: primary-email root/admin, bank account-management/payee/admin, security settings. These require fresh use-time noVNC/session-capture and receive no standing session by default.
18. Require operator approval to create/import/activate/refresh/persist browser login profile. Treat persistent cookie activation as credential use, not a public-web read.
19. Add host/state-change anchored confirm for sensitive hydrated-origin writes. Trigger on sensitive hydrated origin plus state-changing or ambiguous commit observed through Playwright routing/events and broker-known action intent; fail closed on ambiguous sensitive commits. Bind approval to browser side-effect record: actionRef/sessionRef, actor/approver/profile, hydrated origin scope, destination host, submitted-values hash, screenshot/attachment hash, TTL, approval revision.
20. Return page text/accessibility/link summaries through `redactSecrets` and `wrapExternalContent`; screenshots return short-lived attachment refs, never inline bytes. Do not treat these as action-side security controls.
21. Add fixtures/probes for allowed unauth public browse, denied RFC1918/metadata/provider/vault/model, validated-IP CONNECT pin/rebind denial, no relay CA/no TLS MITM assumptions, denied browser tunnel without context identity, cookie-bearing context cannot egress outside approved login-origin set, cross-origin navigation forks cookie-less context, per-target cookie hydration/no portfolio jar, byte-budget exhaustion, egress preflight denial, ephemeral storage discard, catastrophic standing-session denial, and sensitive hydrated write confirm binding.

Exit criteria:

- Operator can search/read public web and use brokered Camoufox with free unauthenticated interaction.
- Browser containment proves separate internal-only trust domain, no direct Hermes runtime/container/provider/vault/model/LAN reachability, and all internet egress via relay browser proxy.
- Unauthenticated public browsing remains open; cookie-bearing contexts cannot egress outside their approved login-origin set.
- CONNECT proxy proves no MITM, validated-IP pinning, rebind denial, byte budget, context identity requirement, and RFC1918/metadata block at validation and dial.
- Persistent login state can be used only through relay broker and under scoped operator authority; catastrophic surfaces are fresh-login only.
- Sensitive hydrated-origin writes are host/state-change confirmed and approval-bound; no per-click ledger or read/act split is required.

Slice 4 lane split:

- S0 containment and egress-proxy infra, owned by Codex: `docker/Dockerfile.browser`, `docker-compose.browser.yml`, `telclaude-browser` network, firewall extension, Camoufox digest pin/canary, browser containment signed probe, CONNECT host/IP validation, M3 validated-IP pin + rebind test, M4 byte budget, no-MITM proof, and `verify-live` gates.
- Broker/session layer, owned by Claude: per-context proxy token, M1 origin-scope policy fed by broker/cookie store, M2 cookie hydration, M5 shared egress preflight helper, relay Playwright/Camoufox broker, `tc_browse` tool surface, cookie store, session-capture provisioning, and browser approval binding.
- S0 must be green before broker/session layers ship.

### Slice 5: Service Enrollment UX

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

### Slice 6: Google Useful Core

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

### Slice 7: WhatsApp Outbound

Goal: let the same operator-private Hermes profile reply/send through WhatsApp safely.

Tasks:

1. Configure WhatsApp bridge as a relay edge sidecar on its own network.
2. Keep bridge credentials out of Hermes.
3. Register WhatsApp as an outbound channel only for authorized profile/channel identities.
4. Route outbound through `tc_outbound_prepare` and `tc_outbound_execute`.
5. Approval prompt shows exact recipient/thread/body/attachments/hash/TTL/idempotency key.
6. Add negative probes for wrong recipient, changed body, wrong conversation attachment, replayed idempotency key, missing sidecar, direct credential injection.
7. Bridge contract: implement `POST /v1/whatsapp/send` and `GET /health`; verify relay-issued `x-telclaude-whatsapp-session-key`, `x-telclaude-whatsapp-request-digest`, expiry, and shared-secret HMAC against the exact request body before sending; pin the bridge image by digest once published.

Exit criteria:

- Operator can ask the same Hermes agent to send/reply on WhatsApp.
- Sends are edge-owned and side-effect-ledger-owned.

### Slice 8: WhatsApp And Email Inbound CL-1

Goal: safely let WhatsApp/email initiate conversations into the same Hermes-backed assistant.

Tasks:

1. Implement inbound listener pipeline: signature/auth verification, dedup, cursor/replay handling, attachment quarantine, risk wrapping, identity lookup, trust-domain assignment, and conversation token minting.
2. Strong-link operator WhatsApp/email to operator-private authority.
3. Strong-link family identities to household authority.
4. Treat external email as public/untrusted and proposal-only.
5. Add group handling rules before enabling WhatsApp group chats.
6. Wired for the operator WhatsApp path: the bridge POSTs signed inbound events to `POST /v1/whatsapp/inbound`, the endpoint calls the complete CL-1 pipeline, and only sanitized events dispatch into Hermes.
7. Inbound bridge signing contract: compute HMAC over the post-schema-default canonical object that the relay verifies, including defaulted fields such as `attachments: []`; signing a sparse pre-default payload must fail closed.
8. Operator-only W-B may use a static operator address allowlist; Telegram `/approve` strong-link pairing and household/multi-number pairing remain separate operator-gated follow-up work.

Exit criteria:

- Inbound WhatsApp/email can reach Hermes only as sanitized, domain-bound, identity-bound content.
- No inbound channel can smuggle authority fields or raw credentials.

### Slice 9: Durable High-Risk Side Effects

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

### Slice 10: Bank And Home Providers

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
4. Widened native toolsets match the signed expected allowlist for the active profile; unexpected native tools fail closed.
5. Native terminal/code/file cannot read relay private config, OAuth stores, vault/TOTP material, host SSH/cloud credentials, or runtime root tokens.
6. Native terminal/code/file cannot write managed skills, Hermes config/auth, relay state, or paths outside the approved scratch/workspace boundary.
7. Native terminal/code/file cannot reach RFC1918, metadata, provider, vault, model, connector, or bridge hosts except through approved relay/broker surfaces.
8. Public web can fetch public content but cannot reach RFC1918, metadata, provider, vault, model, or bridge hosts.
9. Web content is wrapped as untrusted and cannot become trusted memory without human confirmation.
10. Browser containment proves the browser runtime is a separate internal-only trust domain, not reachable from Hermes runtime containers, and cannot egress except through the relay browser proxy.
11. Browser egress proxy proves the locked no-MITM posture: CONNECT host/IP validation is enforced, no relay CA is installed in `tc-browser`, and no required gate depends on HTTPS body inspection.
12. CONNECT proxy dials the validated IP, rechecks blocked ranges at dial, preserves original SNI/Host, and has a rebind denial test.
13. Browser tunnels require relay-issued context identity; cookie-bearing contexts cannot egress outside their approved login-origin set, and unauthenticated public browsing stays open.
14. Persistent browser cookies are encrypted at rest, relay-owned, domain/origin-set/authority-scoped, activation-approved, revocable, and never present in Hermes runtime config/env/logs.
15. Browser contexts hydrate only the target credential profile, never a portfolio jar, and discard all non-relay-owned browser storage on close.
16. Sensitive hydrated-origin writes require host/state-change anchored approval binding; no read/act split or per-click ledger is required.
17. Catastrophic browser surfaces have no standing session by default and require fresh use-time noVNC/session-capture.
18. Delegation cannot widen parent authority, cross memory domains, bypass profile/channel scopes, or create unbounded fanout.
19. Google reads route through relay/sidecar only.
20. Google writes require fresh step-up and exact approval-token binding.
21. WhatsApp outbound cannot mutate recipient/body/attachment after approval.
22. WhatsApp/email inbound remains dark until CL-1 passes.
23. Household and external domains cannot read operator-private memory or provider PII.
24. Cutover/probe evidence is signed, fresh, and origin-bound where applicable.

## Initial Build Order

1. Slice 0: current-state proof.
2. Slice 1: remove runtime token custody.
3. Slice 2: explicit profile/channel authority.
4. Slice 3: native container compute for operator-private.
5. Slice 4: public web and browser broker.
6. Slice 5: service enrollment UX.
7. Slice 6: Google useful core.
8. Slice 7: WhatsApp outbound.
9. Slice 8: WhatsApp/email inbound CL-1.
10. Slice 9: durable high-risk side effects.
11. Slice 10: bank/home providers.

## Definition Of Done For "Personal Agent MVP"

The MVP is done when:

1. The same Hermes-backed operator-private profile can be reached from Telegram and at least one additional strong-linked channel.
2. The agent can run useful native shell/code/file tasks inside the hardened container, with hostile-peer and egress gates green.
3. The agent can search/fetch public web, use brokered Camoufox sessions where ordinary fetch is insufficient, activate relay-owned persistent login state under approval, and perform sensitive hydrated-origin writes only through the host/state-change browser approval binding.
4. The agent can read Google/Gmail/Calendar/Drive/Contacts through relay providers.
5. The agent can prepare at least Gmail draft and self-only calendar event writes with fresh step-up approval.
6. The agent can send/reply through WhatsApp outbound as an edge-owned prepared side effect.
7. No connector/provider/model/vault token is present in the contained Hermes runtime except non-root, short-lived, peer-bound handles with replay denial.
8. All privileged actions are auditable and replay-denied.
9. Household and external channels cannot reach operator-private authority.

## Explicit Non-Goals For MVP

1. Bank transfers.
2. Drive public sharing/deletion.
3. Email send without a separate approval policy.
4. WhatsApp group autonomy.
5. Runtime-held browser cookies or direct authenticated service browser sessions inside Hermes.
6. Standing browser sessions for catastrophic surfaces unless explicitly named later by the operator.
7. Direct LAN/Home Assistant/NAS access from Hermes.
8. Direct host-home, host-filesystem, Docker socket, or unrestricted host terminal access from Hermes.
9. Provider enrollment through an agent-held browser cookie.
10. Any use of prompt instructions as a security boundary.
