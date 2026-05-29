# Spec: Telclaude No-Fork Hermes Wrapper

Date: 2026-05-29
Status: Draft for operator review

## Objective

Build Telclaude into a pristine no-fork wrapper around upstream Hermes, with
complete Telclaude parity proven before any production cutover.

The wrapper must make Hermes more useful, not smaller. The target is a capable
personal and household AI: available over WhatsApp/email/social, able to help
the operator and family, able to use bank/health/government/provider sidecars,
able to browse and automate, and able to run long-lived workflows. The security
envelope grants powers through scoped capability channels instead of handing the
agent raw credentials.

Hermes should own the broad agent operating-system surface: profiles, CLI/TUI,
gateways, toolsets, MCP, skills, plugins, cron, session state, terminal/browser
tools, WhatsApp, email, and public identity workflows.

Telclaude should own the hard security and identity envelope: private ingress,
auth, approval semantics, vault/proxy/sidecar mediation, signed write tokens,
streaming redaction, public/private memory authority, skill provenance, audit,
process/container/network policy, and cutover validation.

This is not a Hermes fork and not a patch against Hermes main. Telclaude should
consume pinned upstream Hermes releases plus documented extension surfaces:
profiles, config generation, plugins, platform adapters, memory providers, MCP
servers, toolsets, and deployment wrappers.

## Assumptions

- Production migration is all-or-nothing per approved workflow bundle. Shadowing
  and dry runs are allowed for proof, but not as gradual production replacement.
- Telclaude is still alpha; clean breaks inside Telclaude are acceptable when
  they reduce migration complexity or preserve the security model.
- Public identity credentials should be dedicated, but production credentials
  live in Telclaude edge sidecars or vault namespaces, not in the Hermes process
  or `.env`. Direct Hermes channel credentials are allowed only for disposable
  shadow/testing profiles with an explicit downgrade note.
- Social identity is not the highest barrier. Autonomous access to skills,
  browser, terminal, messaging, and web/computer tools is the real barrier and
  must be controlled at the process/network boundary.
- Hook/plugin/toolset controls are useful, but they are not hard security
  boundaries.
- Provider powers are expected, not exceptional. Banking, Clalit/health,
  government, Google, and other sidecars should be exposed as high-quality
  Hermes tools with schemas, budgets, approvals, and audit.

## Production Parity Rules

### Cutover scope manifest

Before Phase 0 can complete, Telclaude must produce a cutover scope manifest.
Every workflow row must include:

- `workflow_id`
- owner
- trust domain
- current Telclaude behavior
- Hermes target behavior
- P0/P1/P2 class
- included, excluded, or disabled status
- parity fixture IDs
- negative/adversarial fixture IDs for side-effecting workflows
- rollback owner

`telclaude hermes cutover-check --strict` fails if an included workflow has no
scope row, no fixture, unresolved decision, unsafe evidence, or no rollback
owner.

### Evidence rules

Only pinned-Hermes, edge-mediated, sidecar/vault-owned runs count as production
parity evidence. Direct native Hermes WhatsApp, email, AgentMail, social,
provider, or model credentials are smoke tests only. They never satisfy
`G-EDGE-ADAPTERS`, public identity, email, WhatsApp, AgentMail, model/provider,
or cutover gates.

Shadow runs are useful only when they exercise the same Telclaude edge, sidecar,
vault, identity, approval, redaction, and network paths planned for production.

### Fork-free seam proof

No production gate passes until a fresh pinned upstream Hermes install plus the
Telclaude wrapper package can run the included P0 fixtures with the Hermes
checkout clean. The proof command set must verify:

- no Hermes fork, patch file, vendored source edit, monkeypatch, or runtime source
  replacement is required
- generated profiles and wrapper plugins/adapters are the only Hermes-adjacent
  artifacts
- channel event injection, outbound send routing, headless/private execution,
  model routing, memory provider, cron delivery, browser/computer mediation, and
  control-room status all use documented extension surfaces or wrapper-owned
  process boundaries
- `git diff --exit-code` passes in the Hermes checkout after the fixture suite

If a required seam cannot be proven against the pinned Hermes version, the
affected workflow bundle stays disabled instead of becoming a fork.

### Decision log

Open decisions are not allowed to remain as prose when a workflow enters the
included cutover set. Each decision must have:

- owner
- deadline phase
- accepted answer
- affected workflows
- cutover impact
- downgrade note when applicable

Private execution contract, edge adapter seam, email/AgentMail seam, model relay,
family identity assurance, provider routine-action policy, and first cutover
workflow scope are blocker decisions for any workflow that depends on them.

### Cutover checker contract

`telclaude hermes cutover-check --strict --json` consumes:

- inventory snapshot
- cutover scope manifest
- decision log
- Hermes compatibility lockfile
- feature-probe matrix result
- fixture result bundle
- no-fork proof bundle
- network probe bundle
- queue/approval/card/cron/social/provider snapshot
- rollback rehearsal evidence

It emits `cutover-report.json` with `status`, per-gate pass/fail entries,
workflow IDs, evidence paths, decision IDs, downgrade notes, and remediation
owners. Exit code `0` means the included workflow set is safe to cut over, `1`
means a gate failed or unsafe evidence was used, and `2` means checker inputs are
missing, stale, malformed, or not tied to the pinned Hermes artifact.

## Source Evidence

### Telclaude invariants

- `CLAUDE.md` requires clean TypeScript, no compatibility cruft before 1.0, and
  preserves Telclaude's tier, hook, approval, secret-filter, network, profile,
  and SOCIAL skill-allowlist rules.
- `docs/architecture.md` defines the relay/agent split, private/social memory
  air gap, provider sidecars, approval-token model, firewall backstops, and
  security invariants.
- `docs/operator-playbook.md` describes Telclaude as the secure Telegram
  operator surface where relay, vault, private/social profiles, cron, and signed
  webhooks remain the control plane.

### Hermes extension evidence

- Hermes plugins add tools, hooks, slash commands, CLI commands, bundled skills,
  gateway platforms, image/video/context/memory/model providers, and host-owned
  LLM calls without core changes:
  `/home/user/MyProjects/hermes-agent/website/docs/user-guide/features/plugins.md`.
- Hermes hooks are explicitly non-blocking; errors are logged and the agent
  continues:
  `/home/user/MyProjects/hermes-agent/website/docs/user-guide/features/hooks.md`.
- Hermes profiles create separate `HERMES_HOME` state directories, but do not
  sandbox filesystem access:
  `/home/user/MyProjects/hermes-agent/website/docs/user-guide/profiles.md`.
- Hermes platform adapters can be added as plugins and automatically integrate
  gateway config, authorization, cron delivery, `send_message`, setup/status,
  token locks, and platform hints:
  `/home/user/MyProjects/hermes-agent/website/docs/developer-guide/adding-platform-adapters.md`.
- Hermes WhatsApp uses a built-in Baileys bridge, stores full session
  credentials under the profile, recommends a dedicated number, and warns
  against bulk/cold outbound:
  `/home/user/MyProjects/hermes-agent/website/docs/user-guide/messaging/whatsapp.md`.
- Hermes email uses IMAP/SMTP, requires a dedicated mailbox, stores an app
  password in `.env`, supports allowlists, reply threading, and attachment
  caching:
  `/home/user/MyProjects/hermes-agent/website/docs/user-guide/messaging/email.md`.
- Hermes AgentMail is an optional MCP-backed skill for agent-owned inboxes:
  `/home/user/MyProjects/hermes-agent/website/docs/user-guide/skills/optional/email/email-agentmail.md`.

### Current upstream dependency risk

Do not depend on unmerged upstream work for the wrapper:

- `NousResearch/hermes-agent#4816` gateway terminal-backend sandbox override is
  an open PR.
- `NousResearch/hermes-agent#30179` iron-proxy credential-injection firewall is
  an open PR.
- `NousResearch/hermes-agent#34348` outbound communication approval gate is an
  open issue.
- `NousResearch/hermes-agent#18715` split runtime/local tool execution is an
  open issue.

The wrapper must work against pinned upstream Hermes without these PRs/issues.

### X/community learnings

The eight X posts supplied by the operator were read through `xurl` on
2026-05-29. The spec uses them as directional product input, not security proof.

- Hermes is being treated as a deep, persistent runtime that pairs well with
  faster workers. Telclaude should preserve optional routing to Codex, Claude,
  Pi-style light agents, or other workers when Hermes is not the right executor.
- The "control room" pattern matters: one control plane, many isolated agents,
  specialist runtimes, task routing, and observable state.
- `HERMES_HOME` is the real artifact: config, `.env`, `auth.json`, `SOUL.md`,
  memory, sessions, state DB, skills, cron, plugins, hooks, skins, and logs.
  The generator must treat this as sensitive reproducible state.
- Community examples lean into prompt-driven self-configuration. Telclaude must
  treat guardrail config, including `mcp_servers`, toolsets, terminal backend,
  memory provider, plugins, and `SOUL.md`, as relay-owned reviewable state, not
  as agent-mutated runtime scratch.
- The practical growth path is one lived-in agent, then specialists with their
  own credentials/memory, then orchestration, then automated cron workflows.
- Chief-of-staff workflows are central: daily brief, meeting prep, trend radar,
  support email triage, weekly business report, bookmark inbox, humanizer, and
  Obsidian/wiki memory.
- Public identity needs WhatsApp, email, social handles, outbound delivery,
  attachment handling, and durable memory, but with separate trust domains.
- Hermes Curator is useful for agent-created skill hygiene, but Telclaude
  critical skills must remain pinned, reviewed, signed, or immutable.
- Hermes should be adopted as an agent OS, not just as a chatbot.

## Target Architecture

### Layer 1: Telclaude outer envelope

Telclaude remains the owning layer for:

- Private Telegram ingress and pre-LLM authorization.
- Pre-LLM ingress authorization and infra-secret blocking for every production
  channel, including WhatsApp, email, AgentMail, and social webhooks.
- TOTP/session/rate-limit gates.
- Approval cards, callback identity checks, stale-waiter handling, and durable
  approval state.
- Vault, credential proxy, provider proxy, Google/other provider sidecars.
- Model-provider credentials and LLM endpoint routing. No production Hermes
  process receives raw model/API/provider credentials.
- Ed25519 signed action tokens for provider writes, bound to actor, service,
  action, params hash, profile/domain, provider account, approver identity,
  approval request/card ID and revision, WYSIWYS approval render, idempotency
  key, 60-second relay TTL, sidecar max TTL of 300 seconds, and one-time JTI.
- Streaming redaction before any output leaves to Telegram, WhatsApp, email,
  social platforms, logs, or dashboards.
- Memory authority: private `telegram:<profile>` sources, public/social sources,
  provenance, sanitizer, trust/quarantine, and runtime assertions.
- Skill/plugin supply-chain controls: scanner, signer, allowlist, immutable
  core skills, SOCIAL fail-closed posture.
- Whole-process launch policy for every Hermes trust domain.
- Per-domain proxy/vault/memory/send endpoints selected by physical reachability
  such as network namespace or Unix socket, not by LLM-supplied fields.
- Read-only ownership of guardrail config, plugin roots, model-provider roots,
  memory-provider roots, and promoted skills.
- Parity inventory, replay, shadow, and cutover gates.

### Layer 2: Hermes runtime

Hermes becomes the pinned upstream runtime for:

- Agent loop and model/runtime ergonomics.
- Profiles and `HERMES_HOME` state.
- CLI/TUI/dashboard/control-room surfaces.
- Gateway channels that fit the profile risk model.
- WhatsApp and email for dedicated public identity domains.
- WhatsApp and email transport only when fronted by a Telclaude production edge
  sidecar, or when explicitly marked disposable/shadow downgrade.
- Household assistant surfaces for family members over WhatsApp/email, with
  per-person scopes and consent, not a private-operator-only chatbot.
- Skills, Curator, plugins, toolsets, cron, background jobs, MCP.
- Terminal, browser, file, web, vision, messaging, and delegation tools when
  permitted by the trust domain.
- Session search and long-lived operator workflow state.

### Layer 3: No-fork extension package

Telclaude should ship a wrapper package that installs next to Hermes:

- A Telclaude CLI command group, `telclaude hermes ...`.
- A profile/config generator that emits reproducible `HERMES_HOME` trees.
- A Telclaude MCP server exposing provider, memory, approval, attachment, and
  outbound capabilities through narrow schemas.
- A small Hermes plugin for slash commands, tool registration, toolset labels,
  optional soft hooks, and control-room UX.
- Optional Hermes platform adapters that talk to Telclaude sidecars when native
  channel credentials must not live inside Hermes.
- A public identity bootstrapper for WhatsApp, email, AgentMail, and social
  handles.
- A parity harness and cutover checker.

The Hermes plugin is convenience glue. The MCP/sidecar/process boundary is the
security boundary.

### Fork-free production edge adapters

Production WhatsApp, email, AgentMail, and social channels require an explicit
adapter seam, not just a policy statement:

- **Ingress bridge:** Telclaude edge receives the raw platform event, authorizes
  the actor/thread, quarantines media, classifies risk, records audit metadata,
  then forwards a sanitized event into the correct Hermes profile/session.
- **Outbound bridge:** Hermes emits a typed send request to Telclaude. Telclaude
  applies redaction, recipient/thread policy, approval-token checks when needed,
  rate budgets, and final transport delivery.
- **Status bridge:** Hermes can read setup/status/health through sidecar-owned
  views, but cannot read raw app passwords, WhatsApp session files, social API
  tokens, SMTP/IMAP credentials, cookies, or provider OAuth secrets.
- **Adapter form:** prefer Hermes plugin platform adapters where the upstream
  extension surface is stable; otherwise use a Telclaude MCP/tool bridge plus a
  generated Hermes profile manifest. Either way, production credentials remain
  sidecar/vault-owned.

This is the required production seam for channel parity. In production, Hermes
owns the conversation/session/tool UX while Telclaude edge adapters own all real
transport credentials, ingress, and egress. Native Hermes WhatsApp/email/
AgentMail/social transports are never enabled in production profiles; direct
native Hermes channel credentials are shadow-only downgrade evidence.

### Edge adapter contract

Every production channel adapter must expose typed contracts and a pinned-Hermes
feature probe before it can enter the included cutover set.

Required types:

- `InboundEvent`: channel, conversationRef, actorRef, receivedAt, normalized
  text/media refs, risk labels, source audit metadata.
- `ConversationRef`: channel, thread/chat ID, profile/domain, recipient set,
  routing session, authorization state.
- `ActorRef`: Telclaude actor ID, channel identity, identity assurance level,
  scopes, revocation state.
- `AttachmentRef`: quarantine ID, media type, scan state, size, content hash,
  trust label, expiry.
- `OutboundRequest`: Hermes-supplied request only: channel, recipient/thread
  handle, requested body, media refs, conversationRef, and correlation ID. It
  never contains `outboundRef`, authorizing actor, policy result, approval state,
  or transport credentials.
- `PreparedOutbound`: Telclaude-derived state: outboundRef, channel, resolved
  destination, final rendered body, media refs, authorizing actor, policy result,
  approval requirement, idempotency key, and side-effect ledger ref.
- `OutboundDecision`: allowed/approval_required/denied, reason, approval token
  or approval request when applicable, and prepared outbound ref when one was
  created.
- `DeliveryReceipt`: outboundRef, platform message ID, delivery status,
  timestamps, retry/idempotency state.
- `StatusView`: setup health, sidecar health, credential presence status,
  rate-budget state, no raw secrets.

Contracts are versioned JSON Schema plus generated Zod validators owned by the
wrapper package. Each adapter implements these operations:

- `ingest(InboundEvent) -> IngestAck`
- `prepareOutbound(OutboundRequest) -> OutboundDecision`
- `executeOutbound(outboundRef, approvalToken?) -> DeliveryReceipt`
- `status() -> StatusView`
- `ack(platformMessageId, receiptState) -> DeliveryReceipt`

The schemas include auth binding, payload limits, idempotency keys, ordering
cursor, duplicate handling, retry policy, dead-letter behavior, and attachment
lifecycle state. Attachments move by `AttachmentRef` only; raw bytes stay in the
quarantine store until the receiving domain is authorized.

The wrapper must feature-probe one fork-free path per channel: Hermes plugin
platform adapter, MCP/tool event bridge, or CLI/API event injection. If no stable
path exists for the pinned Hermes release, the channel remains disabled for
production cutover.

### Feature-probe matrix

The wrapper maintains a machine-readable probe matrix at
`docs/hermes/feature-probes.json` and copies the evaluated result into each
generated profile manifest. Every row includes:

- `surface_id`
- pinned Hermes version/commit/package/image digest
- documented extension seam
- probe command or fixture ID
- expected positive result
- negative probe
- evidence path
- compatibility-lockfile key
- disabled/downgrade outcome if the probe fails

Feature probes are contracts only after they pass against the pinned Hermes
artifact. Docs and source hashes are drift signals that trigger re-probe; the
actual production contract is the passing probe, adapter signature, and parity
fixture result.

## Trust Domains

| Domain | Hermes profile | Purpose | Workspace | Memory | Credentials | Required boundary |
|---|---|---|---|---|---|---|
| Private operator | `tc-private-<profile>` | Private Telegram and privileged work | Explicit mounts only | `telegram:<profile>` sanitized | No raw provider/API secrets | Telclaude fronted ingress, container/network policy |
| Shadow private | `tc-shadow-private-<profile>` | Replay and comparison | Test/work copy only | replay snapshot | No production send/write creds | Dry-run sidecars only |
| Public identity | `tc-public` | WhatsApp/email/social public persona | No private workspace | public/social only | Dedicated public creds in sidecars/vault | Separate process/container, inbound and outbound edge policy |
| Household assistant | `tc-household` or family-scoped public profile | Family WhatsApp/email assistant | No private workspace by default | household scoped | Channel creds in sidecar/vault | Separate process/container, edge policy, per-person authorization, consent, provider scopes |
| Public channel split | `tc-public-whatsapp`, `tc-public-email`, etc. | Per-channel isolation if needed | No private workspace | Telclaude-mediated public memory | One channel only | Stronger blast-radius split |
| Specialist | `tc-worker-<role>` | Marketing, research, support, code, curator | Role-specific | role-specific | role-specific or none | Toolset and egress based on role |
| Control room | `tc-control` | Operator dashboard/orchestration | Read-only manifests | registry/audit | no raw runtime secrets | Cannot become a credential authority |

Profiles are state separation, not sandboxes. Any domain with autonomous
terminal/browser/web/computer access must run in a whole-process OS/container
boundary.

## Identity And Actor Migration

Identity migration is a first-class parity surface. Session IDs and Hermes
profile names are routing handles only; authorization comes from Telclaude actor
records and edge policy.

| Actor class | Existing source | Hermes target | Required parity |
|---|---|---|---|
| Private operator | Telegram admin claim, TOTP/session state, profile binding | `tc-private-<profile>` | claim, TOTP challenge/logout/disable/skip, tier, rate limit, `/new`, profile switch |
| Family member | WhatsApp contact plus explicit strong link for sensitive scopes | `tc-household` or scoped public profile | contact-only benign household access, strong-link provider access, consent, relationship, private-memory denial |
| Public sender | WhatsApp/email/social thread identity | `tc-public` or per-channel profile | allowlist/pair/silent policy, attachment quarantine, outbound reply policy |
| Social persona | Telclaude social identity and queues | `tc-public-social` or role profile | public memory only, post/reply budgets, approval semantics, no private leakage |
| Provider actor | Telclaude profile plus provider capability grants | sidecar capability context | actor/service/action binding, params-bound approvals, audit, replay denial |

Required migration fixtures:

- Valid private operator, expired TOTP, logged-out operator, revoked actor,
  banned actor, wrong thread, and wrong profile binding.
- Family member with allowed household task, denied private-memory request, denied
  unscoped provider request, and approved sensitive provider write.
- Unknown public sender, paired public sender, revoked public sender, and blocked
  attachment.
- Social draft, approved social post, denied private-content reference, timeline
  ingestion, reply approval, and backend outage.

### Identity assurance levels

Family, email, social, and provider powers require explicit identity assurance:

- **IAL0 channel-bound:** observed channel identity only, such as WhatsApp
  JID/phone or email envelope sender. This allows benign household tasks only.
- **IAL1 paired:** identity-link code or operator pairing binds the channel
  identity to a Telclaude actor record.
- **IAL2 step-up verified:** fresh operator approval, TOTP-like challenge, or
  provider-specific verification for sensitive reads/writes.
- **Revoked:** identity exists but cannot route to Hermes or sidecars. Revocation
  invalidates in-flight approval waiters, unexecuted `actionRef`/`outboundRef`
  records, active sessions, and queued workflow capabilities for that actor.

Provider reads involving bank, medical, government, or other PII require at
least IAL1 and the actor's provider scope. Sensitive writes require IAL2 and the
approved-write token path. Email actors that can reach provider scopes require
an explicit pairing handshake, such as a link code sent to the address and
returned by the actor; display `From`, SPF, DKIM, and DMARC are not enough for
person-level provider authority. WhatsApp identity must bind JID/phone plus
pairing before provider scopes are reachable.

### Group-recipient policy

Group chats and email threads are authorized against the least-authorized
recipient in the thread. Provider, medical, financial, government, or private
household details may be sent to a group only if every recipient has that scope.
Otherwise the assistant sends a summary-safe response to the group and offers a
private follow-up to the authorized recipient.

If the edge cannot verify roster integrity or membership changes for a channel,
for example an unofficial WhatsApp bridge with weak roster guarantees, the group
is treated as untrusted and receives only summary-safe content. Untrusted roster
state can never authorize a sensitive group send.

## Private Telegram Contract

Private Telegram should stay Telclaude-fronted until parity is proven and any
security downgrade is explicitly accepted.

Accepted execution contracts, in order of preference:

1. Programmatic Hermes runner or `AIAgent`/batch entry point inside a
   Telclaude-controlled process boundary.
2. Hermes CLI single-query/headless invocation with generated profile/config,
   stdout/stderr streamed through Telclaude redaction.
3. Local Hermes API server only if the entire server-side tool execution process
   is inside the same Telclaude isolation domain.

Do not route private Telegram directly into Hermes gateway as the first
production path. Hermes gateway hooks run in the Hermes process and are not a
replacement for Telclaude pre-LLM gates.

### Private execution contract

The chosen private Hermes contract is a Phase 1 exit criterion, not a late
implementation detail. It must prove:

- streaming chunks through Telclaude redaction
- cancellation and stop propagation
- session resume and `/new`
- profile switching
- media and attachment refs
- tool-call events and audit IDs
- cron dispatch into the correct profile/session
- concurrent sessions without cross-thread leakage
- deterministic run/session IDs for audit and replay
- no raw private/provider/model credentials in Hermes env, files, process args,
  child env, or logs
- external approval continuation: either pinned Hermes supports mid-run
  suspend/resume through a documented permission channel, or the wrapper uses the
  explicit cross-turn fallback where prepare ends the turn, approval happens
  out-of-band, and execute starts a fresh turn from an immutable `actionRef` or
  `outboundRef`

CLI single-query, programmatic runner, and local API server options remain
candidates only until one passes this contract against the pinned Hermes
release.

## Public Identity, WhatsApp, and Email

Hermes should get the full public and household identity surface, but only as a
separate identity domain from private operator work.

### Public identity assets

- Dedicated WhatsApp bot number, not the operator's personal number.
- Dedicated email account, not the operator's personal mailbox.
- Optional AgentMail inbox for agent-owned addresses.
- Public social handles, including X/Moltbook equivalents.
- Household WhatsApp contacts and family member identities.
- `SOUL.md` for the public identity.
- Public and household memory stores, scoped separately from private operator
  memory.
- Public attachment quarantine and media store.
- Public audit log and outbound ledger.

### Attachment pipeline

Every public, household, social, email, WhatsApp, AgentMail, and provider
attachment goes through a hostile-file pipeline before Hermes can use it:

- type sniffing independent of filename or MIME header
- AV/YARA or equivalent malware scan
- size, page, duration, and archive-expansion limits
- decompression-bomb detection
- EXIF/location stripping where applicable
- HTML/script sanitization
- OCR/transcription with explicit trust labels
- media-to-text quarantine before any private/provider context use
- signed `AttachmentRef` expiry and actor/thread binding

Public attachments are never auto-promoted into private, provider, or privileged
contexts.

### Identity migration and authorization parity

The wrapper must migrate identity state as an authorization artifact, not only
as contacts or display names.

| Identity surface | Migration requirement | Parity tests |
|---|---|---|
| Private Telegram | chat ID, claimed admin, TOTP state, profile binding, banned/revoked users | unknown sender denied, revoked actor denied, wrong-thread approval denied |
| Family WhatsApp | contact identity, relationship, consent, per-person scopes, emergency contact policy | allowed family routine action succeeds, unscoped provider request requires operator approval |
| Public WhatsApp/email | allowlists, pairing state, thread IDs, sender reputation, attachment policy | unknown sender fail-closed/pair/silent behavior, wrong-thread reply denied |
| Social handles | account identity, posting budgets, reply/DM policy, approval policy | timeline ingestion, draft post, reply approval, autonomous-budget denial |
| AgentMail/email agents | mailbox identity, API key custody, allowed senders, thread mapping | direct key absent from Hermes, sidecar read/send path works |
| Providers | actor-to-provider scope mapping and delegated authority | bank/Clalit/government scope denial for the wrong actor |

### Household assistant policy

Family/household use is a core target. The design should support:

- Family members messaging the assistant on WhatsApp.
- Per-person identity, relationship, and allowed-scope records.
- Bare WhatsApp contact/number identity authorizes only benign household
  capabilities such as reminders, lists, schedules, logistics, and preferences.
- Provider access, including read-only bank/health/government PII, requires a
  strong identity link such as an operator-issued identity-link code in addition
  to the contact identity. Provider writes still require exact operator approval.
- Shared household memory for benign preferences, schedules, shopping lists,
  travel, maintenance, reminders, and family logistics.
- Separate private operator memory that family members cannot access.
- Provider access on behalf of a family member only when that person is
  authorized for that provider scope or the operator explicitly approves.
- Replies and routine low-risk actions without friction when within an
  allowlisted family scope.
- Family-facing email notifications and summaries where each recipient sees
  only their authorized household/provider context.
- Family/social notifications that never expose private operator workspace,
  private memory, provider data, or pending approvals outside the intended
  recipient/thread.
- Per-recipient scoping is enforced by reachability. For a given family thread or
  notification, Telclaude exposes only that recipient's authorized household
  memory slice and provider context to Hermes. The composing brain cannot query
  another family member's memory/provider context and is not trusted to
  self-segregate output.
- Explicit approval for sensitive actions: money movement, medical writes,
  insurance/government submissions, account changes, new recipients, public
  posts, or anything that exposes private operator data.

This should feel like a capable personal assistant, not a read-only kiosk. The
approval layer is for risk boundaries, not for every useful action.

### Credential policy

Production has one credential mode:

- **Sidecar credentials:** Telclaude sidecars own WhatsApp/email/AgentMail/social
  credentials. Hermes receives sanitized message events and calls send/read
  tools through Telclaude. Dedicated public credentials may exist, but they live
  in a public edge sidecar or vault namespace, not in Hermes `.env`, `auth.json`,
  MCP config, plugin config, or filesystem.

Disposable shadow/testing profiles may use native Hermes WhatsApp/email
credentials only with a manifest entry naming the downgrade, expiration date,
and blast radius. They are not valid production parity evidence.

Private/provider/model credentials never use a direct-Hermes exception.

The production Hermes network namespace reaches only the Telclaude relay/edge
endpoints it is assigned. Direct SMTP, IMAP, WhatsApp Web bridge, provider,
vault, model-provider, metadata, RFC1918, and cross-domain routes must fail at
the OS/network layer.

### Outbound policy

- Replies in existing, allowlisted threads may be pre-authorized by profile
  policy.
- New recipients require explicit operator approval.
- Bulk/cold outbound is blocked unless a narrowly scoped campaign capability is
  explicitly created and rate-limited.
- Public social posts can be autonomous only within configured public-policy
  budgets; private content references always require operator approval.
- Attachments are quarantined or skipped until scanned.
- All outbound sends pass through Telclaude redaction, approval, and audit
  before any transport can egress.
- Approval tokens for outbound sends bind the final relay-forwarded body,
  destination, channel, recipient/thread, actor, profile, action, TTL, and
  one-time JTI. Hermes never supplies a precomputed params hash.

### Inbound policy

- Production WhatsApp/email/AgentMail/social inbound terminates at a Telclaude
  edge sidecar or relay.
- The edge applies authorization, rate limits, infra-secret blocking, attachment
  quarantine, observer/security classification where applicable, and audit
  before Hermes receives content.
- Native Hermes gateway allowlists/pairing may be mirrored for UX, but they are
  not the enforcing ingress boundary.
- Unknown public senders fail closed, pair, or stay silent according to the
  edge policy before the model sees their message.
- The fork-free transport seam is a Telclaude edge platform adapter: native
  WhatsApp/email/AgentMail/social webhooks or polling feed sanitized events into Hermes
  through a wrapper-owned gateway/MCP/tool interface, and Hermes sends outbound
  only by requesting Telclaude edge delivery. Native Hermes channel adapters may
  be mirrored for UX/status, but they do not hold production credentials, read
  session files, or trigger credential/session reconnects.

## Extension Design

### Telclaude MCP server

Expose narrowly scoped tools to Hermes:

- `tc_provider_read(service, action, params)`
- `tc_provider_prepare_write(service, action, params)`
- `tc_provider_execute_write(actionRef, approvalToken)`
- `tc_memory_search(query, filters)`
- `tc_memory_write(entry, provenance)`
- `tc_attachment_get(ref)`
- `tc_outbound_prepare(channel, recipient, content, mediaRefs)`
- `tc_outbound_execute(outboundRef, approvalToken)`
- `tc_audit_note(kind, payload)`

Every tool must derive actor/profile/domain, memory source, writable namespace,
and provider authority from the wrapper session and endpoint/netns, not from
LLM-provided parameters. If a user-facing memory or provider scope appears in a
schema, it is advisory and the server clamps or ignores it.

`tc_memory_write` provenance is metadata-only. The server overwrites or rejects
any provenance fields that attempt to choose the authoritative source, trust
domain, writable namespace, actor, or profile.

Write and send execution use immutable prepared records:

- Provider prepare returns `actionRef`, canonical params, params hash, preview,
  and approval request. Execute accepts only `actionRef` plus approval token.
  Sidecars ignore any fresh mutable params at execute time.
- Provider approvals include both canonical machine JSON and the exact
  human-readable approval render shown to the approver; the signed token binds
  the record the human saw, not just opaque params. The token also binds actor,
  profile/domain, provider account, approver identity, approval request/card ID
  and revision, service/action, params hash, idempotency key, TTL, and one-time
  JTI.
- Outbound prepare returns `outboundRef`, rendered body, destination, media refs,
  preview, and approval request. Execute accepts only `outboundRef` plus approval
  token. Approval tokens bind the exact outbox record, rendered body, media refs,
  destination, actor, profile, TTL, and one-time JTI.

Every MCP server emitted by the generator must set sampling off. Telclaude
sidecars must refuse server-initiated LLM sampling requests so MCP cannot become
a sidecar-to-agent prompt injection channel.

MCP configs must also disable or explicitly allowlist tools, resources, prompts,
roots, sampling, env, cwd, and subprocess permissions. A malicious MCP server
must not expose unauthorized resources/prompts, spawn networked helpers, or
reach sidecar sockets outside its assigned domain.

### Provider capability model

Provider sidecars are the way Hermes gets serious powers while staying safe.
Each provider capability should be modeled as a tool family with a risk tier:

- **Read:** fetch balances, appointments, documents, recent activity, messages,
  claims, lab results, account metadata, and status. Allowed by actor/provider
  scope and rate limits. Releasing read results to a human/channel is separately
  recipient-authorized; provider reads are not automatically safe to display.
- **Draft/prepare:** draft bank transfers, bill payments, appointment bookings,
  Clalit messages, form submissions, support replies, or government filings
  without committing them.
- **Approved write:** execute a prepared action only with a signed approval token
  bound to exact final parameters.
- **Delegated routine:** allow narrow low-risk recurring read/draft-only actions
  with sidecar-enforced budgets, such as checking appointment availability,
  downloading monthly statements, or summarizing new provider inbox items. This
  tier never executes writes; all writes require the approved-write token path.
- **Blocked:** actions outside declared provider schemas, bulk actions, credential
  changes, MFA changes, destructive account changes, or unreviewed medical/financial
  submissions.

Examples that should become first-class parity fixtures:

- Bank: balances, recent transactions, card/charge lookup, statement download,
  payment/transfer draft, approved transfer execution.
- Clalit/health: appointments, lab results, medication/referral documents,
  message drafting, appointment booking draft, approved booking/cancellation.
- Government: status lookups, document fetches, form draft, approved submission.
- Google/Gmail/Calendar/Drive: read summaries, draft replies/events, approved
  sends/events, attachment storage.

Provider sidecars own credentials and interactive session state. Hermes never
sees passwords, OAuth refresh tokens, access tokens, cookies, OTPs, backup
codes, CAPTCHA/manual-login pages, provider session files, or raw browser pages
for bank/Clalit/government systems. MFA prompts and manual-login steps are
Telclaude approval-card workflows with redacted audit.

Provider-specific safety tiers:

- Bank/government/health reads may be routine internally only after actor scope
  and identity assurance pass; release to WhatsApp/email/social/control-room
  recipients requires recipient/thread authorization.
- Banking and government writes require a human-readable final render, canonical
  machine JSON, exact approval binding, and idempotency key.
- Clalit/health flows detect urgent/emergency language and escalate safely rather
  than acting autonomously; no autonomous medical advice, medication changes, or
  clinical interpretation beyond source-linked summaries.
- Appointment cancellation, government submission, money movement, new
  recipients, insurance changes, and account/profile changes require explicit
  approval even if the actor has provider scope.

### Web/browser egress broker

Hermes should remain useful on the web, but browser/terminal egress cannot be an
uncontrolled bypass around sidecars.

Production browser and terminal web access go through a Telclaude web proxy or
browser-worker sidecar with:

- per-domain allow/deny policy
- audit and side-effect ledger
- download and upload quarantine
- cookie/session isolation per trust domain
- separate browser profiles and no shared cookies between private, public,
  household, and specialist domains
- provider-domain blocking unless using the provider sidecar/browser worker
- direct SMTP/IMAP/WhatsApp/model/vault/provider denial
- controlled DNS: no outbound `:53` except to a filtering resolver that answers
  only allowlisted names and refuses arbitrary recursion; DoH/DoT, IP literals,
  DNS rebinding, CONNECT/proxy tunneling, WebSocket/WebRTC exfil, service worker
  persistence, extensions/native messaging, and localhost callback exfil are
  blocked or explicitly brokered
- budgets for autonomous browsing and scraping
- redacted screenshots/text extraction for sensitive sites
- screenshot retention limits and redacted control-room display
- approval before submitting forms that contain financial, health, government,
  credential, public-post, outbound-message, or private-memory data
- navigation, form-submit, upload, download, and extracted-data audit records

Allowed general web research must still work with low friction. Sensitive bank,
Clalit/health, government, and account-management sites use provider sidecars or
dedicated browser workers that hold session/cookie custody outside Hermes.

Computer-use automation follows the same broker model. Each domain has an
allowlist of target apps/windows, isolated display/session state, clipboard
read/write policy, screenshot and video retention/redaction, UI side-effect
classification, and approval before clicks/keystrokes that submit financial,
health, government, credential, public-post, outbound-message, or private-memory
data. Desktop automation audit records include app/window identity, screenshot
refs, extracted text refs, side-effect decision, and operator approval ref when
used.

### Hermes plugin

Use a Hermes plugin for:

- Namespaced tools and toolsets.
- Slash commands that mirror Telclaude operator commands where useful.
- Control-room status panels.
- Soft pre-tool warnings and UX annotations.
- Optional result transforms for defense in depth.
- Bundled wrapper skills with explicit provenance.

Never rely on plugin hooks for mandatory denial. Hook failures in Hermes must be
treated as fail-open.

### Memory provider

Implement a Hermes memory provider that reads a sanitized Telclaude view:

- Private profiles see only their active `telegram:<profile>` source.
- Public profiles see only public/social memory.
- Public memory is never injected into private LLM context.
- Cross-persona queries go through a Telclaude relay tool and return sanitized
  summaries, not raw memory blobs.
- Compiled `MEMORY.md`-style files are caches, not authority.
- Hermes built-in memory files are treated as untrusted per-domain scratch. For
  public/autonomous domains, mount `~/.hermes/memories/` on ephemeral tmpfs or a
  relay-owned generated snapshot that is destroyed or regenerated between runs.
- Memory `source`, domain, and writable namespace are derived server-side from
  the authenticated endpoint/netns, never from request fields.

### Profile/config generator

The generator emits complete profile artifacts:

- `config.yaml`
- `.env.EXAMPLE` and a secret manifest, not raw private secrets.
- `SOUL.md`
- plugin enablement
- MCP server config
- toolsets
- terminal backend/cwd
- gateway platform settings
- cron exports
- memory provider config
- skills manifest
- provenance manifest
- audit/cutover manifest

The generator must classify every output path as secret, sensitive, derived,
or safe-to-diff.

The generator also emits `docs/hermes/hermes-compat.lock.json`, a JSON
compatibility lockfile containing:

- pinned Hermes version, commit, package, or image digest
- evaluated feature-probe matrix digest and per-probe pass/fail evidence refs
- Hermes source/docs commit hashes as advisory drift signals
- adapter API signatures
- plugin/MCP/model-provider/memory-provider capabilities
- required upgrade tests
- generated profile schema version and wrapper package version
- parity suite result digests and no-fork proof evidence path

Comparison is fail-closed: an unknown pinned artifact, changed adapter
signature, missing probe result, changed capability, changed generated schema,
or stale parity digest blocks production. A docs/source hash change alone does
not prove behavior, but it invalidates the lockfile until the affected feature
probes and parity fixtures are rerun. Any Hermes upgrade reruns the full parity
and adversarial suite before production use.

Guardrail files and directories are relay-owned read-only mounts in production,
including `config.yaml`, `.env`, `auth.json`, MCP config, toolset config,
`SOUL.md`, promoted skills, `plugins/`, `plugins/memory/`, and
`plugins/model-providers/`. Agent-authored changes go to quarantine and require
review/promotion.

### Control room

Build the operator surface around a control-room model:

- Profile roster and trust-domain status.
- Active sessions, cron jobs, approvals, cards, queues, and side effects.
- Public identity channel health: WhatsApp, email, AgentMail, social.
- Parity fixture results and shadow diffs.
- Skill provenance, Curator status, pinned/immutable skill state.
- Outbound ledger and rate budgets.
- Cutover readiness.

The control room must not hold raw runtime secrets.

It also must not become an authority bypass. It can display state and submit
operator intents, but it cannot mint provider tokens, hold approval signing
keys, bypass actor checks, or dispatch sends directly. Approval signing remains
in vault/sidecar code paths with callback identity checks.

Control-room data is itself sensitive. It must enforce per-view authorization,
redact secrets and PII in logs/tool args/results/session summaries/screenshots,
separate private/public/household panes, and honor retention/export/delete
policies for attachments, screenshots, provider records, public messages, and
audit logs.

## Long-Running Workflow Semantics

Hermes should keep its cron/background-job strengths, but Telclaude owns side
effect safety and workflow authority. Every long-running workflow record includes:

- run ID, actor, profile, trust domain, workflow bundle ID, and capability set
- side-effect ledger with idempotency keys for provider writes and outbound sends
- approval waiter IDs and exact resume target
- cancellation and human-takeover path
- retry/backoff/misfire policy
- max runtime, budget, checkpoint, and heartbeat state
- partial-failure compensation plan
- queue owner and rollback owner

Resume must never duplicate money movement, appointment booking, government
submission, email sending, WhatsApp sending, or social posting. Cron delivery
uses Telclaude outbound adapters, never native Hermes transport credentials.

## Complete Parity Matrix

Every row needs a fixture, expected output, and acceptance proof before cutover.

| Area | Required parity | Hard owner |
|---|---|---|
| Private chat | Auth, TOTP, rate limits, tiers, session reset, streaming, media, directives | Telclaude |
| Approvals/cards | Actor/chat/thread/revision checks, TTL, stale waiter behavior, durable state | Telclaude |
| Providers | Read, write prepare, write execute, audit, direct-route denial | Telclaude sidecars |
| Banking | Balances, transaction lookup, statements, payment/transfer draft, approved execution | Telclaude sidecar |
| Clalit/health | Appointments, lab results, documents, message/booking draft, approved booking/cancellation | Telclaude sidecar |
| Government/identity | Status lookup, document fetch, form draft, approved submission | Telclaude sidecar |
| Approval tokens | Ed25519, params hash, actor/service/action binding, 60s relay TTL, sidecar max TTL <=300s, JTI replay prevention | Vault/sidecar |
| Memory | Private/public source separation, sanitizer, provenance, runtime assertions | Telclaude |
| Skills | Mirrored skills, scanner, signer, pinning, SOCIAL fail-closed allowlist | Telclaude + Hermes Curator |
| Social/public | Timeline ingestion, draft/post/reply flows, approvals, budgets, backend outage handling, no private leakage | Telclaude envelope |
| WhatsApp | Dedicated number, Telclaude edge ingress, media/voice quarantine, outbound approval, native bridge only for shadow/downgrade | Telclaude edge + Hermes runtime |
| Household WhatsApp | Contact-only benign tasks, strong-link provider access, per-person reachability, household memory, sensitive-action approvals | Telclaude edge + Hermes runtime |
| Email | Dedicated mailbox, Telclaude edge ingress, attachments, threading, outbound approval, no production app password in Hermes `.env` | Telclaude edge + Hermes runtime |
| Household email | Family-facing mailbox rules, per-person reachability, shared/private memory split, attachment quarantine, strong-link provider access | Telclaude edge + Hermes runtime |
| AgentMail | Dedicated inboxes, API key in sidecar/vault, polling/webhook mode, no direct production key in Hermes MCP env | Telclaude sidecar |
| Identity migration | Private, family, public, social, provider actors; pair/revoke/ban/wrong-thread cases | Telclaude |
| Edge adapters | Sanitized inbound, relay-mediated outbound, sidecar-owned status, no production channel creds in Hermes | Telclaude edge + Hermes plugin/MCP |
| Model-provider relay | Hermes model traffic reaches only relay-approved endpoints or is denied by network policy | Telclaude relay + OS/network |
| Cron | Private/public/specialist jobs, dry-run mode, failure notification | Hermes runtime + Telclaude gate |
| Long-lived workflow runs | Actor, authority, scope, freshness, idempotency, side-effect ledger, cancellation | Telclaude + Hermes runtime |
| Chief of staff | Daily brief, meeting prep, support triage, weekly report, trend radar, bookmarks | Profile-specific |
| Browser/web/computer | Tool availability by trust domain, network/FS isolation | OS/container |
| Web/browser broker | Allowed research works; sensitive/provider domains are sidecar-mediated; direct covert egress denied | Telclaude broker + OS/network |
| Redaction | Chunk-boundary, logs, media captions, platform output, high-entropy values | Telclaude egress |
| Cutover | No unmapped workflow, no active queues, rollback path, burn-in evidence | Telclaude |

## Implementation Plan

Implementation is phased for engineering order, not for gradual production
migration. Production cutover remains complete-parity gated.

### Phase 0: Freeze and inventory

Deliver:

- Freeze Telclaude feature expansion except security fixes and migration
  blockers.
- Produce the cutover scope manifest and decision log skeleton.
- Inventory chats, profiles, tiers, skills, cron jobs, providers, OAuth/vault
  state, media refs, background jobs, social queues, cards, approvals, and
  external identities.
- Produce an identity migration table covering private, family, public, social,
  and provider actors, including revoked/banned/wrong-thread cases.
- Classify each workflow by trust mode: private, public, provider-read,
  provider-write, autonomous-web, autonomous-computer, social, cron, disabled.
- Produce the first parity fixture catalog.

Commands:

```bash
pnpm dev hermes inventory --json > /tmp/telclaude-hermes-inventory.json
pnpm dev doctor --json
pnpm dev doctor --secrets --network --json
```

Acceptance:

- No workflow exists without an owner, trust domain, parity fixture, and cutover
  requirement.
- No included workflow has unresolved blocker decisions or unsafe evidence.
- All current pending queues can be listed and drained or assigned.
- Actor migration has fixture coverage for allow, deny, revoke, ban, pair,
  wrong-thread, and expired-session cases.

### Phase 1: Pinned wrapper foundation

Deliver:

- `telclaude hermes doctor`
- `telclaude hermes inventory`
- `telclaude hermes generate --dry-run`
- Private execution contract selection and feature probe.
- Hermes compatibility lockfile generation.
- Hermes pin discovery for binary/image/package.
- Refusal to run production profiles against unpinned Hermes.
- Canonical Hermes source/image/digest selection when multiple local checkouts
  exist.

Commands:

```bash
pnpm dev hermes doctor --json
pnpm dev hermes generate --dry-run --out /tmp/tc-hermes
hermes doctor
hermes profile list
```

Acceptance:

- Wrapper can identify the exact Hermes version/commit/package.
- Wrapper records one canonical Hermes checkout or image digest and reports
  drift if another local checkout is accidentally used.
- Generated profiles contain no raw private/provider secrets.
- Generated artifacts include provenance and sensitivity classification.
- Private execution contract proves streaming, cancellation, resume, media refs,
  tool events, cron dispatch, concurrency, redaction wrapping, and audit IDs.
- Compatibility lockfile captures pinned Hermes release and detected extension
  APIs.

### Phase 2: Private headless runtime contract

Deliver:

- One chosen private Hermes execution contract.
- Streaming redaction around all Hermes output.
- Session mapping from Telclaude chat/profile to Hermes profile/session.
- Dry-run private replay harness.
- Model-provider relay evaluation: production model traffic is relay-mediated.
  The implementation may be a stable Hermes model-provider/endpoint override or
  a network-level transparent route to the Telclaude relay, but raw model
  credentials never enter Hermes and all direct non-relay model endpoints fail.
- Approval continuation evaluation: first probe Hermes-as-MCP-server permission
  surfaces such as `events_wait`, `permissions_list_open`, and
  `permissions_respond`; if pinned Hermes cannot suspend/resume safely, record
  the cross-turn prepare/approve/execute fallback and disable any workflow that
  requires exact mid-run continuation.

Acceptance:

- Unknown private sender is denied before Hermes.
- Expired TOTP session challenges before Hermes.
- Private replies stream through Telclaude redaction.
- Hermes cannot directly reach vault/provider/private sidecar hosts.
- Hermes cannot directly reach model provider endpoints except the approved
  Telclaude relay/proxy endpoint.
- If a Hermes model-provider extension is used, the provider root is read-only
  relay-owned and cannot be overridden by profile/plugin writes.
- Approval wait/resume or the explicit cross-turn fallback passes provider,
  outbound, cron, and long-running workflow fixtures.

### Phase 3: Telclaude sidecar and MCP bridge

Deliver:

- Telclaude MCP server for providers, memory, approvals, attachments, outbound
  requests, and audit.
- MCP sampling disabled in every emitted server config.
- Provider read/write fixtures.
- Bank, Clalit/health, government, and Google fixture families with read,
  prepare, approved write, denial, and audit cases.
- Signed approval-token write path.
- Direct-route denial tests from inside Hermes domains.
- Removal or replacement of loopback/private-IP-only trust in credential,
  Anthropic/model, capability, and token-mint listeners.

Acceptance:

- Provider writes fail without a valid params-bound token.
- Replay, expiry, wrong actor, wrong service/action, params mutation, wrong
  provider account, wrong approval card revision, wrong approver, and
  approve-then-revoke-then-execute fail.
- Audit logs contain actor/service/action/status metadata and no raw secrets.
- MCP tool schemas cannot let the LLM choose actor/profile/domain.
- Co-located Hermes cannot mint tokens or fetch credentials by virtue of loopback
  or private-IP reachability.
- Routine read/delegated provider powers work without unnecessary friction when
  the actor has scope, while financial/medical/government writes require exact
  approval.

### Phase 4: Whole-process isolation

Deliver:

- Container/process launcher per trust domain.
- Explicit mounts, no host home, no Docker socket, non-root user, resource
  limits, separate data/log dirs, restricted egress.
- Network policy for metadata, RFC1918, CGNAT, provider/vault, and cross-domain
  routes, direct SMTP/IMAP/WhatsApp bridge routes, and model-provider routes.
- Malicious plugin and MCP subprocess tests.

Commands:

```bash
docker compose -f docker/docker-compose.hermes.yml config
docker compose -f docker/docker-compose.hermes.yml up -d
docker exec tc-hermes-public sh -lc 'test ! -e ~/.ssh && test ! -S /var/run/docker.sock'
docker exec tc-hermes-public sh -lc 'curl -m2 http://169.254.169.254 || true'
```

Acceptance:

- Hard failures happen at OS/network level, not by model refusal.
- Disabling Hermes toolsets/hooks does not grant private creds, private memory,
  vault, provider, metadata, or cross-domain access.
- A planted memory-provider or model-provider plugin cannot override production
  providers because plugin/provider roots are read-only relay-owned mounts.
- An MCP server `sampling/createMessage` request is refused.

### Phase 5: Public identity pilot

Deliver:

- `tc-public` profile or explicit per-channel public profiles.
- `tc-household` profile or family-scoped public profile policy.
- Dedicated WhatsApp number/session held by the Telclaude edge sidecar.
- Dedicated mailbox held by the Telclaude edge sidecar.
- AgentMail decision: Telclaude-wrapped sidecar/vault custody for production;
  direct MCP only for disposable shadow/downgrade.
- Public social handles connected through existing or Hermes-supported paths.
- Telclaude edge-to-Hermes adapters for sanitized inbound events, relay-mediated
  outbound sends, sidecar status, and attachment quarantine.
- Edge adapter contract schemas and feature probes for each included channel.
- Public `SOUL.md`, memory policy, outbound ledger, and attachment quarantine.
- Family identity records, strong-link state, household memory policy,
  provider-scope policy, per-recipient reachability policy, and family-facing
  approval UX.
- Household email fixtures in addition to household WhatsApp fixtures.
- Social fixtures for timeline ingestion, post drafts, approved posts, reply
  approvals, denied private references, and X/Moltbook backend parity.

Commands:

```bash
hermes -p tc-public gateway status
hermes -p tc-public tools
pnpm dev hermes parity --identity --whatsapp --email --social --shadow
```

Acceptance:

- WhatsApp/email work in shadow against test contacts through the Telclaude edge.
- Family WhatsApp flows work in shadow for contact-only benign household tasks,
  strong-link provider reads, number-only provider denial, private-data denial,
  and sensitive-action approval.
- Household email flows work in shadow for scoped family requests, attachment
  quarantine, per-recipient reachability, private-data denial, strong-link
  provider access, and sensitive-action approval.
- Social flows prove timeline ingestion, draft creation, approved posting,
  reply approval, outbound budget enforcement, backend outage handling, and no
  private memory leakage.
- Unknown senders fail closed, pair, or stay silent according to policy.
- New outbound recipient requires explicit approval.
- Public profile cannot read private workspace, private memory, private
  sessions, or provider scopes.
- Public credentials are absent from private domains.
- Production public credentials are absent from Hermes domains.
- Direct-Hermes native credential smoke tests do not count as public identity,
  WhatsApp, email, AgentMail, social, or cutover evidence.

### Phase 6: Skills, Curator, and workflow migration

Deliver:

- Skill manifest mapping `.claude/skills` and `.agents/skills` to Hermes skills.
- Pinned/immutable classification for Telclaude-critical skills.
- Agent-created skill review path using Hermes Curator plus Telclaude scanner.
- Chief-of-staff workflow fixtures.
- Profile-specific skill/toolset policies.

Acceptance:

- SOCIAL/public profiles fail closed with no explicit skill allowlist.
- Critical skills cannot be overwritten by Curator or agent-authored updates.
- Agent-authored plugins, model providers, memory providers, MCP config, and
  toolset mutations cannot become active without relay-side promotion.
- Daily brief, meeting prep, support triage, weekly report, trend radar,
  bookmarks, humanizer, and Obsidian/wiki fixtures pass in dry run.

### Phase 7: Shadow parity and strict cutover

Deliver:

- Replay harness for private, public, provider, cron, skill, and outbound flows.
- Shadow comparison reports.
- `telclaude hermes cutover-check --strict`.
- Rollback playbook.

Commands:

```bash
pnpm dev hermes parity --providers --memory --redaction --identity --shadow
pnpm dev hermes cutover-check --inventory /tmp/telclaude-hermes-inventory.json --strict
```

Acceptance:

- All P0 fixtures pass with malicious Hermes plugin installed and cooperative
  Hermes guards disabled.
- No pending approval/card/background job/cron/provider/social queue is
  unowned.
- No private/provider secret is readable by any Hermes domain.
- Direct provider/vault/private endpoint access fails from Hermes.
- Direct public transport egress fails from Hermes except through Telclaude edge
  endpoints.
- Operator can complete daily workflows without using the legacy Telclaude
  runtime.
- Rollback can restore the current Telclaude path.

## Task Breakdown

Task dependencies on open decisions:

- Private headless execution depends on Q3 and Q9.
- Model-provider relay depends on Q10.
- Private Telegram, approvals/cards/status parity, and cutover UX depend on Q5
  unless the decision log marks current Telegram card/status semantics as
  explicitly non-blocking for the included workflow set.
- Public identity, edge adapter, WhatsApp, email/AgentMail, and social tasks
  depend on Q1, Q2, Q4, Q6, and Q8 for any included workflow.
- Household policy and provider-power tasks depend on Q11 and Q12.
- Any first-cutover task depends on Q7 and cannot enter the included set until
  the decision log has owner, deadline phase, accepted answer, affected
  workflows, cutover impact, and downgrade note where applicable.

### Foundation tasks

- [ ] Add inventory schema and `telclaude hermes inventory`.
  - Acceptance: JSON lists every chat/profile/skill/provider/cron/social/public
    identity/queue with owner and trust domain.
  - Verify: `pnpm dev hermes inventory --json`.
  - Files: `src/commands/**`, `src/config/**`, `src/storage/**`.

- [ ] Add cutover scope manifest and decision log.
  - Acceptance: every included workflow has owner, trust domain, P0/P1/P2 class,
    parity fixtures, rollback owner, and no unresolved blocker decision.
  - Verify: `pnpm dev hermes cutover-check --strict --dry-run`.
  - Files: `src/hermes/**`, `docs/**`, tests.

- [ ] Add Hermes pin discovery and `telclaude hermes doctor`.
  - Acceptance: production mode refuses unpinned Hermes; doctor reports version,
    path, profile root, plugin support, MCP support, and gateway support.
  - Verify: `pnpm dev hermes doctor --json`.
  - Files: `src/commands/**`, `src/hermes/**`, tests.

- [ ] Add feature-probe matrix and compatibility lockfile schema.
  - Acceptance: `docs/hermes/feature-probes.json` and
    `docs/hermes/hermes-compat.lock.json` schemas validate required fields,
    evidence paths, digests, and fail-closed upgrade semantics.
  - Verify: `pnpm dev hermes doctor --probes --json`.
  - Files: `src/hermes/**`, `docs/hermes/**`, tests.

- [ ] Add upstream no-fork seam proof harness.
  - Acceptance: fresh pinned upstream Hermes plus wrapper package and generated
    profiles runs included P0 fixtures with a clean Hermes checkout and no runtime
    source replacement.
  - Verify: `telclaude hermes prove --upstream-clean --p0`.
  - Files: `src/hermes/**`, `tests/**`, docs.

- [ ] Build profile/config generator dry run.
  - Acceptance: emits profile tree, manifest, sensitivity classification, and no
    private raw secrets.
  - Verify: `pnpm dev hermes generate --dry-run --out /tmp/tc-hermes`.
  - Files: `src/hermes/**`, `tests/**`.

- [ ] Add guardrail config ownership model.
  - Acceptance: production generated profiles mount guardrail config, plugin
    roots, model-provider roots, memory-provider roots, and promoted skills
    read-only from relay-owned paths; writable mutations go to quarantine.
  - Verify: generated manifest plus mutation denial fixture.
  - Files: `src/hermes/**`, `tests/**`.

### Runtime tasks

- [ ] Spike private headless Hermes execution.
  - Acceptance: the selected contract proves streaming chunks, cancellation,
    session resume, profile switching, media refs, tool events, approval
    wait/resume or cross-turn fallback, cron dispatch, concurrent sessions,
    redaction wrapping, and deterministic audit IDs.
  - Verify: private replay fixture.
  - Files: `src/hermes/**`, `src/telegram/**`, `src/sdk/**`.

- [ ] Resolve Hermes model-provider relay seam.
  - Acceptance: production model traffic goes through a relay-owned endpoint,
    model-provider override, or transparent relay route; raw model credentials
    are absent from Hermes and direct non-relay model-provider egress is blocked.
  - Verify: direct model endpoint probe fails; relay route succeeds; planted
    model-provider plugin cannot override production route.
  - Files: `src/hermes/**`, `src/relay/**`, generated profiles, tests.

- [ ] Implement Telclaude MCP foundation and hardening.
  - Acceptance: actor/profile/domain derivation, endpoint/netns binding, schema
    validation, sampling denial, and tools/resources/prompts/roots/env/cwd/
    subprocess allowlists apply to every wrapper MCP server.
  - Verify: MCP hardening fixture with malicious resources/prompts/subprocesses.
  - Files: `src/hermes/mcp/**`, `src/providers/**`, `src/memory/**`.

- [ ] Implement provider and memory MCP tool families.
  - Acceptance: Hermes can call provider reads/prepares and memory search/write
    through narrow schemas; actor/profile/source are wrapper-derived and
    provenance is metadata-only.
  - Verify: provider and memory MCP integration tests plus adversarial source
    spoofing fixture.
  - Files: `src/hermes/mcp/**`, `src/providers/**`, `src/memory/**`.

- [ ] Implement attachment, outbound, and audit MCP tool families.
  - Acceptance: attachment refs, outbound prepare/execute, and audit notes use
    immutable refs, quarantine state, redaction, policy decisions, and
    side-effect ledger records; the LLM cannot choose trust domain or transport
    credential.
  - Verify: attachment/outbound/audit MCP integration tests plus bypass fixtures.
  - Files: `src/hermes/mcp/**`, `src/media/**`, `src/telegram/**`, `src/social/**`.

- [ ] Port provider write approval path.
  - Acceptance: write prepare stores immutable `actionRef` and canonical params;
    execute accepts only `actionRef` plus signed approval token binding actor,
    profile/domain, provider account, approver, card revision, WYSIWYS render,
    idempotency key, TTL, and JTI.
  - Verify: replay, mutation, expiry, actor mismatch, wrong account, wrong card
    revision, wrong approver, and approve-then-revoke-then-execute tests.
  - Files: `src/google-services/**`, `src/vault-daemon/**`, `src/hermes/**`.

- [ ] Add outbound outbox prepare/execute path.
  - Acceptance: outbound prepare stores immutable `outboundRef`; execute accepts
    only `outboundRef` plus approval token bound to rendered body, destination,
    media refs, actor, profile, TTL, and JTI.
  - Verify: body mutation, wrong recipient, replay, expiry, actor mismatch, wrong
    approval revision, and approve-then-revoke-then-execute tests.
  - Files: `src/hermes/**`, `src/telegram/**`, `src/social/**`, tests.

- [ ] Add long-running workflow ledger.
  - Acceptance: run records include actor/profile/domain/capabilities, side-effect
    idempotency keys, approval waiters, retry/backoff, checkpoint/resume,
    cancellation, human takeover, and compensation metadata.
  - Verify: interruption/resume fixtures around approval waits, provider timeout,
    model timeout, process restart, outbound wait, and cancellation.
  - Files: `src/hermes/**`, `src/cron/**`, `src/storage/**`, tests.

- [ ] Replace loopback/private-IP listener trust.
  - Acceptance: credential/model/capability/token-mint listeners require
    relay-issued session auth and domain socket/netns reachability, not merely
    loopback or private IP.
  - Verify: co-located Hermes cannot mint tokens or fetch credentials.
  - Files: `src/relay/**`, `src/hermes/**`, tests.

### Isolation tasks

- [ ] Add Hermes trust-domain launcher.
  - Acceptance: domain config maps to process/container profile, mounts, env,
    egress, and logs.
  - Verify: launcher dry run plus container config validation.
  - Files: `src/hermes/**`, `docker/**`.

- [ ] Add adversarial containment tests.
  - Acceptance: malicious plugin/MCP/terminal/code path cannot read private
    creds, vault socket, private memory, host home, Docker socket, metadata IP,
    or provider endpoints.
  - Verify: `pnpm dev hermes parity --redteam`.
  - Files: `tests/**`, `docker/**`, `src/hermes/**`.

- [ ] Add network/HTTP web egress broker.
  - Acceptance: allowed web research works through broker policy; sensitive
    provider domains use sidecar/browser-worker custody; direct SMTP/IMAP,
    WhatsApp, model, vault, provider, metadata, and private endpoint routes fail.
  - Verify: `pnpm dev hermes parity --browser --network --redteam`.
  - Files: `src/hermes/**`, `src/providers/**`, `docker/**`, tests.

- [ ] Add browser profile and cookie isolation.
  - Acceptance: private/public/household/specialist domains have separate browser
    profiles, no shared cookies, isolated caches, bounded sessions, and audited
    navigation.
  - Verify: `pnpm dev hermes parity --browser --profiles`.
  - Files: `src/hermes/**`, `src/providers/**`, `docker/**`, tests.

- [ ] Add browser artifact quarantine.
  - Acceptance: uploads, downloads, screenshots, video captures, extracted text,
    and generated files are quarantined, retention-limited, redacted where
    required, and attached by refs rather than raw paths.
  - Verify: `pnpm dev hermes parity --browser --artifacts`.
  - Files: `src/hermes/**`, `src/media/**`, `docker/**`, tests.

- [ ] Add browser form-submit approval and audit.
  - Acceptance: forms containing financial, health, government, credential,
    public-post, outbound-message, or private-memory data require approval and
    produce side-effect ledger/audit records.
  - Verify: `pnpm dev hermes parity --browser --forms`.
  - Files: `src/hermes/**`, `src/providers/**`, `docker/**`, tests.

- [ ] Add network/DNS/browser-native bypass fixture pack.
  - Acceptance: DNS tunneling, DoH/DoT, WebSocket/WebRTC, CONNECT/proxy tunneling,
    IP literals, DNS rebinding, extension/native-messaging, service-worker, file
    upload, and localhost callback exfil attempts fail unless explicitly brokered.
  - Verify: `pnpm dev hermes parity --browser --egress-bypass --redteam`.
  - Files: `tests/fixtures/**`, `src/hermes/**`, `docker/**`.

- [ ] Add computer-use broker policy.
  - Acceptance: target app/window allowlists, isolated display/session state,
    clipboard policy, screenshot/video retention/redaction, UI side-effect
    approval, and desktop audit records work per trust domain.
  - Verify: `pnpm dev hermes parity --computer --redteam`.
  - Files: `src/hermes/**`, `src/media/**`, `docker/**`, tests.

### Public identity tasks

- [ ] Build edge adapter contract package and base runtime.
  - Acceptance: shared schemas, validators, operations, idempotency, ordering,
    retry/DLQ, attachment lifecycle, status, and auth binding work without any
    channel-specific credentials in Hermes.
  - Verify: edge adapter contract fixture.
  - Files: `src/hermes/**`, `src/providers/**`, tests.

- [ ] Add WhatsApp edge adapter and probe.
  - Acceptance: WhatsApp inbound becomes sanitized Hermes events; outbound sends
    pass through Telclaude redaction, approval, budgets, and audit; sidecar status
    is visible without exposing session files; pinned-Hermes feature probe passes.
  - Verify: `pnpm dev hermes parity --whatsapp --edge-adapter`.
  - Files: `src/hermes/**`, `src/providers/**`, tests.

- [ ] Add email edge adapter and probe.
  - Acceptance: IMAP/SMTP-style inbound/outbound works through Telclaude
    sidecar/vault custody, threading and attachments are preserved, and Hermes has
    no app password or mailbox token.
  - Verify: `pnpm dev hermes parity --email --edge-adapter`.
  - Files: `src/hermes/**`, `src/providers/**`, tests.

- [ ] Add AgentMail edge adapter and probe.
  - Acceptance: AgentMail polling/webhook mode works through Telclaude
    sidecar/vault custody, send/reply operations use prepared refs, and Hermes has
    no production AgentMail API key.
  - Verify: `pnpm dev hermes parity --agentmail --edge-adapter`.
  - Files: `src/hermes/**`, `src/providers/**`, tests.

- [ ] Add social edge adapter and probe.
  - Acceptance: social inbound/timeline/post/reply events become sanitized Hermes
    events or prepared outbound refs; budgets, approval, private-leakage denial,
    and sidecar-owned credentials hold.
  - Verify: `pnpm dev hermes parity --social --edge-adapter`.
  - Files: `src/hermes/**`, `src/social/**`, tests.

- [ ] Add attachment quarantine pipeline.
  - Acceptance: public/channel/provider attachments are type-sniffed, scanned,
    size-limited, archive-limited, EXIF-stripped where relevant, sanitized,
    trust-labeled, and never auto-promoted into private/provider context.
  - Verify: hostile attachment fixture pack.
  - Files: `src/media/**`, `src/hermes/**`, tests.

- [ ] Build identity migration fixtures.
  - Acceptance: private, family, public, social, and provider actor records map
    to Hermes profile/session routing while Telclaude remains the authorization
    authority.
  - Verify: allow, deny, revoke, ban, pair, wrong-thread, expired-session, and
    wrong-profile fixtures.
  - Files: `src/hermes/**`, `src/config/**`, `src/storage/**`, tests.

- [ ] Generate `tc-public` identity profile.
  - Acceptance: public `SOUL.md`, public memory config, channel configs, and
    outbound policy manifest are generated.
  - Verify: `hermes -p tc-public doctor`.
  - Files: `src/hermes/**`, `docs/**`.

- [ ] Generate household assistant policy.
  - Acceptance: family identities, per-person scopes, household memory,
    strong-link requirements, private-memory denial, provider-scope rules,
    per-recipient reachability, and approval UX are represented in generated
    manifests.
  - Verify: household WhatsApp fixture pack.
  - Files: `src/hermes/**`, `src/config/**`, `docs/**`, tests.

- [ ] Add WhatsApp pilot.
  - Acceptance: dedicated number/session is edge-owned, pre-LLM inbound policy
    enforced, outbound new recipient approval required, direct native Hermes
    bridge is disabled for production.
  - Verify: shadow WhatsApp fixture.
  - Files: `src/hermes/**`, `docs/**`, tests.

- [ ] Add email/AgentMail pilot.
  - Acceptance: dedicated mailbox or AgentMail mode works in shadow through
    sidecar/vault custody; API/app credentials are absent from Hermes;
    attachments are quarantined.
  - Verify: shadow email fixture.
  - Files: `src/hermes/**`, `docs/**`, tests.

- [ ] Add household email fixture pack.
  - Acceptance: family-scoped email requests, shared household memory,
    private-memory denial, per-recipient reachability, strong-link provider
    access, attachment quarantine, and approval-required actions work through
    the Telclaude edge.
  - Verify: `pnpm dev hermes parity --email --household`.
  - Files: `tests/fixtures/**`, `src/hermes/**`, `src/config/**`.

- [ ] Add social backend parity pack.
  - Acceptance: X/Moltbook timeline ingestion, draft creation, approved posting,
    reply approval, budget enforcement, backend outage handling, and private-data
    denial all pass through Telclaude policy.
  - Verify: `pnpm dev hermes parity --social --identity`.
  - Files: `tests/fixtures/**`, `src/social/**`, `src/hermes/**`.

- [ ] Add bank provider fixture pack.
  - Acceptance: balances, transactions, statements, transfer draft, approved
    transfer, denial, replay, revoke-after-approval, and audit fixtures pass.
  - Verify: `pnpm dev hermes parity --providers --bank`.
  - Files: `tests/fixtures/**`, `src/hermes/**`, `src/providers/**`.

- [ ] Add Clalit/health provider fixture pack.
  - Acceptance: appointments, lab/referral/medication document reads, message
    draft, appointment booking/cancellation draft, approved action, emergency
    language escalation, denial, replay, revoke-after-approval, and audit fixtures
    pass.
  - Verify: `pnpm dev hermes parity --providers --health`.
  - Files: `tests/fixtures/**`, `src/hermes/**`, `src/providers/**`.

- [ ] Add government provider fixture pack.
  - Acceptance: status lookup, document fetch, form draft, approved submission,
    denial, replay, revoke-after-approval, and audit fixtures pass.
  - Verify: `pnpm dev hermes parity --providers --government`.
  - Files: `tests/fixtures/**`, `src/hermes/**`, `src/providers/**`.

- [ ] Add Google provider fixture pack.
  - Acceptance: Gmail/Calendar/Drive reads, draft replies/events, approved
    sends/events, attachment storage, denial, replay, revoke-after-approval, and
    audit fixtures pass.
  - Verify: `pnpm dev hermes parity --providers --google`.
  - Files: `tests/fixtures/**`, `src/hermes/**`, `src/providers/**`.

- [ ] Add provider session and MFA custody rules.
  - Acceptance: sidecars own passwords, OAuth, cookies, OTP prompts, CAPTCHA,
    manual login, and session renewal; Hermes never sees raw login/session state.
  - Verify: MFA/session custody fixture and log scan.
  - Files: `src/providers/**`, `src/hermes/**`, tests.

### Workflow tasks

- [ ] Map Telclaude skills to Hermes skills.
  - Acceptance: every skill has runtime target, trust domain, provenance,
    pinning, and review state.
  - Verify: skill manifest audit.
  - Files: `.agents/skills/**`, `.claude/skills/**`, `src/hermes/**`.

- [ ] Implement chief-of-staff read/prepare fixture packs.
  - Acceptance: daily brief, meeting prep, support triage, weekly report, trend
    radar, bookmarks, humanizer, and Obsidian/wiki workflows each have a separate
    dry-mode fixture with declared data sources, approval budget, side-effect
    policy, and expected output shape.
  - Verify: `pnpm dev hermes parity --workflows --chief-of-staff`.
  - Files: `tests/fixtures/**`, `src/hermes/**`.

- [ ] Add workflow run ledger semantics.
  - Acceptance: every long-lived/cron/background run records workflowRunId,
    initiatingActor, authorityActor, scope, budget, freshnessDeadline,
    idempotencyKey, approvalPolicy, and sideEffectLedgerRef.
  - Verify: duplicate, retry, stale-data, outage, and cancellation fixtures.
  - Files: `src/hermes/**`, `src/cron/**`, tests.

- [ ] Build strict cutover checker.
  - Acceptance: cutover fails on unmapped workflows, active queues, secret
    readability, missing P0 evidence, missing/stale feature probes, direct
    provider access, unmanaged outbound paths, invalid lockfile, unresolved
    included-workflow decisions, or missing rollback rehearsal.
  - Verify: `pnpm dev hermes cutover-check --strict --json`.
  - Files: `src/hermes/**`, tests.

## Verification Strategy

Use three levels of proof:

- **Static proof:** generated manifests, sensitivity classification, toolset
  policies, skill provenance, profile config diffs.
- **Replay proof:** fixed fixtures for chats, provider calls, approvals, memory,
  public channels, cron, and workflows.
- **Adversarial proof:** malicious plugin, MCP subprocess, terminal, code
  execution, cooperative guards disabled, and direct network probes.

Baseline commands:

```bash
pnpm typecheck
pnpm lint
pnpm test
pnpm dev doctor --json
pnpm dev doctor --secrets --network --json
pnpm dev integration-test --harness
pnpm dev hermes parity --providers --memory --redaction --identity --shadow --browser --social --household --longrun
pnpm dev hermes prove --upstream-clean --p0
pnpm dev hermes cutover-check --strict
```

Named gates:

- `G-INGRESS-ALL-CHANNELS`: infra-secret and authorization gates fire before
  the model on Telegram, WhatsApp, email, AgentMail, and social webhooks.
- `G-EGRESS-REDACT-ALL-CHANNELS`: CORE secrets, including split-chunk secrets,
  are redacted on every outbound channel, and the channel cannot egress except
  through the relay/edge.
- `G-PLUGIN-OVERRIDE`: planted memory/model-provider plugins do not load in
  production profiles.
- `G-MCP-HARDENING`: malicious MCP servers cannot expose unauthorized tools,
  resources, prompts, roots, env, cwd, subprocesses, network helpers, or sidecar
  sockets.
- `G-MEM-BUILTIN`: public/social content written into Hermes built-in memory
  does not persist into private domains or later sessions.
- `G-SAMPLING`: MCP `sampling/createMessage` requests are refused.
- `G-USEFUL-PROVIDERS`: scoped bank, Clalit/health, government, and Google reads
  and prepared actions work through sidecars without write approval friction; the
  envelope still gates sensitive reads by identity/scope, gates read release by
  recipient/thread authorization, and blocks unapproved writes.
- `G-PROVIDER-APPROVAL-BINDING`: provider write tokens bind actor,
  profile/domain, provider account, approver identity, approval request/card ID
  and revision, WYSIWYS render, service/action, params hash, idempotency key, TTL,
  and one-time JTI; replay, mutation, wrong account, wrong card revision, wrong
  approver, and approve-then-revoke-then-execute all fail closed.
- `G-HOUSEHOLD-SCOPES`: a family member can complete allowed household tasks
  over WhatsApp/email but cannot access private operator memory, another family
  member's memory/provider context, or unscoped provider powers. A bare
  WhatsApp number cannot read bank/health/government/provider PII without a
  strong identity link.
- `G-IDENTITY-MIGRATION`: private, family, public, social, and provider actor
  migration fixtures preserve allow/deny/revoke/ban/pair/wrong-thread semantics.
- `G-EDGE-ADAPTERS`: WhatsApp/email/AgentMail/social production traffic can only
  ingress and egress through Telclaude edge adapters, while Hermes sees sanitized
  events and typed send requests.
- `G-SOCIAL-PARITY`: social timeline ingestion, posting, replies, budgets,
  backend failure, and private-leakage denial pass against X/Moltbook fixtures.
- `G-MODEL-RELAY`: Hermes model traffic is relay-mediated through an approved
  Telclaude relay/proxy path; direct egress to model hosts other than that path
  fails at the OS/network layer.
- `G-UPSTREAM-NOFORK`: a fresh pinned upstream Hermes install plus wrapper package
  runs included P0 fixtures with no Hermes diff, patch, monkeypatch, or runtime
  source replacement.
- `G-HEADLESS-OR-ADAPTER-CONTRACT`: sanitized channel events can enter a named
  Hermes profile/session and stream back through Telclaude with deterministic
  session mapping, cancellation, retry, duplicate handling, and error reporting.
- `G-HEADLESS-ENTRYPOINT`: the chosen private execution path proves streaming,
  session reuse, `/new`, cancellation, tool-result return, approval wait/resume,
  or explicit cross-turn approval fallback, concurrent sessions, and
  deterministic error mapping.
- `G-EDGE-FEATURE-PARITY`: WhatsApp/email/AgentMail/social adapters preserve
  threading, reply-to, attachments, media quarantine, voice-note support or
  explicit denial, contact identity, delivery failures, rate limits, cron
  delivery, and status without exposing raw credentials.
- `G-OUTBOUND-BYPASS`: terminal, browser, plugin, MCP subprocess, built-in send
  tools, email tools, social tools, HTTP POST, DNS, DoH/DoT, WebSocket/WebRTC,
  CONNECT/proxy tunneling, IP literals, DNS rebinding, file upload, localhost
  callbacks, service workers, extension/native messaging, and cron cannot bypass
  Telclaude outbound policy.
- `G-MODEL-CREDENTIAL-ABSENCE`: no production Hermes env/file/process args/child
  env/log/session DB/generated profile/plugin config/MCP config/browser store
  contains model-provider secrets, and a malicious model-provider plugin cannot
  override the relay route.
- `G-APPROVAL-CONTINUATION`: approval waiters either resume the original Hermes
  run through a proven pinned-Hermes permission channel exactly once, or the
  workflow uses the explicit cross-turn fallback: prepare ends the turn, approval
  happens out-of-band, execute starts a fresh turn from the immutable prepared
  ref, and no duplicate side effect occurs.
- `G-BROWSER-COMPUTER`: browser/computer use has isolated profiles, no shared
  cookies, target-app/window allowlists, isolated display/session state,
  clipboard policy, upload/download/screenshot/video quarantine and retention,
  step budgets, form/UI-submit approvals, and audit.
- `G-CRON-IDEMPOTENCY`: cron jobs are deduplicated, bounded, cancellable,
  auditable, and cannot deliver directly to public platforms.
- `G-LONGRUN-IDEMPOTENCY`: workflows can survive approval waits, provider
  timeouts, model timeouts, process restarts, and operator cancellation without
  duplicating side effects.
- `G-LOG-STATE-REDACTION`: redaction covers Hermes logs, gateway logs, MCP
  frames, tool args/results, stdout/stderr, exception traces, session DB,
  summaries, browser screenshots, attachment metadata, and control-room displays.
- `G-DATA-RETENTION-ERASURE`: public, household, health, bank, government,
  Google, attachments, screenshots, and audit logs have retention, deletion,
  export, and quarantine policies.
- `G-MULTIPROFILE-CONCURRENCY`: simultaneous private/public/household/specialist
  sessions cannot cross memories, approvals, channels, files, provider scopes,
  queues, or outbound ledgers.
- `G-BROWSER-BROKER`: allowed web/browser research works through the broker, while
  direct SMTP/IMAP/WhatsApp/model/vault/provider/private endpoint routes fail.
- `G-NO-HANDICAP`: the named workflow set completes end-to-end in shadow with
  zero operator approvals for scoped family routines, chief-of-staff reads,
  provider reads/prepares after identity/scope and recipient/release checks, web
  research, and allowlisted scoped replies; approvals appear only for the
  enumerated sensitive write/new-recipient/public-post/provider-execute set.
- `G-CUTOVER-EVIDENCE`: strict cutover fails on unresolved decisions for included
  workflows, direct-Hermes credential evidence, missing feature probes, mutable
  guardrail drift, unreviewed `HERMES_HOME` drift, missing negative tests, or no
  rollback rehearsal.

## Boundaries

Always:

- Pin Hermes for production.
- Generate profiles reproducibly.
- Keep private/provider secrets outside Hermes.
- Keep model, public-channel, private, and provider production credentials
  outside Hermes.
- Run public/autonomous profiles in whole-process isolation.
- Preserve signed provider-write approval tokens.
- Preserve Telclaude streaming redaction at egress.
- Treat all public/social inputs as untrusted.
- Make useful scoped powers available through sidecars instead of disabling
  provider, WhatsApp, email, browser, or automation workflows wholesale.
- Prove parity with fixtures before cutover.

Ask first:

- Letting Hermes directly hold any public identity credential even for
  disposable shadow/testing.
- Sharing one `tc-public` profile across all public channels instead of
  per-channel profiles.
- Allowing autonomous outbound to new recipients.
- Replacing a Telegram card/approval semantic with Hermes UX.
- Accepting any explicit security downgrade.

Never:

- Fork Hermes or patch Hermes main for required behavior.
- Depend on unmerged Hermes PRs/issues for production guarantees.
- Treat Hermes hooks/plugins/toolsets as hard containment.
- Route private Telegram directly to Hermes before parity approval.
- Put private/provider OAuth/API credentials in Hermes env/files.
- Put production WhatsApp/email/AgentMail/model credentials in Hermes env/files.
- Let public/social memory enter private LLM context.
- Let unknown public attachments auto-enter private or privileged contexts.
- Allow writable production `plugins/`, `plugins/memory/`,
  `plugins/model-providers/`, MCP config, toolset config, or promoted skills.

## Success Criteria

- `telclaude hermes doctor` verifies pinned upstream Hermes and wrapper
  readiness.
- `telclaude hermes generate --dry-run` emits clean, reproducible profiles with
  no private raw secrets.
- Private Telegram parity passes through Telclaude-fronted Hermes headless mode.
- Provider read/write parity passes with signed one-time approval tokens.
- Public identity works in shadow over WhatsApp, email, AgentMail, and social
  through sidecar/vault custody, with any direct-Hermes credential use marked as
  disposable downgrade only.
- Direct-Hermes credential smoke tests are excluded from production parity
  evidence.
- Public/social/private memory boundaries pass adversarial tests.
- Browser/web/computer/tool/skill access is controlled by OS/container policy,
  not only by prompts or hooks.
- Brokered browser/web access proves Hermes remains useful for allowed research
  and automation without direct sensitive/provider/covert egress.
- Chief-of-staff workflows pass dry-run fixtures.
- Household WhatsApp/email and provider-power fixtures pass, including routine
  useful actions and sensitive-action approvals.
- Cutover checker fails closed for every unmapped or unsafe condition.
- Operator can run the approved workflow set entirely through the wrapper.

## Open Questions

Each open question below is a decision-log candidate, not permission to ship
ambiguity. Any question that gates an included workflow bundle must be represented
in the decision log with owner, deadline phase, accepted answer, affected
workflows, cutover impact, and downgrade note where applicable. Any included
workflow depending on an unanswered question fails strict cutover.

1. Should `tc-public` be one cohesive public identity across WhatsApp, email,
   AgentMail, and social, or separate profiles per channel sharing only
   Telclaude-mediated public memory?
2. Which production edge adapter should land first: WhatsApp, email, AgentMail,
   or social? All production channel credentials remain Telclaude sidecar/vault
   owned.
3. Which private Telegram headless contract should become the production path:
   programmatic Hermes runner, CLI single-query, or local API server inside the
   private isolation domain?
4. Which outbound messages may bypass explicit approval: existing-thread replies,
   allowlisted recipients, operator cron notifications, or none?
5. Which current Telegram card/status semantics are mandatory parity versus
   acceptable Hermes UX replacements?
6. Should AgentMail be included in the first production parity set through a
   Telclaude vault/sidecar, or left as disposable shadow-only until the wrapper
   exists?
7. Which workflows are inside the first complete-parity cutover set, and which
   are intentionally left disabled until a later all-or-nothing gate?
8. Is there a fork-free IMAP/SMTP inbound ingestion seam that keeps credentials
   out of Hermes, or is email production necessarily Telclaude-edge/AgentMail
   sidecar first?
9. Does Hermes expose a stable headless entrypoint signature suitable for the
   private production contract, and which version is pinned?
10. Which LLM relay seam is pinned for production: Hermes model-provider/
    endpoint override, transparent network route to the Telclaude relay, or a
    disabled workflow until a credential-free relay path is proven?
11. Which family members and household roles belong in the first WhatsApp
    parity set, and what provider scopes can each use?
12. Which bank, Clalit/health, government, and Google sidecar actions should be
    allowed as routine delegated actions versus approval-required writes?
