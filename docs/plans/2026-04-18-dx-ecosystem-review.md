# Telclaude DX & Ecosystem Review — April 2026

Status: APPROVED 2026-04-18 — execution in flight
Owner: Aviv (driver), claude (integrator), codex (parallel implementation via AMQ), subagents (worktree per workstream)
Scope: P0 + P1 + P2 + W15 (W11 ruled out; W5 parked on radar). Hard breaks allowed (no compat shims). No backwards-compat; we are the only users.

---

## Executive summary

Five parallel research streams (three subagents + codex via AMQ, plus a DX audit subagent) converged on this picture:

1. **vestauth.com → skip.** It solves *inbound* RFC 9421 agent-auth. Telclaude is outbound-only; its core invariant is that agents never see signing keys. Adopting vestauth would regress confused-deputy protection. Both independent streams (subagent + codex) reached the same verdict. Vestauth itself signals this isn't their space: their README lists "Send/Receive Telegram" and "Human-in-the-loop" as "coming soon".
2. **Hermes (Nous Research) has the most mature Telegram control plane** in the ecosystem. Codex and the Hermes-focused subagent independently identified ~6 ideas worth porting.
3. **Openclaw & Ironclaw lead on approval UX, skill-supply-chain hardening, and — critically — onboarding.** All three peers now ship `<name> onboard` and `<name> doctor` flows. Telclaude has neither. This is the single biggest gap in the "rough around the edges" feeling.
4. **Telclaude's skill & provider onboarding has real structural issues**, not just missing polish. Codex caught two real bugs: (a) `docs/providers.md` never tells operators to run `telclaude network add`, but `src/providers/provider-validation.ts:27-29` throws a confusing error when the private-endpoint allowlist is empty; (b) `skills import-openclaw` targets `.claude/skills/openclaw` (active dir) by default — bypassing the draft/promote quarantine that `/skills promote` teaches operators to expect.
5. **Telclaude's security core is ahead of peers.** The vault, approval-token system (Ed25519 + JTI + params-hash binding + domain separation), memory split, and PreToolUse-primary enforcement are stronger than equivalent components in Openclaw/Ironclaw/Hermes. **Keep and document; don't rewrite.**

The net: we've already won the security-architecture race. Where we lose is operator ergonomics and onboarding. This review proposes 15 workstreams, prioritized.

---

## Goals & non-goals

### Goals
- Reduce operator-side friction for the mobile-first solo use case.
- Collapse provider onboarding from "edit ~15 files" to "run one command + answer a wizard".
- Port proven ecosystem ergonomics (Hermes approvals, Openclaw exec-policy, Ironclaw graduated risk, universal onboard+doctor) without weakening telclaude's stricter invariants.
- Fix the two documentation/flow bugs codex caught.
- Stay under 1.0 — we can still break things; prefer boldness over backwards-compat gymnastics.

### Non-goals
- Rewrite the vault or the credential proxy. Both are ahead of peers.
- Adopt vestauth. Decided: skip.
- Chase Composio (850 SaaS via one integration) in this review — needs its own security design doc because it conflicts with "agents never see creds".
- Build a heavyweight web dashboard. A small local one is on the radar (W15) but Telegram stays primary.
- Expose an inbound agent-callable HTTP surface.
- Pair with other agents.

---

## Research summary (one paragraph per stream)

**Hermes control plane (Nous Research, `hermes-agent`, v0.5–0.9 over the last quarter; subagent + codex independently confirmed).** Ships a messaging gateway that unifies Telegram/Discord/Slack/etc behind one runtime with: inline-keyboard approvals with four scopes (once/session/always/deny), interactive `/model` picker with pagination via message edits, DM pairing codes for first-touch access (rate-limited, 1h expiry), `/sethome` + conversational cron authoring, `/background` jobs with auto-notifications, topic-bound sessions with per-topic skill + system-prompt overrides, and a local web dashboard (v0.9.0, April 13). Live model switching and approval buttons landed v0.8.0 (April 8). Multi-instance profiles + Telegram webhook mode landed v0.6.0 (March 30). Sources: github.com/NousResearch/hermes-agent/releases, hermes-agent.nousresearch.com/docs/user-guide/messaging.

**Openclaw & Ironclaw (the "alternatives" from issue #61).** Openclaw 2026.4.x shipped `exec-policy` CLI with per-agent glob allowlists and "safe bins" (stdin-only utils auto-allowed), ClawHub-in-UI skill install + code signing (reaction to Jan 2026 supply-chain incident with 341 malicious SKILL.md files), credential proxy pattern (validates telclaude's architecture), and a model auth-status card. Ironclaw 0.22–0.25 added graduated approval risk levels (low/med/high with auto-approve low) with approval-queue merging, deployment profiles, Composio native tool, and a dual-mode live/replay test harness. Both projects expose `onboard`, `doctor`, and gateway lifecycle commands (`install|start|stop|status`). Sources: github.com/openclaw/openclaw, github.com/nearai/ironclaw.

**vestauth.com evaluation.** Product from the dotenvx author. Implements RFC 9421 HTTP Message Signatures + web-bot-auth draft. Agent-side CLI signs outbound HTTP requests with Ed25519; server-side SDK verifies. Useful shape: "my server receives requests from agents I don't fully control." Telclaude is the opposite shape — closed-loop relay, no inbound agent traffic. Agent-side signing would require putting keys in agent containers, breaking "agents never see credentials". **Verdict: skip.** Revisit only if telclaude ever exposes a public webhook; even then, implement RFC 9421 directly against the existing vault keypair rather than adopting vestauth's stack. Codex independently reached the same verdict with the same reasoning.

**Telclaude DX audit.** Adding a skill: 6 manual steps, works but no scaffold. Adding a provider: ~15 files, ~7 categories, 500+ LOC for a new sidecar. Pain points: `src/oauth/registry.ts:43-78` hardcoded service list; `src/commands/setup-google.ts` is 150 lines of copy-paste boilerplate that ends with "now deploy sidecar manually and edit config"; `docker/init-firewall.sh:32` comments warn that it must stay in sync with `src/sandbox/domains.ts` (two sources of truth); `src/sdk/client.ts:995-1003` fail-closed `allowedSkills` default for SOCIAL can silently deny all skills if misconfigured; `/skills reload` is Telegram-only, no CLI equivalent.

**Codex independent memo.** Independently confirmed vestauth-skip and Hermes patterns. Added high-leverage findings the subagents missed: (a) `provider-validation.ts:27-29` throws an undocumented "`telclaude network add`" error — docs/providers.md doesn't mention this step, so the documented path fails even when the provider is implemented correctly; (b) `skills import-openclaw` defaults its target to `.claude/skills/openclaw` active dir, bypassing the draft/promote workflow that Telegram teaches operators to use (`src/commands/skills-import.ts:340-347` vs `src/commands/skills-promote.ts:4-12`); (c) `provider-query` is registered as an internal top-level command only (`src/index.ts:117-127`) yet the external-provider skill depends on it — operators have no `providers list`/`schema`/`doctor` surface; (d) skill-root resolution probes multiple candidate roots and silently degrades to prompt injection (`src/providers/provider-skill.ts:371-400`, `src/commands/skill-path.ts:37-53`); (e) `setup-google` ends with manual deploy-sidecar-and-edit-config steps rather than finishing the integration; (f) every peer (Hermes / Openclaw / Ironclaw) has converged on `<name> onboard` + `<name> doctor` + gateway lifecycle — telclaude has neither.

---

## Workstreams

Each workstream has: what, why, where it lives, acceptance criteria, rough effort. Priority tags at end.

### W1 — Graduated approval scopes (Hermes + Ironclaw)
**What.** Replace single-scope `/approve CODE` flow with an inline keyboard offering **Approve once / Approve this session / Approve always / Deny**. Merge with Ironclaw's risk tiers: low-risk actions auto-approve, medium prompts once, high always prompts regardless of "always" scope.

**Why.** Biggest mobile-UX win. One tap to "approve always for this tool this chat" eliminates 10–30 subsequent prompts per coding session. "Session" scope is the natural extension of our existing 5-minute TTL.

**Where.**
- `src/telegram/cards/renderers/` — new `ApprovalScopeCard` renderer (current registry is fixed to 7 cards, codex ref `src/telegram/cards/renderers/index.ts:13-22`; add this one)
- `src/telegram/cards/callback-tokens.ts` — carry `scope` in callback token
- `src/security/approvals.ts` — extend approval record with `scope: 'once' | 'session' | 'always'` + per-(user, tool_key, scope) allowlist keyed off session id
- `src/security/pipeline.ts` — consult allowlist before generating a prompt; auto-approve low-risk against the allowlist
- SQLite: `approval_allowlist` table (user_id, tier, tool_key, scope, granted_at, expires_at)

**Risk tiering.** Classify at pipeline step. Low = read tools + safe bins. Medium = Write/Edit/Bash non-destructive. High = destructive Bash, FULL_ACCESS ops, cross-persona queries. High never upgrades to "always".

**Acceptance.** ApprovalCard shows four buttons on non-low-risk tool calls; "always" for low/medium persists across sessions and can be revoked; "session" scope expires on `/new` or session rotation; "high" actions always prompt; existing `/approve CODE` continues working as fallback (audit-friendly copy-paste path); unit tests for scope grant/expiry/downgrade; integration test showing a multi-step session with one "always" grant produces zero further prompts.

**Effort.** ~3–5 days. **P0.**

---

### W2 — Interactive pickers (Hermes; codex-augmented)
**What.** Inline-keyboard pickers navigating via `editMessageReplyMarkup` (no chat clutter) for:
- `/model` — paginated model list per provider, Prev/Next/Back/Cancel, shows current model + tier + fallback state
- `/skills` — upgrade drafts list + promote flow to inline keyboard
- `/providers` — list providers with health icons, tap for detail (auth expiry, rate pressure, last-error)
- `/background` — list active background jobs, tap for status/cancel (see W12)

**Why.** `/skills drafts|promote|reload` today is CLI-shaped; you must remember names. Pickers are the mobile-native answer and we already have the card + callback-token infra.

**Where.**
- `src/telegram/cards/renderers/` — `ModelPickerCard`, `SkillPickerCard`, `ProviderListCard`, `BackgroundListCard`
- `src/telegram/cards/callback-tokens.ts` — pagination cursors
- `src/telegram/intent-router.ts` — NL entry ("switch to Sonnet" → `ModelPickerCard` pre-filtered)
- `src/telegram/control-command-actions.ts` + `src/telegram/control-commands.ts` — add `/model`, `/providers`, `/background`; un-hide `/skills` subcommands from catalog (codex ref `src/telegram/control-commands.ts:390-440`)

**Acceptance.** All four commands open a picker; navigation uses message-edit not new messages; NL phrase "switch to sonnet" opens `ModelPickerCard`; callback tokens ≤10 min single-use; `/providers` surfaces auth expiry and remediation commands.

**Effort.** ~3–4 days. **P0.**

---

### W3 — `/sethome` + conversational cron (Hermes)
**What.** Telegram command `/sethome` persists a home chat/topic for cron delivery. Agent gains tool-level cron CRUD behind WRITE_LOCAL+. "Every weekday at 9am check HN and post here" → agent writes the cron job itself.

**Why.** Today cron is CLI-shaped. For mobile operators this is the difference between "I'll set that up at my laptop later" and "done in 10 seconds."

**Where.**
- `src/telegram/control-command-actions.ts` — `/sethome` handler
- Storage (new or `src/config/sessions.ts`) — per-user `homeChatId`, `homeThreadId`
- `src/cron/schedule.ts` — job schema gains `deliveryTarget: 'home' | 'origin' | {chatId, threadId}`
- `src/cron/runner.ts` — resolve delivery target at dispatch
- `src/sdk/client.ts` — expose cron CRUD as tool calls behind WRITE_LOCAL+
- `src/telegram/intent-router.ts` — parse NL schedule phrases (chrono-node); fall back to existing wizard on parse failure

**Acceptance.** `/sethome` persists; visible in `/system`; NL schedule phrase creates a cron job delivered to home; `/cron list` shows delivery targets; tier gated.

**Effort.** ~3–4 days. **P1.**

---

### W4 — DM pairing codes (Hermes)
**What.** Replace "edit `allowedChats` + restart + admin-claim" with: stranger DMs bot → bot replies with one-time code + rate-limit notice → operator approves via `telclaude pairing approve <code>` (CLI) or admin-chat command. Rate limits: 1/10 min/user, max 3 pending, 5-fail → 1h lockout, codes expire 1h.

**Why.** Current first-run requires config edit + restart for every new user. Pairing flow is strictly better: no restart, rate-limited, time-bounded, reuses callback-token machinery. Same UX story as Hermes / Openclaw DM pairing.

**Where.**
- `src/telegram/inbound.ts` — unknown-chat detection emits pairing code instead of silent drop
- `src/commands/pairing.ts` (new) — `list`, `approve`, `revoke`, `clear-pending`
- `src/security/rate-limits.ts` — pairing-specific limits
- `src/security/approvals.ts` — pairing codes reuse Ed25519-signed short-code format
- SQLite: `pairing_requests` table

**Acceptance.** Unknown-chat DM replies with code + one-line explainer; rate limits enforced; lockouts visible; pairing grants configured tier (default READ_ONLY); `allowedChats` still works (additive); single-use cryptographically verified codes with 1h expiry.

**Effort.** ~2–3 days. **P0.**

---

### W5 — Chat topics as parallel sessions (Hermes) — *P3, defer*
**What.** Use `(chatId, threadId)` as session key. Config: `topicBindings: [{threadId, skills?, personaOverride?, systemPrompt?}]`.

**Why / Risks.** Lets an operator run work/home/social-drafting in parallel in one Telegram group. But topics are group-only, some clients render poorly, and the private/social air-gap needs re-asserting at topic level. Low immediate payoff vs. complexity.

**Effort.** ~4–5 days. **P3 — defer until W1–W4 + onboarding wins ship.**

---

### W6 — Skill scaffold + unified lifecycle (DX audit #1; codex-augmented)
**What.**
- `telclaude skill-scaffold <name> [--template <t>]` creates `.claude/skills-draft/<name>/` with filled frontmatter, subdirs, and a `PREVIEW.md` checklist.
- **Fix `skills import-openclaw` to default its target to `.claude/skills-draft/openclaw/<name>/` instead of `.claude/skills/openclaw/`** (codex ref: `src/commands/skills-import.ts:346` vs `src/commands/skills-promote.ts:4-12`). Imports should route through the same draft/promote/review flow as locally authored skills.
- Unify skill-root resolution: one canonical writable root (eliminate the silent-degrade probe in `src/providers/provider-skill.ts:371-400` + `src/commands/skill-path.ts:37-53`).
- Expand Telegram `/skills` to `/skills list|new|import|scan|doctor|drafts|promote|reload|sign` (W9 adds `sign`). Un-hide from catalog.
- Add CLI equivalent to `/skills reload`.

**Why.** Current lifecycle is inconsistent: imports bypass quarantine, skill-root probing hides config errors, Telegram surface is narrower than the CLI. A new operator trying to onboard a skill from Openclaw today lands in an unexpected directory and gets a different flow than local authoring.

**Where.**
- `src/commands/skill-scaffold.ts` (new)
- `src/commands/skills-import.ts:346` — change default target to draft dir
- `src/providers/provider-skill.ts`, `src/commands/skill-path.ts` — unify to single `getSkillRoot()` utility
- `src/telegram/control-commands.ts:390-440` — expand `/skills`, un-hide
- `assets/skill-templates/` — basic/api-client/telegram-render templates

**Acceptance.** Scaffold produces a valid SKILL.md passing existing scanner; `skills import-openclaw` lands in drafts by default (flag to override); `skills doctor` returns pass/warn/fail per skill; Telegram `/skills` catalog mirrors CLI; one documented canonical skill-root path.

**Effort.** ~2–3 days. **P1.**

---

### W7 — Provider scaffold + `providers.json` unification + doc fixes (DX audit #2+#3; codex-augmented)
**What.** A single declarative `providers.json` becomes the source of truth. `telclaude providers init <id>` reads it and generates:
- OAuth registry entry (derived, not hand-edited in `src/oauth/registry.ts:43-78`)
- Setup command stub in `src/commands/setup-<id>.ts` (but the setup command **finishes the integration**: after OAuth success, offer "register provider config now? add network allowlist now? run provider doctor now?" — fixes codex finding on `src/commands/setup-google.ts:227-229`)
- Sidecar skeleton in `src/<id>-services/`
- Dockerfile + docker-compose block
- .env.example entries
- Firewall allowlist entry (derived from providers.json, not hand-synced)
- **Private-endpoint allowlist auto-added (`telclaude network add` integrated into the flow — fixes the missing doc step from `src/providers/provider-validation.ts:27-29`)**

Replace the internal `provider-query` command with a discoverable family: `telclaude providers list|schema|query|setup|doctor`. `query` supports schema-driven prompting, not raw JSON; auto-infers actor user ID from runtime context.

**Why.** Biggest DX win. Collapses ~15 files × 7 categories into one config + one generator run. Kills the `init-firewall.sh` ↔ `src/sandbox/domains.ts` sync hazard. Fixes the undocumented `telclaude network add` trap. Makes the external-provider skill robust (today it depends on an internal command and scrapes `<request-context user-id="...">` from prompt — `.claude/skills/external-provider/SKILL.md:29-39`).

**Where.**
- `providers.json` (repo root or `src/config/`)
- `src/oauth/registry.ts` — derive from providers.json (keep Zod typing)
- `src/commands/providers.ts` (new) — `list|schema|query|setup|init|doctor` under one parent
- `src/index.ts:117-127` — promote providers from internal to public
- `src/commands/setup-google.ts:21-50,227-229` — migrate + finish-integration behavior
- `docker/init-firewall.sh:32` + `src/sandbox/domains.ts` — both derive from providers.json (share a TS module or codegen a shell fragment at build time)
- `docs/providers.md:69-185` — rewrite around the new scaffold + document `telclaude network add` correctly

**Acceptance.** `providers init notion …` produces a buildable skeleton with all 7 categories covered; google-services is migrated in the same PR (no parallel formats); `providers doctor notion` gives pass/warn/fail per check including network allowlist state; firewall rules derive from providers.json; `providers query` uses schema-driven prompts; provider-query old command hidden with deprecation shim; all tests pass; `docs/providers.md` end-to-end matches reality including the network-allowlist step.

**Effort.** ~6–8 days. **P1.** Plan 8, budget 10 for google-services migration surprises.

---

### W8 — Exec-policy allowlists & "safe bins" (Openclaw 2026.4.12)
**What.** Port Openclaw's host guardrail to WRITE_LOCAL/FULL_ACCESS tiers. Per-chat glob allowlists persisted in a policy file. "Safe bins" (cut/head/tail/wc/grep read-only) auto-allow when args are stdin-only (no positional paths, no redirects into new files).

**Why.** Today FULL_ACCESS is binary and WRITE_LOCAL blocking is heuristic. Real allowlist → graduated trust without "turn off all safety for one command".

**Where.**
- `src/security/exec-policy.ts` (new) — glob matcher + safe-bins catalog
- `src/security/pipeline.ts` — consult policy before approval
- `~/.telclaude/exec-policy.json` or per-chat SQLite — persisted allowlist
- Integrates with W1: "approve always" for a Bash command writes into exec-policy.

**Acceptance.** Safe bins run without approval in WRITE_LOCAL if no positional/redirect args; `telclaude exec-policy list|add|revoke` CLI; per-chat policy; strict-profile enforces, simple-profile warns.

**Effort.** ~3–4 days. **P2.**

---

### W9 — Skill signing & draft-review card (Openclaw ClawHub / Jan 2026 incident)
**What.** Optional Ed25519 signature on SKILL.md (signed by vault). Unsigned skills flagged "community" in picker. Draft-review card shown before promote: diff vs. prior version, scanner findings, signature status, auto-install patterns matched.

**Why.** Openclaw's Jan 2026 ClawHub incident (341 malicious SKILL.md files) is the canonical case. Our `skills-draft/` quarantine is half the defense; operator-visible review card is the other half.

**Where.**
- `src/commands/skills-import.ts` — scanner emits structured findings
- `src/commands/skills-promote.ts` — present review card before move
- `src/telegram/cards/renderers/` — `SkillReviewCard`
- `src/vault-daemon/server.ts` — `sign-skill` / `verify-skill` with `skill-v1` prefix for domain separation (distinct from `approval-v1`, `session-v1`)

**Acceptance.** Promote shows review card with findings + signature state; unsigned gets "community" badge, not blocked; `telclaude skills sign <name>` signs via vault; domain-separated signing prefix enforced.

**Effort.** ~3–4 days. **P2.**

---

### W10 — `/system` health card (Openclaw 2026.4.15; codex-expanded)
**What.** Extend `/system` with a live health snapshot: current model + tier + fallback state; Anthropic/OpenAI OAuth token expiry; Google OAuth refresh-token health; provider sidecar health (from `/v1/health`); vault uptime; cron lag; pending approvals count; heartbeat last/next run; active session IDs; current skill set.

**Why.** Today operators discover auth expiry via failure. A 1-tap health card is the mobile dashboard. Codex notes `src/providers/provider-health.ts:38-124` + `src/telegram/status-overview.ts:15-84` already have the aggregation machinery — the gap is the operator UX.

**Where.**
- `src/telegram/cards/renderers/` — `SystemHealthCard`
- `src/telegram/control-command-actions.ts` — hook into `/system`
- `src/relay/capabilities.ts` + existing health modules — aggregate
- Remediation tap-through: degraded item → remediation card with command (e.g., `telclaude setup-google`)

**Acceptance.** `/system` surfaces summary; tap "health" for details; each service shows ok/degraded/auth_expired/unreachable; tap-through opens remediation card; pending approvals and heartbeat schedule surfaced.

**Effort.** ~2 days. **P0.**

---

### W11 — Composio — *ruled out*
Decision 2026-04-18: rule out. Conflicts with "agents never see creds" invariant and would need a per-action proxy layer for 850 APIs that's out of scope. Not revisiting.

---

### W12 — `/background` jobs with completion notifications (Hermes v0.8.0; codex)
**What.** First-class Telegram primitive for "kick off this work, notify me when done". Long-running tool calls (or explicit "run this in background") register as a tracked job; Telegram receives a status card on completion; optional cancellation via inline button.

**Why.** Today long-running agent work blocks the turn or silently runs. Hermes made this first-class in v0.8.0 and it's exactly the rough-edge removal mobile operators feel. Ties into cron (W3) and heartbeat machinery we already have.

**Where.**
- `src/cron/` — generalize job store or add `background_jobs` table
- `src/sdk/client.ts` — surface background tool or `&` directive (or integrate with existing `@silent` directive)
- `src/telegram/cards/renderers/` — `BackgroundJobCard` (status + cancel)
- `src/telegram/control-commands.ts` — `/background [list|cancel <id>]`
- Integration with W10 `/system` — show active background job count

**Acceptance.** Long-running tool call can be backgrounded; completion triggers a Telegram notification to origin (or home, per W3); cancellation works; jobs survive relay restart (persisted); tier-gated.

**Effort.** ~3–4 days. **P1.**

---

### W13 — `telclaude onboard` + `telclaude doctor` (Openclaw/Hermes/Ironclaw consensus; codex)
**What.** Two new top-level CLI commands.

`telclaude onboard`: interactive wizard that walks a new operator through:
1. Relay bootstrap (Docker vs native choice)
2. Telegram bot token entry (calls setup flow)
3. Admin chat claim
4. Optional: OpenAI / GitHub / Google OAuth setup (with setup-* commands chained)
5. Optional: social persona config
6. Final health check (runs `doctor`)

`telclaude doctor`: one-shot validation that returns pass/warn/fail across:
- Config loads; required fields present
- Telegram bot token valid (API reachable)
- Vault daemon up; keypair present
- TOTP daemon up (if configured)
- Network allowlist sensible; private-endpoint setup present
- Each configured provider: container reachable, `/v1/health` 200, `/v1/schema` valid, OAuth creds stored
- Each skill: scanner passes
- Docker mode: all 6 containers healthy
- Native mode: SDK sandbox present

**Why.** Universal pattern across all three peers. Telclaude's current `pnpm dev doctor --network --secrets` (`CLAUDE.md:84-107`) is partial. Operators currently assemble setup steps across README + CLAUDE.md + docs/providers.md manually. An `onboard` wizard is the single biggest first-time-operator ergonomic win.

**Where.**
- `src/commands/onboard.ts` (new)
- `src/commands/doctor.ts` — expand existing; add provider checks, skill checks, container checks
- `src/index.ts` — register both as public top-level commands

**Acceptance.** Fresh clone + `telclaude onboard` reaches a working relay with bot token, admin claim, and at least a READ_ONLY private chat tier — no manual config edits. `telclaude doctor` reports structured pass/warn/fail JSON on request (for CI).

**Effort.** ~3–5 days. **P0.**

---

### W14 — Gateway lifecycle commands (Openclaw/Hermes pattern)
**What.** `telclaude gateway install|start|stop|status|restart` wrapping docker-compose (or native supervisord-equivalent) with friendly output.

**Why.** Hermes/Openclaw both expose this. Reduces "edit docker-compose + run docker commands" to one verb per action. Pairs naturally with `onboard` and `doctor`.

**Where.**
- `src/commands/gateway.ts` (new)
- Shells out to docker-compose / native supervisor with wrapped error handling

**Acceptance.** All five verbs work in Docker mode; native mode emits sensible messages; `gateway status` returns container health matching `doctor`'s container section.

**Effort.** ~1–2 days. **P2.**

---

### W15 — Optional local dashboard (Hermes v0.9.0) — *P3*
**What.** Small local web UI (listening on localhost only, not exposed) showing: `/system` equivalent; provider + skill + approval lists; live audit log tail; on-demand `doctor` run.

**Why.** Hermes shipped one April 13; Ironclaw has a web gateway. Useful for the "operator at laptop" path without dethroning Telegram. Reduces terminal spelunking.

**Risks.** Scope creep risk. Needs auth (TOTP-gate) to access, network-allowlist to listen only on localhost.

**Effort.** ~5–7 days. **P3 — defer until P0–P2 ship.**

---

## Priority & sequencing

**P0 — foundation (mobile + first-time-operator):**
- W1 Graduated approval scopes
- W2 Interactive pickers (`/model`, `/providers`, `/background`, upgrade `/skills`)
- W4 DM pairing codes
- W10 `/system` health card
- W13 `telclaude onboard` + `doctor`

**P1 — streamlining:**
- W3 `/sethome` + conversational cron
- W6 Skill scaffold + lifecycle unification (fixes `import-openclaw` bug — **hard break, no legacy flag**)
- W7 `providers.json` unification + scaffold + doc fixes (fixes `network add` undocumented step; **hard break on google-services migration, no compat shim**)
- W12 `/background` jobs

**P2 — hardening + dashboard:**
- W8 Exec-policy + safe bins
- W9 Skill signing + review card
- W14 Gateway lifecycle commands
- W15 Local dashboard (approved)

**P3 — parked on radar (not in this arc):**
- W5 Chat topics as sessions

**Ruled out:** W11 Composio.

Total committed scope: ~35–40 engineer-days across parallel workstreams.

---

## Risks & open questions

1. **Approval scope "always" misuse.** Operator grants always for Bash, regrets it. Mitigation: tier caps (SOCIAL/WRITE_LOCAL can't escalate to FULL_ACCESS always); `/approvals revoke`; list in `/system`.
2. **providers.json migration.** Migrating google-services is a breaking internal change. Under 1.0 it's OK; plan migration in one PR.
3. **Firewall allowlist derivation fragility.** Shell consuming JSON via `jq` is fragile. Prefer: generate a shell fragment from TS at container build time; both `init-firewall.sh` and `domains.ts` consume it.
4. **Onboard wizard scope.** Temptation to make it a full IDE. Cap at: bot token, admin claim, optional OAuth setup, doctor. Nothing more in v1.
5. **Background jobs persistence.** If a relay restart drops background jobs, operators lose trust. Persist to SQLite before returning job id.
6. **`skills import-openclaw` break.** Changing the default target is a behavior change. Ship with a `--legacy-target` flag for one release + deprecation notice.
7. **Telegram topics (W5).** Client rendering varies. Not worth shipping without design review. Defer until demand is clear.
8. **Vestauth revisit trigger.** If telclaude ever exposes an inbound agent webhook, reopen. Current answer: no.
9. **Doc drift.** `docs/providers.md` being out of sync with runtime (the `network add` hole) is a symptom. Consider a `doctor` check that diffs docs against actual required setup steps.
10. **Effort estimates are ranges.** Provider scaffold (W7) especially could blow up. Plan 8 days, budget 10.

---

## Decisions (resolved 2026-04-18)

1. **Vestauth** — skip. Doc closed, not on watchlist.
2. **Priority ordering** — claude + codex agreed stack approved.
3. **Scope cap** — commit to all P0 + P1 + P2 + W15.
4. **providers.json migration** — hard break on google-services; no compat shim.
5. **`skills import-openclaw` default change** — hard break; no `--legacy-target` flag, no deprecation notice (we are the only users).
6. **W5 chat topics** — keep on radar (parked).
7. **W11 Composio** — ruled out.
8. **W15 local dashboard** — yes; included in P2 scope.

All known bugs also in scope for this arc. Codex bug-hunt 2026-04-18 found 12:

| # | Sev | Bug | Owner |
|---|---|---|---|
| 1 | P0 | OAuth `confidentialClient: false` inconsistent w/ vault schema + refresh emitting client_secret | W7 (codex) |
| 2 | P0 | `src/agent/client.ts:66-95` native FULL_ACCESS leaks `githubToken`/`openaiApiKey` to agents — invariant violation | ✅ fixed on main `c7dc242` (gated behind `TELCLAUDE_INSECURE_EXPOSE_NATIVE_CREDENTIALS=1`) |
| 3 | P1 | `docker/init-firewall.sh` vs `src/sandbox/domains.ts` allowlist drift | W7 (codex) |
| 4 | P1 | Telegram memory never asserts social-leak at runtime (social side does); invariant #8 only half-enforced | ✅ fixed on main `c7dc242` (assertNoSocialLeak) |
| 5 | P1 | `doctor` scans `./.claude/skills` only; misses Claude home + bundled roots | W13 (command-surface sweep) |
| 6 | P2 | TOTP refs still use removed top-level `telclaude totp-*` | W13 sweep |
| 7 | P2 | Vault remediation refs use removed `telclaude vault-daemon` | W13 sweep |
| 8 | P2 | OpenAI remediation refs use removed `telclaude setup-openai` | W13 sweep |
| 9 | P2 | Git/GitHub/Google setup refs use removed `telclaude setup-*` top-level | W13 sweep |
| 10 | P1 | Admin-claim success copy points to removed `/disable-2fa|/setup-2fa|/skip-totp` | W13 sweep |
| 11 | P2 | CLAUDE.md emergency runbook uses removed `telclaude ban|unban|force-reauth` | W13 sweep |
| 12 | P1 | Provider docs miss `telclaude network add` step + stale `setup-google` refs | ✅ partial fix on main `532bbc0` (network-add step added); remainder in W7 |

Status key: ✅ fixed on main | 🔄 in-flight workstream | ⏳ pending

Any additional bugs surfaced during execution → fix in-flight under the owning workstream.

## Execution plan

| Workstream | Priority | Owner | Isolation | Status |
|---|---|---|---|---|
| Bug fixes (round 1) | P0 | claude | main | ✅ committed `532bbc0`, `c7dc242` |
| W4 DM pairing codes | P0 | subagent A | worktree (writes to main tree ⚠) | in flight |
| W6 skill lifecycle | P1 | subagent B | branch `w6-skill-lifecycle` | ✅ complete (19 tests, 2 commits); symlink scanner issue surfaced (out of scope); awaiting merge |
| W12 `/background` jobs | P1 | subagent C | worktree (writes to main tree ⚠) | in flight |
| W7 providers.json megawin (+ bugs #1, #3, #12-rest) | P1 | codex (AMQ) | branch `codex/w7-providers-json` | ✅ implementation + tests done; committing now |
| W13 onboard + doctor + command-surface sweep (bugs #5–#11) | P0 | pending | own branch | queued (after W4/W6/W12 land) |
| W1 graduated approvals | P0 | pending | worktree | Wave 2 |
| W2 interactive pickers | P0 | pending | worktree | Wave 2 (needs W12) |
| W10 `/system` health card | P0 | pending | worktree | Wave 2 |
| W3 `/sethome` + cron | P1 | pending | worktree | Wave 2 |
| W8 exec-policy | P2 | pending | worktree | Wave 3 (integrates with W1) |
| W9 skill signing | P2 | pending | worktree | Wave 3 (after W6) |
| W14 gateway lifecycle | P2 | pending | worktree | Wave 3 |
| W15 local dashboard | P2 | pending | worktree | Wave 4 (consumes W10, W13) |

**⚠ Note on worktree isolation**: the first wave of subagents (W4/W6/W12) were launched with `isolation: "worktree"` but their changes appeared in the main working tree rather than the allocated worktree dirs under `.claude/worktrees/`. Claude will untangle into per-workstream branches at the merge boundary. Subsequent waves will use explicit branch naming in the brief to force isolation.

**Merge order**: bug fixes ✅ → [W4, W6, W12 split into per-workstream branches] → W7 → W10 + W13 → W1 + W2 → W3 + W8 + W9 + W14 → W15. Claude integrates and resolves conflicts at each wave boundary.

**Codex-review gate**: per `~/.claude/CLAUDE.md`, significant changes get a codex review before landing on main. Every workstream PR gets an AMQ review request.

---

## Appendix — source material

- **Hermes memo** (subagent): "What to Steal from Hermes for telclaude's Telegram Control Plane" — 5 ranked ideas with file paths.
- **Openclaw/Ironclaw memo** (subagent): "Telclaude DX Review Memo: Openclaw & Ironclaw (Apr 2026)" — exec-policy, graduated approvals, ClawHub signing, model auth card, Composio.
- **Vestauth memo** (subagent): "Vestauth vs. telclaude — evaluation memo" — skip verdict with reasoning.
- **DX audit memo** (subagent): "DX Audit: Skills & Providers in Telclaude" — 15 file touchpoints, scaffold proposals.
- **Codex independent memo** (AMQ): caught `provider-validation.ts:27-29` undocumented-error bug, `skills import-openclaw` default-target inconsistency, `provider-query` internal-command gap, skill-root resolution silent-degrade, `setup-google` half-done integration, and the ecosystem `onboard`/`doctor`/gateway consensus.
- Key external sources: github.com/NousResearch/hermes-agent/releases, hermes-agent.nousresearch.com/docs, github.com/openclaw/openclaw, github.com/nearai/ironclaw/releases, vestauth.com (skip).
- Verified codex claims live against repo:
  - `src/providers/provider-validation.ts:27-29` — confirmed: throws "Add a provider endpoint via `telclaude network add`" when `privateEndpoints` is empty.
  - `src/commands/skills-import.ts:346` — confirmed: default target is `.claude/skills/openclaw` (active dir), bypassing draft/promote quarantine.
