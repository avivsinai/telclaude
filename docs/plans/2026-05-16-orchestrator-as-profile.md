# Orchestrator-as-Profile — May 2026

Status: DESIGN — proposal only. No code yet.
Owner: Aviv (driver), claude (author), codex (peer review pending).
Scope: Can existing primitives fake a Hermes "Level 3" orchestrator pattern without a new subsystem?

## Problem statement

Shann Holmberg's Hermes operator playbook describes a "Level 3" stage where an `hermes-orchestrator` agent fronts a roster of specialists and routes the operator's high-level request to whichever specialist owns the work. Telclaude now ships three primitives that, on the surface, look orchestrator-shaped — operator profiles (`66b3c3b`, `a8055a9`, `b74057f`), Codex work units as background jobs (`110d0ba`, `083e250`), and the signed curator inbox (`e0dea00`, `4204968`, `4e11b36`). The question this pass answers is whether they compose into a useful orchestrator UX as-is, what the smallest viable handoff primitive looks like if not, and what we must not break while doing it.

## Brief framing — what I am pushing back on

1. **"Cron can fire scheduled prompts targeting specific chats" is half-true.** A cron `agent-prompt` resolves the chat → profile mapping at dispatch time (`src/cron/agent-action.ts` after `083e250` calls `resolveChatProfile(destination.chatId, cfg)`). The job does not carry its own profile id. So "cron fires a prompt at the engineer profile" only works if the destination chat is already bound to `engineer`. There is no per-job profile override today.
2. **"Drops a curator item the specialist picks up on its next cron tick" is not wired.** Curator items have no `targetProfileId` field, and the four existing kinds (`cron_hardening`, `background_attention`, `memory_queue`, `skill_review`) are operator-facing review items, not work queues. The curator is an inbox of suggestions for the human, not a mailbox between profiles.
3. **"Memory-promote that the specialist profile picks up" is blocked by design.** Commit `b74057f` scoped private memory by profile (`telegram:<profile-id>`). The runtime assertion in `src/memory/telegram-memory.ts` filters out (or in dev, throws on) cross-profile entries. This is the right invariant — see Architecture #8 — and we should not undo it to build orchestration on top.
4. **"Operator can bypass and `/profile switch engineer`" is correct and is probably the answer.** The honest orchestrator-equivalent here is operator-driven, not agent-driven.

Net: the brief's mental model assumes more cross-profile plumbing than exists. The real answer is that **the existing primitives compose for a narrower, operator-driven orchestrator pattern**, and any agent-driven cross-profile routing requires a small new primitive that we should design carefully or skip.

## What composes vs what is missing

| Need (Hermes Level 3) | Telclaude today | Gap |
|---|---|---|
| Front-door agent reads a roster | `/profile list` exists; profile SOUL.md overlay loads | Roster description is in operator's head, not in the front-door's prompt. Could be solved by a `router` profile whose SOUL embeds the table. |
| Front-door delegates to a specialist | `/codex` exists for Codex; no equivalent for "queue work for the engineer profile" | **Real gap.** No agent-callable handoff primitive exists. |
| Operator can address specialists directly | `/profile switch engineer` exists | Works as-is. |
| Specialist's tools/skills differ from front-door | Per-profile `allowedSkills`, `defaultModel`, `soulPath` exist | Works as-is. |
| Operator sees what each specialist is doing | `/background list`, `/curator`, `/system` exist; no "by profile" filter | Minor gap; cosmetic. |
| Handoff carries context | Memory is profile-scoped (intentionally air-gapped); curator items have no `targetProfileId` | **Real gap.** Cross-profile context transfer has no clean channel. |
| Specialist runs proactively when given a task | Cron `agent-prompt` fires at the chat's currently-bound profile | Need per-job profile override, or per-profile cron home chat. |

Two real gaps, both in the "handoff" lane: no agent-callable handoff primitive, no carrier for the handoff's context. Everything else is already there.

## Sizing options

### Option A — Tiny: convention only (zero code)

**What.** Document a `router` profile convention. The operator authors a `profiles/router/SOUL.md` that includes:

- A table of the other configured profiles (engineer, homeops, social-drafts, ...) with one-line responsibilities.
- A rule: "When the operator asks for work I cannot do directly, I recommend `/profile switch <id>` and summarize what I would hand off. I do not silently queue work for another profile."
- A rule: "For bounded code work, I may call `/codex` myself; the operator sees the work unit card."
- A rule: "Anything cross-domain returns a one-paragraph summary plus the exact `/profile switch` command to copy-paste."

**File deltas.**
- `docs/profiles.md` (new) — convention doc.
- `assets/profile-templates/router/SOUL.md` (new) — reference template.
- `README.md` — one paragraph.
- No code changes.

**UX.** Operator sends "ship the feature": router profile replies "this is engineer work — `/profile switch engineer` and re-send, or I can scope the spec here first." Operator either switches or stays. Honest, low-magic, no new attack surface.

**Security implications.** None new. The persona air-gap (Architecture invariants #1, #8) is preserved by construction because no cross-profile state is created.

**Cost.** Hours, not days. ~50 lines of markdown.

**Limit.** Not a real orchestrator. It is a router profile that recommends switches. There is no agent-driven delegation, no automatic context handoff, no background dispatch.

### Option B — Small: profile-aware codex + profile-scoped curator hint (1–2 commits)

**What.**
1. **Per-profile `/codex` policy.** Profiles gain optional `codex.allowedFromAgent: boolean` and `codex.defaultCwd?: string`. The router profile is the only one whose SOUL is allowed to invoke `/codex` programmatically via a structured directive. Other profiles must surface a button card instead.
2. **Curator `handoff_recommendation` kind.** Add a fifth curator item kind: `handoff_recommendation`. Producer = `claude-code` (signed envelope, same as the existing producer-auth path in `src/curator/auth.ts`). Fields: `fromProfileId`, `toProfileId`, `summary`, `proposedFirstMessage`, `evidence`. The item is **inert** — accepting it does not switch profiles or queue work; it generates a `/profile switch <id>` deeplink message in the chat.
3. **`/system` filter.** `/system` and `/background list` gain a `--profile <id>` filter so the operator can see what each specialist is in the middle of.

**File deltas.**
- `src/curator/types.ts` — new kind enum value.
- `src/curator/auth.ts` — claims hash includes new fields; no signing prefix change.
- `src/telegram/cards/renderers/curator-inbox.ts` — render the handoff item with a deeplink button.
- `src/config/config.ts` — extend `OperatorProfileConfigSchema` with optional `codex` block.
- `src/telegram/control-command-actions.ts` — `/system [--profile <id>]`, `/background list [--profile <id>]`.
- `docs/profiles.md`, `docs/architecture.md` — document handoff semantics.
- Tests: curator types, schema, renderer, control-command parsing.

**UX.** Operator chats with router. Router decides "this is engineer work" and writes a signed curator item. The operator sees an inbox card: "Hand off to engineer — accept to copy the proposed first message into your clipboard?" Operator taps; receives a chat message like `/profile switch engineer\n\nThe ask: ...`. Operator pastes (or, if we want one tap, the renderer can send both messages directly into the same chat). No agent ever wrote into a different profile's memory.

**Security implications.**
- Cross-profile information flow remains operator-mediated. Architecture #1 ("private LLM never processes social memory") is unchanged. #8 ("memory source boundaries are enforced at runtime") is unchanged because the handoff item lives in the curator table, not in either profile's memory. The handoff payload travels through the operator, not through memory.
- Curator producer signing (`4204968`, prefix `curator-producer-v1`) already prevents agent forgery of producer kind. Reuse as-is.
- New risk: the router profile could be tricked by a prompt injection into writing many spurious handoff items. Mitigations: rate-limit curator producer-signed writes from agents (already feasible — the vault sees every signing call), curator items expire, operator must accept each one. Severity: low. The damage ceiling is inbox spam, not privilege escalation.
- Codex policy change is a tightening, not a loosening. `/codex --write` already requires FULL_ACCESS (`110d0ba`). Per-profile gating only narrows.

**Cost.** 2–4 commits. ~300–500 LOC + tests.

**Limit.** Still operator-mediated. There is no automatic "engineer profile is now thinking about your feature." That is the right limit for alpha.

### Option C — Medium: cross-profile job queue + per-job profile override (3–6 commits, new subsystem)

**What.**
1. **Per-job profile override on cron.** `agent-prompt` cron action gains `targetProfileId?: string`. Dispatcher resolves the chat → profile mapping, then overrides if the job specifies one. The destination chat's session is forked for the run (do not mutate the chat's `chat_profiles` row).
2. **Agent-callable "queue for profile" tool.** New WRITE_LOCAL+ tool: `delegate_to_profile({ profileId, prompt, deliveryTarget? })`. Internally: creates a one-shot cron job (or a new `delegations` table — same shape) with `targetProfileId` set, dispatches immediately, returns a background job id. Operator sees a background card on completion. The originating profile **does not** receive the result automatically; only the operator does.
3. **Per-profile cron home.** `/sethome` learns a per-profile dimension so cron output from engineer-profile delegations lands in the engineer chat (if there is one) instead of the originating chat. Optional; defaults to origin chat.

**File deltas.**
- `src/cron/types.ts` — `targetProfileId` field on `agent-prompt`.
- `src/cron/agent-action.ts` — honor override, fork session, write a per-run audit row.
- `src/sdk/tools/delegate-to-profile.ts` (new) — tool definition.
- `src/security/permissions.ts` — gate the tool to WRITE_LOCAL+ and to profiles that explicitly opt in (`profile.canDelegate?: boolean` on the originating profile).
- `src/security/pipeline.ts` — PreToolUse hook for the new tool: deny if originating profile is not allowed to delegate, deny if target profile id is not configured, deny if `prompt` contains social memory markers (we never bridge social → private).
- New SQLite table `profile_delegations` for audit and replay protection.
- `src/telegram/cards/renderers/background.ts` — show originating profile + target profile on the job card.
- `src/telegram/control-command-actions.ts` — `/delegations list|cancel`.
- `docs/architecture.md` — add invariant #11: cross-profile delegations are operator-visible, audited, signed, and can never carry social-source content.
- Tests: tool gating, profile override, audit row, prompt injection cases.

**UX.** Operator sends a multi-part request to the router profile. Router decides "engineer handles the build, homeops handles the deploy" and calls `delegate_to_profile` twice. Each call surfaces a background job card. Operator sees both in flight; both return results in cards. Operator can `/profile switch engineer` to continue the conversation with the engineer profile from where the delegation left off (session-fork preserves context). Closer to Hermes Level 3 but still operator-visible.

**Security implications.**
- New invariant work. Must add to Architecture invariants:
  - Cross-profile delegations carry no social-source content. Enforced by inspecting the prompt for source markers and by limiting the tool to private profiles. Mirrors invariant #1.
  - The originating agent never sees the target agent's response. The relay holds the result and routes it to the operator's chat only. Mirrors invariant #3 (agents cannot reach other agents).
  - Delegations are first-class audit objects. Mirrors invariant #6/#10 (audit is non-overridable).
- New attack surface: a prompt injection inside the router profile could attempt to delegate harmful work to a high-privilege profile (e.g., one with FULL_ACCESS). Mitigations: tier of the target profile is capped at the operator's tier (already true via `src/security/permissions.ts`), delegated prompts pass through the same pipeline as operator messages, target profile re-runs the observer.
- Cron's existing `allowedSkills` per-job is the model to follow. Apply the target profile's `allowedSkills` to the forked session — never widen.
- New table = new migration. Under alpha rules, that's fine.

**Cost.** 3–6 commits. ~1500–2500 LOC + tests + docs.

**Limit.** Is a new subsystem. We are deciding here whether the orchestrator UX is worth a new subsystem in alpha. My read: not yet.

## Recommendation

**Ship Option A now. Hold Option B for the next operator-UX wave. Defer Option C until we feel actual pain.**

Reasoning:

1. **Option A unlocks 70% of the value with zero code.** Most Hermes Level 3 demos in the wild are operator-driven anyway — the orchestrator agent recommends, the human acts. A documented router-profile convention plus a template gets us there.
2. **Option B is the right next slice when the convention starts to chafe.** The signal will be: operator finds themselves repeatedly typing the same `/profile switch ... + here's the context` paragraph. At that point the handoff curator item is a small, well-scoped addition that reuses the producer-signing pattern we already shipped (`4204968`).
3. **Option C is a subsystem.** It introduces a new tool that lets one agent queue work for another agent in a different profile. Even with strong invariants this is a meaningful expansion of the trust graph. We have not yet demonstrated that operator-mediated handoffs are too slow. Ship A, run on it for a few weeks, then re-evaluate.
4. **Spec-driven discipline.** The brief asks for the minimum viable slice. A is the minimum. Anything more is speculative until the convention is in operator hands.

## Security invariants to preserve (cite `docs/architecture.md`)

Independent of which option ships:

- **Invariant #1** — Private LLM never processes social memory. No orchestrator pattern may bridge social → private. Any "delegate to social-drafts profile" must enforce that the prompt carries no `telegram:<profile-id>`-sourced memory either; the social handler already gates this.
- **Invariant #3** — Agents cannot reach other agents. Any handoff travels through the relay/operator, never agent-to-agent. Option C explicitly preserves this by routing results back to the operator's chat, not to the originating agent's session.
- **Invariant #6** — PreToolUse hooks run unconditionally. Any `delegate_to_profile` tool (Option C) must be gated by a PreToolUse hook, not only by `canUseTool`. Otherwise `acceptEdits` mode bypasses enforcement.
- **Invariant #8** — Memory source boundaries are enforced at runtime. Profile-scoped memory (`b74057f`) must remain exact-source-scoped. No option proposed here loosens this. Cross-profile context, if it travels at all, travels through curator items or one-shot delegation prompts — never through memory.
- **Invariant #9** — SOCIAL skill invocations require an explicit allowlist. Mirror this for cross-profile delegations: the originating profile must declare `canDelegate: true` and the target profile must declare `acceptsDelegationFrom: [...]` (Option C). Fail-closed.
- **Invariant #10** — Approval tokens are one-time use, params-bound, signed. If Option C ever adds a "delegate with FULL_ACCESS effect" path, it must adopt the approval-token shape, not invent a new one.

## Operator-facing UX

### With Option A (recommended)

Operator binds chat to `router` profile. Sends a request. Router replies in two parts:

1. One-paragraph distillation of what the operator wants.
2. A `/profile switch <id>` recommendation plus the suggested first message to send after switching.

Operator either accepts (`/profile switch engineer`, then pastes the first message) or asks the router to scope it further. Router can also call `/codex` for bounded research/build work directly (existing behavior, no change). Bypass works as today (`/profile switch <any>` at any time).

What it feels like: an honest dispatcher. No magic, no surprise delegations, no "wait, which profile just wrote to my memory?"

### With Option B (next wave)

Same as A, plus: the router writes signed curator items for handoffs. The curator inbox card shows a "Hand off to engineer" button that, on tap, switches the chat and primes the first message. Operator still drives, but the cost of acceptance is one tap instead of a copy-paste.

### With Option C (deferred)

Router can fire a delegation tool. Operator gets a background card per delegated work unit. Operator can continue chatting with router while engineer is thinking. Hermes-Level-3 feel, but at the cost of a new subsystem.

## Test plan if shipping Option A

1. **Convention doc lints.** `docs/profiles.md` references real profile fields (`id`, `label`, `allowedSkills`, `defaultModel`, `soulPath`). Add a markdown lint check or a doctest.
2. **Reference template loads.** A test under `tests/soul.test.ts` (already exists) verifies that `assets/profile-templates/router/SOUL.md` is non-empty and parses under the existing `loadProfileSoul` path.
3. **Operator dry-run.** Configure a real `router` profile pointing to the reference SOUL. Send 3 sample messages ("ship the X feature", "deploy Y", "draft a tweet about Z") and verify each reply ends with a `/profile switch ...` recommendation or an inline `/codex` call.
4. **Negative test.** Verify the router profile does not write into another profile's memory: send a message designed to provoke "remember this in the engineer profile" and confirm the memory writes (if any) land under `telegram:router`, not `telegram:engineer`. Existing assertion in `src/memory/telegram-memory.ts` covers this; add an explicit test fixture.

If we later ship Option B, add:

5. **Handoff item signing.** Producer-signed envelope round-trip for `handoff_recommendation` items.
6. **Renderer wiring.** Curator inbox shows the deeplink button only when the target profile id is configured and resolvable.

## Decisions to confirm

1. **Adopt "router profile" as a project convention or leave it informal?** Recommendation: adopt, add to `docs/profiles.md`, ship the reference template.
2. **Where does the router profile's SOUL live?** Recommendation: `assets/profile-templates/router/SOUL.md` as the canonical reference; operator copies into their `profiles[]` entry.
3. **Should `/codex` be restricted to opted-in profiles?** Today every WRITE_LOCAL+ chat with FULL_ACCESS can call `--write`. The router-profile convention does not require this restriction. Recommendation: defer to Option B; do nothing now.
4. **Curator `handoff_recommendation` kind — accept the type expansion now or wait?** Recommendation: wait. Adding it costs more than the convention alone and is wasted if the convention works.

## Open questions

1. **Where do non-private personas fit in?** Social agents are explicitly air-gapped. The router profile lives entirely on the private side. If we ever want the operator to ask "post about X on social", the router profile recommends `/social ...` commands rather than delegating into the social agent. This is already the right shape; the convention should state it explicitly.
2. **Does `/codex` count as a specialist?** Codex is a peer, not a profile. The router can call it for bounded code work without invoking the profile machinery. Document this as a separate dispatch lane.
3. **What about future "child claude" sub-agents (Task tool style)?** Out of scope. Telclaude does not run nested agent contexts today and adopting them would be a different subsystem than profiles. Track separately if it ever comes up.

## Appendix — primitives surveyed

| Primitive | Commit | Role |
|---|---|---|
| Operator profiles | `66b3c3b`, `a8055a9` | Per-chat SOUL overlay + `allowedSkills` + `defaultModel`. |
| Profile-scoped memory | `b74057f` | Memory `source: "telegram:<profile-id>"`; runtime-asserted. |
| `/codex` command | `110d0ba` | Background work unit; read-only by default; `--write` needs FULL_ACCESS. |
| Curator inbox + signing | `e0dea00`, `4204968`, `4e11b36` | Operator-facing review queue; producer-signed envelopes. |
| Cron with allowedSkills | `e0dea00` | Per-job skill allowlist; per-chat profile resolution at dispatch (`083e250`). |
| Audit gaps closed | `083e250` | `/curator` Telegram, profile-scoped memory CLI, signed-producer submission. |

End of plan.
