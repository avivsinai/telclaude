# Telclaude <-> OpenClaw Bidirectional Adoption Plan (Features + Security)

**Date:** 2026-02-21  
**Authoring stance:** telclaude owner/operator decision memo  
**Scope:** what telclaude should adopt from OpenClaw, and what OpenClaw should adopt from telclaude

---

## Executive Decision

1. Keep telclaude's trust-boundary architecture as-is (relay/vault/agent split); do not import OpenClaw's in-process credential model.
2. Aggressively import OpenClaw's product and operator UX strengths (onboarding, channel/account operations, scheduling, status).
3. Export telclaude's strongest security primitives back to OpenClaw (output exfiltration blocking, vault proxy isolation, persona/memory trust boundaries).

---

## Review Method

- Compared both repositories at module level:
  - `telclaude`: ~170 TS source files, 50 tests, 39 commands, 14 Telegram modules.
  - `openclaw`: ~3456 TS source files, ~1336 tests, 227 commands, 85 Telegram modules.
- Focused on:
  - security primitives and trust boundaries,
  - channel and messaging features,
  - onboarding/operator workflows,
  - runtime resilience and scheduling.

---

## Findings (Ordered by Severity)

### Critical

1. **Never collapse telclaude into OpenClaw's in-process credential model.**
   - OpenClaw stores and uses provider credentials in agent/gateway process flows (`/Users/avivsinai/workspace/openclaw/src/agents/auth-profiles/store.ts`, `/Users/avivsinai/workspace/openclaw/src/agents/model-fallback.ts`).
   - Telclaude keeps credentials in a separate vault sidecar + relay proxy (`src/vault-daemon/server.ts`, `src/relay/http-credential-proxy.ts`).
   - Importing OpenClaw's model into telclaude would be a security regression.

2. **OpenClaw still lacks a mandatory outbound exfiltration blocker equivalent to telclaude's pipeline.**
   - OpenClaw primarily redacts logs (`/Users/avivsinai/workspace/openclaw/src/logging/redact.ts`) and provides optional hook points (`/Users/avivsinai/workspace/openclaw/src/plugins/hooks.ts`).
   - Telclaude enforces outbound blocking + redaction (`src/security/output-filter.ts`, `src/security/streaming-redactor.ts`, `src/telegram/outbound.ts`).

### High

3. **Telclaude has clear feature depth gaps in onboarding and day-2 operations.**
   - OpenClaw has interactive + non-interactive onboarding and channel setup (`/Users/avivsinai/workspace/openclaw/src/commands/onboard.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/onboard-interactive.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/onboard-non-interactive.ts`).
   - Telclaude currently has `quickstart` + narrower status UX (`src/commands/quickstart.ts`, `src/commands/status.ts`).

4. **OpenClaw has stronger multi-channel/account governance primitives.**
   - Channel plugin model, account-level status, allow-from/pairing flows (`/Users/avivsinai/workspace/openclaw/src/channels/plugins/index.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/channels/status.ts`, `/Users/avivsinai/workspace/openclaw/src/cli/pairing-cli.ts`, `/Users/avivsinai/workspace/openclaw/src/pairing/pairing-store.ts`).
   - Telclaude is Telegram-centric; strong security but lower channel scalability.

5. **Telclaude has stronger identity and 2FA controls that OpenClaw should copy.**
   - Admin claim + identity link + TOTP gate (`src/security/admin-claim.ts`, `src/security/linking.ts`, `src/security/totp-auth-gate.ts`).
   - No equivalent TOTP layer was found in OpenClaw source.

### Medium

6. **OpenClaw runtime resilience (provider/model rotation) is ahead.**
   - Fallback and cooldown logic (`/Users/avivsinai/workspace/openclaw/src/agents/model-fallback.ts`, `/Users/avivsinai/workspace/openclaw/src/agents/auth-profiles/usage.ts`).
   - Telclaude has provider health checks, but less dynamic model/profile failover (`src/providers/provider-health.ts`).

7. **Both sides have already converged on some prior security backports; avoid duplicate work.**
   - Telclaude already includes guarded fetch, audit collectors/fixers, input normalization, output guard (`src/sandbox/fetch-guard.ts`, `src/commands/audit-collectors.ts`, `src/commands/audit-fixers.ts`, `src/sdk/output-guard.ts`).

---

## What Telclaude Should Take From OpenClaw

## P0 (Next 1-2 cycles)

1. **Onboarding framework (interactive + non-interactive)**
   - Source: `/Users/avivsinai/workspace/openclaw/src/commands/onboard.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/onboard-interactive.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/onboard-non-interactive.ts`.
   - Why: reduces setup mistakes, speeds up operator activation.
   - Telclaude target: extend `src/commands/quickstart.ts` into full `onboard` command.

2. **Operational status surfaces (status + sessions)**
   - Source: `/Users/avivsinai/workspace/openclaw/src/commands/status.command.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/sessions.ts`.
   - Why: better day-2 observability than current `status`.
   - Telclaude target: expand `src/commands/status.ts` with deep mode and session/token/agent insights.

3. **Pairing-style DM bootstrap and approval workflow**
   - Source: `/Users/avivsinai/workspace/openclaw/src/cli/pairing-cli.ts`, `/Users/avivsinai/workspace/openclaw/src/pairing/pairing-store.ts`, `/Users/avivsinai/workspace/openclaw/src/pairing/pairing-messages.ts`.
   - Why: safer controlled first-contact than static allowlists alone in broader deployments.
   - Constraint: must integrate with telclaude admin claim + TOTP, not replace them.

4. **Cron scheduler CLI**
   - Source: `/Users/avivsinai/workspace/openclaw/src/cli/cron-cli/register.ts`, `/Users/avivsinai/workspace/openclaw/src/cli/cron-cli/register.cron-add.ts`.
   - Why: product-level automation capability beyond heartbeat intervals.
   - Telclaude target: introduce `telclaude cron` with strict permission tier defaults.

## P1 (After P0)

5. **Model/provider auth profile rotation**
   - Source: `/Users/avivsinai/workspace/openclaw/src/agents/model-fallback.ts`, `/Users/avivsinai/workspace/openclaw/src/agents/auth-profiles/store.ts`, `/Users/avivsinai/workspace/openclaw/src/agents/auth-profiles/usage.ts`.
   - Why: resilience under provider outages/rate limits.
   - Telclaude target: provider layer and SDK execution path.

6. **Reusable channel gating primitives**
   - Source: `/Users/avivsinai/workspace/openclaw/src/channels/mention-gating.ts`, `/Users/avivsinai/workspace/openclaw/src/channels/command-gating.ts`, `/Users/avivsinai/workspace/openclaw/src/channels/allow-from.ts`.
   - Why: cleaner group/command policy logic than ad-hoc checks.
   - Telclaude target: `src/telegram/inbound.ts` and command routing in `src/telegram/auto-reply.ts`.

7. **Draft stream improvements for long responses**
   - Source: `/Users/avivsinai/workspace/openclaw/src/telegram/draft-stream.ts`.
   - Why: better stream UX control (initial debounce, force new message, flush behavior).
   - Telclaude target: `src/telegram/streaming.ts`.

## P2 (Strategic, longer horizon)

8. **Pluginized channel architecture**
   - Source: `/Users/avivsinai/workspace/openclaw/src/channels/plugins/*`.
   - Why: unlocks true multi-channel expansion.
   - Risk: high migration complexity; keep telclaude security invariants central.

9. **Memory backend fallback strategy (optional)**
   - Source: `/Users/avivsinai/workspace/openclaw/src/memory/search-manager.ts`.
   - Why: graceful degradation if advanced memory backend fails.

---

## What OpenClaw Should Take From Telclaude

## P0

1. **Vault-sidecar credential isolation + relay proxy pattern**
   - Source: `src/vault-daemon/server.ts`, `src/relay/http-credential-proxy.ts`.
   - Why: removes raw credentials from agent execution context.

2. **Mandatory outbound secret blocking and stream-aware redaction**
   - Source: `src/security/output-filter.ts`, `src/security/streaming-redactor.ts`, `src/telegram/outbound.ts`.
   - Why: logging redaction is not enough; must block exfiltration on send path.

3. **Private/public persona trust boundary with runtime memory assertions**
   - Source: `src/social/handler.ts` (source-bound filtering + runtime assertions), `docs/architecture.md`.
   - Why: prevents confused-deputy prompt injection between trust domains.

4. **Identity-link + 2FA gate in inbound message pipeline**
   - Source: `src/security/linking.ts`, `src/security/totp-auth-gate.ts`, `src/security/admin-claim.ts`.
   - Why: strong operator identity and session authentication model for chat control planes.

5. **Quarantined skill promotion with immutable core skills**
   - Source: `src/commands/skills-promote.ts`, `src/commands/skills-import.ts`.
   - Why: reduces malicious or accidental skill-supply-chain exposure.

## P1

6. **User-tier permission model tied to identity**
   - Source: `src/security/permissions.ts`, plus approval/rate-limit layers.
   - Why: policy by user trust level, not only global/runtime defaults.

7. **Two-layer private provider isolation pattern**
   - Source: `src/providers/provider-validation.ts`, `docs/architecture.md` (hook + firewall model).
   - Why: better containment for internal/private endpoints.

---

## Do Not Port (Important)

1. **Do not port OpenClaw's in-process auth profile model into telclaude.**
2. **Do not port telclaude's single-channel assumptions into OpenClaw.**
3. **Do not duplicate already-backported security work in telclaude unless tests show a regression.**

---

## Owner-Level Roadmap Recommendation

1. **Ship P0 feature imports from OpenClaw into telclaude first** (onboarding, status/sessions, pairing, cron).  
   Rationale: biggest product delta with contained security risk.
2. **Concurrently define a security export package for OpenClaw** (vault proxy + output blocking + 2FA pattern).  
   Rationale: highest ecosystem impact and aligns with telclaude's core differentiation.
3. **Defer major architectural convergence (pluginized channels) until P0/P1 are stable**.  
   Rationale: avoid destabilizing telclaude's current trust-boundary guarantees.

---

## Existing Backports Already Landed In Telclaude

- DNS-pinned guarded fetch and redirect revalidation: `src/sandbox/fetch-guard.ts`.
- Security audit collectors and fixers: `src/commands/audit-collectors.ts`, `src/commands/audit-fixers.ts`.
- Inbound normalization (raw + normalized split): `src/telegram/inbound.ts`.
- Stream output guard for oversized tool results: `src/sdk/output-guard.ts`.
- OpenClaw skill import/promotion pipelines: `src/commands/skills-import.ts`, `src/commands/skills-promote.ts`.

