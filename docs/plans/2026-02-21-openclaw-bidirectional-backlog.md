# OpenClaw <-> Telclaude Backlog

**Date:** 2026-02-21  
**Companion doc:** `docs/plans/2026-02-21-openclaw-bidirectional-feature-security-adoption.md`

---

## Telclaude: Import Backlog (From OpenClaw)

| ID | Priority | Theme | Source Modules | Target Modules | Effort | Risk | Acceptance |
|---|---|---|---|---|---|---|---|
| TC-OC-01 | P0 | Onboarding UX | `/Users/avivsinai/workspace/openclaw/src/commands/onboard.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/onboard-interactive.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/onboard-non-interactive.ts` | `src/commands/quickstart.ts` (+ new `src/commands/onboard.ts`) | M | M | Interactive and non-interactive setup flow with security-safe defaults and `doctor` integration |
| TC-OC-02 | P0 | Status and Sessions | `/Users/avivsinai/workspace/openclaw/src/commands/status.command.ts`, `/Users/avivsinai/workspace/openclaw/src/commands/sessions.ts` | `src/commands/status.ts` | M | L | `status --deep` + session summary output including model/tier/runtime details |
| TC-OC-03 | P0 | DM Pairing | `/Users/avivsinai/workspace/openclaw/src/cli/pairing-cli.ts`, `/Users/avivsinai/workspace/openclaw/src/pairing/pairing-store.ts` | `src/telegram/inbound.ts`, `src/security/admin-claim.ts`, new pairing command/module | M | M | Unknown DMs get controlled pairing path; integrates with admin/TOTP flow |
| TC-OC-04 | P0 | Cron Automation | `/Users/avivsinai/workspace/openclaw/src/cli/cron-cli/register.ts`, `/Users/avivsinai/workspace/openclaw/src/cli/cron-cli/register.cron-add.ts` | new `src/commands/cron.ts`, scheduler integration | M | M | Jobs can be listed/added/disabled; default tier restrictions enforced |
| TC-OC-05 | P1 | Model/Auth Fallback | `/Users/avivsinai/workspace/openclaw/src/agents/model-fallback.ts`, `/Users/avivsinai/workspace/openclaw/src/agents/auth-profiles/usage.ts` | `src/providers/*`, `src/sdk/*` | L | M | Provider/model retries with cooldown and deterministic fallback order |
| TC-OC-06 | P1 | Gating Primitives | `/Users/avivsinai/workspace/openclaw/src/channels/mention-gating.ts`, `/Users/avivsinai/workspace/openclaw/src/channels/command-gating.ts` | `src/telegram/inbound.ts`, `src/telegram/auto-reply.ts` | S | L | Group mention and command gating logic consolidated to reusable helpers |
| TC-OC-07 | P1 | Streaming UX | `/Users/avivsinai/workspace/openclaw/src/telegram/draft-stream.ts` | `src/telegram/streaming.ts` | S | L | Better coalescing and message lifecycle handling for streaming replies |
| TC-OC-08 | P2 | Channel Plugin Architecture | `/Users/avivsinai/workspace/openclaw/src/channels/plugins/*` | future `src/channels/*` layer | XL | H | First non-Telegram channel added without weakening existing security invariants |

---

## OpenClaw: Export Backlog (From Telclaude)

| ID | Priority | Theme | Source Modules | Destination Area | Effort | Risk | Acceptance |
|---|---|---|---|---|---|---|---|
| OC-TC-01 | P0 | Vault Isolation | `src/vault-daemon/server.ts`, `src/relay/http-credential-proxy.ts` | OpenClaw gateway/auth architecture | L | H | Agents can call authenticated services without receiving raw credentials |
| OC-TC-02 | P0 | Secret Exfiltration Blocking | `src/security/output-filter.ts`, `src/security/streaming-redactor.ts` | OpenClaw outbound channel pipeline | M | M | Outbound messages are blocked/redacted for core secret patterns before send |
| OC-TC-03 | P0 | Identity + 2FA Gate | `src/security/linking.ts`, `src/security/totp-auth-gate.ts`, `src/security/admin-claim.ts` | OpenClaw chat auth layer | M | M | Optional but enforceable per-chat identity binding and TOTP verification |
| OC-TC-04 | P0 | Persona Memory Boundary | `src/social/handler.ts`, `docs/architecture.md` | OpenClaw agent routing/memory | M | M | Runtime-enforced source boundary between trust domains |
| OC-TC-05 | P0 | Skill Quarantine | `src/commands/skills-import.ts`, `src/commands/skills-promote.ts` | OpenClaw skills lifecycle | S | L | Draft -> scan -> promote flow with immutable core skill list |
| OC-TC-06 | P1 | Tiered User Permissions | `src/security/permissions.ts` | OpenClaw per-user policy | M | M | Per-user tier policies impact tool availability consistently |
| OC-TC-07 | P1 | Provider Isolation Pattern | `src/providers/provider-validation.ts`, `docs/architecture.md` | OpenClaw private provider integration | M | M | Private provider access requires explicit allowlisting and enforcement layers |

---

## Milestone Plan

1. M1 (2-3 weeks): `TC-OC-01`, `TC-OC-02`, `TC-OC-06`.
2. M2 (2-3 weeks): `TC-OC-03`, `TC-OC-04`, `TC-OC-07`.
3. M3 (3-5 weeks): `TC-OC-05`.
4. Strategic track: `TC-OC-08` only after M1-M3 stabilize.

Parallel ecosystem track:

1. E1 (design + RFC): `OC-TC-01`, `OC-TC-02`.
2. E2 (implementation): `OC-TC-03`, `OC-TC-05`.
3. E3 (advanced boundaries): `OC-TC-04`, `OC-TC-06`, `OC-TC-07`.

