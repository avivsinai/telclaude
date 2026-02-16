# Strategic Evaluation: Telclaude vs OpenClaw

**Date**: 2026-02-16
**Research**: 5 agents (3 Claude + Codex + deep-dive), parallel investigation

---

## TL;DR

OpenClaw (147K stars, OpenAI-backed OSS foundation) operates in the same space as telclaude. We evaluated all paths — including ignoring migration cost entirely. **The blocker isn't effort; it's architecture.** OpenClaw is a single-process gateway where agents share the same trust domain as credentials. Telclaude splits relay and agents into separate processes with explicit trust boundaries. Porting our security model to OpenClaw means rewriting its process model — at which point we're rebuilding telclaude inside OpenClaw.

**Recommendation**: Stay on telclaude. Backport OpenClaw's best ideas. Revisit if OpenClaw adopts a multi-process agent mode.

---

## What Happened

On 2026-02-15, OpenAI hired Peter Steinberger (OpenClaw creator, ex-PSPDFKit founder). OpenClaw becomes an independent OSS foundation with OpenAI sponsorship. MIT license. 147K+ GitHub stars, 430K+ lines of code, 12+ messaging channels.

OpenClaw's security track record is poor: 512 vulnerabilities (8 critical), 12% of skills on ClawHub confirmed malicious, ~1,000 exposed instances without authentication. Cisco, Kaspersky, and Palo Alto Networks published critical assessments.

---

## The Architectural Divide

This is the single most important finding. Everything else follows from it.

| | Telclaude | OpenClaw |
|---|---|---|
| **Process model** | Multi-process: relay + agent containers on separate networks | Single-process: gateway + in-process agent sessions |
| **Trust assumption** | Agents are untrusted compute | Agents share gateway trust domain |
| **Credentials** | Vault sidecar; agents never see raw keys | LLM client needs keys in gateway process memory |
| **Persona isolation** | Air-gapped containers, split memory, relay-mediated queries | Shared process, shared memory index |
| **Output filtering** | Streaming redactor on all output, non-overridable CORE patterns | Log redaction only, disableable |

Features that work within a single process (output filtering, tool policy) can be added to OpenClaw — some as plugins without touching core. Features that require process-level isolation (credential vault, persona air gap) require rewriting the gateway into a relay+worker model.

---

## Security Gap Analysis

### MUST-HAVE features (8 evaluated)

| Feature | OpenClaw Status | Retrofittable? |
|---------|----------------|----------------|
| Permission tiers (READ_ONLY → FULL_ACCESS) | Partial — per-agent, not per-user | Yes, medium effort |
| PreToolUse hooks (primary enforcement) | Partial — plugin hooks exist, not tool-universal | Yes, medium effort |
| **Credential vault sidecar** | **Missing** | **Partially** — sandbox tools yes, LLM calls no (in-process) |
| RFC1918/metadata blocking (non-overridable) | Partial — SSRF module exists, is configurable | Yes, pattern exists |
| **Streaming output secret filter** | **Missing** | **Yes** — `message_sending` hook is the right interception point |
| **Non-overridable infrastructure blocks** | **Missing** | Partially — `validateSandboxSecurity` pattern exists |
| **Persona air gap** | **Missing** | **Requires gateway rewrite** — single-process blocker |
| **Memory provenance assertions** | **Missing** | Yes, per-agent memory indexes already exist |

**Summary**: 5 missing, 3 partial. The credential vault and persona air gap are architecturally blocked by the single-process model.

---

## All Options Evaluated

### Option A: Stay on telclaude

Security intact. israel-services works today. No migration risk. Bus-factor risk (single developer). No multi-channel.

### Option B: Migrate to vanilla OpenClaw

Multi-channel gains. Massive security regression — credentials in-process, no output filtering, no persona isolation. Even with unlimited effort, the single-process gateway means credentials always live in the agent's address space.

### Option C: Run both (hybrid)

Double maintenance, identity fragmentation, Pi4 resource constraints. The "non-sensitive boundary" is hard to maintain in practice.

### Option D: Security-hardened OpenClaw fork

Upstream plugin-level features (output filter, tool policy, audit). Fork for architecture-level changes (multi-process gateway, vault). Regular upstream merges. **Risk**: merge-tax on 430K LOC codebase; fork scope creep.

### Option E: Propose relay architecture upstream to OpenClaw

Propose multi-process agent mode to the foundation. If accepted, long-term best outcome. **Risk**: foundation governance undefined, timeline uncertain, Steinberger now at OpenAI (who drives this?).

---

## Decision Matrix

**Cost-agnostic** — migration effort excluded from weights.

| Criterion | Weight | A: Telclaude | B: OpenClaw | D: Fork | E: Upstream |
|-----------|--------|-------------|-------------|---------|-------------|
| Security posture | 30% | 9 | 3 | 8 | 9 |
| Long-term sustainability | 25% | 4 | 8 | 7 | 9 |
| Multi-channel reach | 15% | 2 | 9 | 9 | 9 |
| israel-services compat | 15% | 9 | 5 | 8 | 9 |
| Community/ecosystem | 10% | 1 | 9 | 6 | 9 |
| Architectural coherence | 5% | 9 | 7 | 5 | 9 |
| **Weighted Total** | **100%** | **5.30** | **6.15** | **7.30** | **8.85** |

Option E scores highest but depends on foundation acceptance. Option D is the pragmatic fallback. Option A is the safe choice.

---

## israel-services

*Analysis by Codex. Feasibility: 7.5/10 as sidecar, 4/10 as plugin rewrite.*

israel-services stays as a standalone Docker container regardless of platform choice. The question is the security envelope:

- **Telclaude**: relay-proxied, HMAC auth, two-layer enforcement (hook + iptables), attachment storage. Production-ready today.
- **OpenClaw**: thin plugin adapter (3-5 weeks), app-layer hook blocking only, no kernel firewall backstop, `web_fetch` can't carry custom headers. Needs deployment-level compensating controls.

If OpenClaw gained proper provider enforcement, feasibility rises to ~9/10.

---

## Recommendation

**Stay on telclaude. Backport OpenClaw's best ideas. Monitor the foundation.**

The security architecture is the asset — not the UI, not the channel list. Telclaude's relay+agent split with separate trust domains is a design decision that can't be bolted onto a single-process gateway. OpenClaw would need to adopt a fundamentally different process model to match it.

### Immediate actions

1. **Backport from OpenClaw**:
   - SSRF DNS pinning (check all resolved IPs) — high priority
   - Skill/plugin static scanner — high priority
   - Security audit CLI — medium priority
   - External content wrapping with homoglyph protection — medium priority

2. **Monitor OpenClaw**: if the foundation introduces a multi-process agent mode or credential isolation, revisit this evaluation.

3. **Address bus-factor risk**: document architecture decisions (done — `docs/architecture.md`), maintain comprehensive tests, keep the codebase lean.

### Conditions for revisiting

OpenClaw would need ALL of these:
- [ ] Multi-process agent mode (relay/agent split)
- [ ] Credential isolation (agents never see raw keys)
- [ ] Non-overridable output filtering on all messaging surfaces
- [ ] Demonstrated security improvement (reduction in exposed instances, malicious skills)
- [ ] Clear foundation governance (board, charter, decision process)

---

## Research Team

| Agent | Role | Key Finding |
|-------|------|-------------|
| news-researcher | OpenAI + OpenClaw news | 512 vulns, 12% malicious skills, undefined governance |
| openclaw-researcher | Codebase deep-dive | Strong sandbox/SSRF, weak output filtering, no credential isolation |
| security-auditor | Gap analysis | 5/8 MUST-HAVEs missing, persona air gap impractical |
| codex (amq) | israel-services path | 7.5/10 as sidecar, keep standalone, thin plugin adapter |
| deep-dive agent | Architecture portability | Single-process gateway is root blocker for vault + air gap |
