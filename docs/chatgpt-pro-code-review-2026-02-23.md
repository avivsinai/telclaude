# ChatGPT Pro Code Review — Telclaude
**Date**: 2026-02-23
**Model**: ChatGPT 5.2 Pro (Extended Pro, ~18m 43s thinking)
**Input**: Full project bundle (189 files, ~49K lines TypeScript + docs)

---

## Executive Summary

Telclaude is architecturally strong. The relay/agent split, credential proxy pattern, Ed25519 RPC auth, memory provenance boundaries, and Docker firewall enforcement show deliberate security engineering.

However, there are **four critical structural risks** and several medium-severity hardening opportunities:

## 🔴 Critical Findings

1. **WRITE_LOCAL is not a security boundary** (documented, but still dangerous in practice).
2. **Approval model shows intent, not executed commands** (confused deputy risk).
3. **Linux native sandbox TOCTOU gap** for newly created sensitive files.
4. **FULL_ACCESS exposes API keys directly to model process** (native mode).

## 🟡 High-Value Improvements

- Make approvals show planned tool invocations (not just user text).
- Add structured "execution plan preview" before FULL_ACCESS approval.
- Enforce HTTP method restrictions at runtime (not just domain allowlist).
- Improve session-token concurrency handling.
- Harden Docker firewall verification further.
- Add secret redaction fuzzing tests.

---

## 1. Architecture Review

### 1.1 System Topology

```
Telegram
  ↓
Relay (security + secrets + rate limits + observer + approvals)
  ↓ internal HTTP
Agent(s) (SDK + tools, no raw secrets)
  ↓
Claude Agent SDK
```

Sidecars:
- Vault daemon (credential storage)
- TOTP daemon
- Git proxy
- HTTP credential proxy

### 1.2 Architectural Strengths

**✅ Strong Trust Boundaries**
- Relay holds all secrets. Agents never do.
- Credential injection happens in the relay proxy.
- Agents call `http://relay:8792/...`.
- Vault stores encrypted credentials (AES-256-GCM).
- This prevents classic "prompt injection → print env vars" exfiltration.

**✅ Isolation Boundary Clarity**
- Single isolation boundary per mode:
  - Native → SDK sandbox (bubblewrap / Seatbelt)
  - Docker → container + iptables firewall
- Avoiding double sandboxing is correct.

**✅ Bidirectional RPC Auth (Ed25519)**
- Agent signs → relay verifies.
- Relay signs → agent verifies.
- Superior to shared HMAC keys and prevents impersonation if one side is compromised.

**✅ Memory Provenance Model**
- Memory separated by `source: "telegram"` / `source: "social"`
- Runtime enforcement ensures Telegram agent never processes social memory.
- Eliminates the confused deputy risk between public content and private privileged context.
- *Extremely well designed.*

**✅ Credential Proxy Pattern**
- Instead of `OPENAI_API_KEY in env → accessible to model`
- Uses: `Agent → relay proxy → vault → upstream`
- *Textbook secure capability proxy pattern.*

---

## 2. Security Audit

### 🔴 CRITICAL ISSUE 1: WRITE_LOCAL Is Not a Security Boundary

Blocked commands: `rm, chown, chmod, sudo`

But bypasses include:
```bash
python -c "import os; os.remove('file')"
node -e "require('fs').unlinkSync('file')"
```

**Impact**: If attacker reaches WRITE_LOCAL via prompt injection, they can destroy workspace files, exfiltrate via encoded channels, or create reverse shells in permissive network mode.

**Recommendation**: Treat WRITE_LOCAL as convenience tier only. Never assign to untrusted users. Prefer Docker mode for any WRITE_LOCAL deployment.

### 🔴 CRITICAL ISSUE 2: Approval Model Shows User Intent, Not Executed Commands

Approval shows the user's original request, not the actual commands Claude will execute.

**Confused Deputy Risk**: User sees "Delete temp files", Claude executes `rm -rf ~`

**Recommendation (High Priority Fix)**: Before FULL_ACCESS execution, have agent produce a structured execution plan showing planned tool calls. Approve specific tool calls, not just text. *This is the most important design improvement needed.*

### 🔴 CRITICAL ISSUE 3: Native Sandbox TOCTOU File Exposure

Sensitive file patterns expanded at startup. If new secret file created after relay starts (`project/new-secret/.env`), it may be readable.

**Recommendation**: Re-scan sensitive paths dynamically before tool execution. Or enforce Docker-only for production. Or use deny-by-pattern on every file access (hook-level check).

### 🔴 CRITICAL ISSUE 4: FULL_ACCESS Exposes Raw API Keys in Native Mode

In native mode, FULL_ACCESS tier gets configured API keys exposed to sandbox. Model can print keys, encode and exfiltrate via WebFetch. Secret filter can be bypassed via obfuscation.

**Recommendation**: Even in native mode, prefer vault + proxy model for all tiers. Avoid direct env var exposure entirely.

### 🟡 HIGH RISK: HTTP Method Restrictions Not Enforced

Domain allowlists are enforced, but HTTP method restrictions are not. Agent can POST sensitive data to allowed domains.

**Fix**: Enforce GET-only domains unless explicitly allowed, or enforce path-level restrictions.

### 🟡 HIGH RISK: Secret Redaction Is Regex-Based

Bypasses: obfuscation, Base64 encoding, JSON fragmentation.

**Improvement**: Add partial-token sliding window entropy scan, common base64 secret detection, key pattern normalization.

### 🟡 HIGH RISK: DNS Rebinding (Permissive Mode)

**Recommendation**: Default to strict always. Emit loud warning if permissive mode enabled.

---

## 3. Threat Model

| Attacker Persona | Mitigations | Gap |
|---|---|---|
| Malicious Telegram User | Tiers, Observer, Approvals, Rate limits | Approval UX vulnerability |
| Compromised Agent Container | No secrets in agent, Firewall egress, Vault isolation | Strong design |
| Compromised Relay | All secrets accessible (acceptable — relay is intended TCB) | — |
| Vault Compromise | AES-256-GCM, encryption key env var | Keep vault on isolated network |
| Docker Breakout | cap_drop ALL, read-only root, tmpfs, AppArmor | Docker daemon/kernel vulnerabilities |

---

## 4. Deployment Hardening

### Recommended Production Profile

Always use Docker mode. Native mode only for development.

```
security.profile = strict
defaultTier = READ_ONLY
observer.enabled = true
fallbackOnTimeout = block
TELCLAUDE_FIREWALL = 1
TELCLAUDE_IPV6_FAIL_CLOSED = 1
```

Additional: run on dedicated host, disable Docker socket mounting, use restricted API keys, enable centralized log monitoring.

---

## 5. Code Quality Review

### Strengths
- Strong typing with TypeScript
- Clear module boundaries
- Excellent CLI ergonomics
- Good error handling
- Thoughtful documentation

### Minor Improvements
1. **Session Token Concurrency Guard**: `process.env` mutation is global state. Race conditions possible in async errors. Better to pass token via child process env only.
2. **Repeated JSON Parsing Blocks**: Minor refactor opportunity.
3. **Test Coverage Gaps**: Add obfuscated secret redaction tests, approval bypass simulations, DNS rebinding test harness, WRITE_LOCAL bypass tests.

---

## 6. Bug & Edge Case Analysis

- **Git Credential Helper Logging**: Correctly redacted. ✅
- **DNS Cache in Network Test**: `clearDNSCache` called before testing. ✅
- **Skill Promotion Path Traversal**: Strict regex `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$` prevents traversal. ✅
- **Media Path Extraction in Integration Tests**: Low severity regex risk.

---

## 7. Overall Security Posture Rating

| Category | Rating |
|---|---|
| Architecture | ⭐⭐⭐⭐⭐ |
| Isolation | ⭐⭐⭐⭐⭐ |
| Secret Management | ⭐⭐⭐⭐⭐ |
| Approval UX | ⭐⭐ |
| Prompt Injection Resilience | ⭐⭐⭐⭐ |
| Docker Hardening | ⭐⭐⭐⭐⭐ |
| Default Safety | ⭐⭐⭐⭐ |

---

## 8. Priority Fix List

### 🔥 Immediate
- Implement "execution plan preview" for FULL_ACCESS
- Remove raw API key exposure in native mode
- Dynamically enforce sensitive path blocking (not just startup expansion)

### ⚠️ Next
- Enforce HTTP method restrictions
- Improve secret redaction robustness
- Move session token to request-scoped env only

### 🛠 Nice-to-Have
- Add automated security regression tests
- Add approval diff preview (before/after file changes)
- Add rate-limit anomaly detection alerts

---

## Final Assessment

> Telclaude is one of the more carefully architected Telegram-to-LLM bridges I've reviewed. The relay/agent split + vault proxy + Ed25519 RPC design is genuinely strong. The main remaining risk is **human approval UX**, not infrastructure isolation.
>
> If you fix the approval preview problem and eliminate raw key exposure in native mode, this becomes **production-grade secure by design**.
