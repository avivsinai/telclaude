# Telclaude Architecture Review: Is the Security Layer Over-Engineered?

**Date**: 2024-12-04
**Context**: Seeking feedback on whether to simplify the security architecture

---

## The Question

> "I think we are over-engineering our solution. Eventually the only real way to protect against Claude is to limit it 'physically' via sandbox and Docker. All these permissions of 'ALL', 'read only' etc. are kinda irritating. We should just run with `--dangerously` BUT make sure we're protected 'from the outside' + authorization."

---

## Current Architecture (7 Layers)

```
┌─────────────────────────────────────────────────────┐
│ 1. Fast-path regex      - Pattern matching          │
│ 2. Observer (Haiku)     - AI pre-analysis           │
│ 3. Permission tiers     - READ_ONLY/WRITE_SAFE/FULL │
│ 4. Approval workflows   - Human-in-the-loop         │
│ 5. Rate limiting        - Abuse prevention          │
│ 6. Identity linking     - Authorization             │
│ 7. OS Sandbox           - Kernel-level enforcement  │
└─────────────────────────────────────────────────────┘
```

---

## The Argument FOR Simplification

### 1. The Code Admits Software Checks Are Bypassable

From `CLAUDE.md`:
> "WRITE_SAFE prevents *accidental* damage, not *malicious* attacks. Users can escape by writing scripts that perform blocked operations."

If the tier system can be bypassed, why maintain it?

### 2. Prompt Injection Defeats Software Checks

If Claude is tricked via prompt injection, it can:
- Write a Python script that calls `os.remove()`
- Use `subprocess` to run blocked commands
- Exploit any indirect path to the blocked operation

The `allowedTools` array is a suggestion, not enforcement.

### 3. The Sandbox IS the Real Boundary

The sandbox (seatbelt/bubblewrap) provides kernel-level enforcement:
- Cannot read `~/.ssh`, `~/.aws`, `~/.telclaude` - physically blocked
- Write paths are restricted at the OS level
- Network filtering happens at the kernel

No amount of prompt injection can bypass kernel-level restrictions.

### 4. Complexity Has Real Costs

| Component | Cost |
|-----------|------|
| Observer | +latency (Claude Haiku call per message) |
| Approval workflow | User friction, pending state management |
| Permission tiers | Config complexity, edge cases |
| Fast-path regex | Maintenance, false positives |
| Multiple tiers | Code paths to test and maintain |

### 5. The System Conflates Policy and Enforcement

- **Policy** = what we want Claude to do (advisory)
- **Enforcement** = what Claude CAN do (mandatory)

The permission tier system tries to be both but succeeds at neither:
- Not reliable enforcement (bypassable)
- Not good policy (creates friction for legitimate use)

---

## Proposed Simplified Architecture

```
Telegram Bot API (grammY)
         │
         ▼
┌─────────────────────────────────────┐
│        Authorization Layer          │
│  - Identity linking (who can use)   │
│  - Rate limiting (abuse prevention) │
│  - Audit logging (accountability)   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│    OS-Level Sandbox (MANDATORY)     │
│  - Filesystem: block sensitive dirs │
│  - Write: only project + /tmp       │
│  - Network: optional filtering      │
│  - THIS IS THE SECURITY BOUNDARY    │
└─────────────────────────────────────┘
         │
         ▼
  Claude Agent SDK
  (bypassPermissions: true)
  (allowDangerouslySkipPermissions: true)
```

### What Gets Removed

| Component | Reason |
|-----------|--------|
| Permission tiers | Bypassable, friction without security |
| Observer | Latency without reliable security |
| Approval workflows | Friction, sandbox provides real enforcement |
| Fast-path regex | Bypassable |
| `allowedTools` restrictions | Bypassable |

### What Remains

| Component | Reason |
|-----------|--------|
| Authorization (identity linking) | Who can use the bot |
| Rate limiting | Resource protection |
| Audit logging | Accountability, debugging |
| OS Sandbox | THE security boundary |
| TOTP (optional) | Additional auth factor |

---

## Counter-Arguments to Consider

### 1. Defense in Depth
"Multiple layers means if sandbox has a bug, other layers catch it."

**Counter**: Sandbox is kernel-level (seatbelt, bubblewrap), extremely well-tested. The software layers we'd be removing are bypassable anyway.

### 2. Accidental Damage
"Without WRITE_SAFE, Claude might `rm -rf` by accident."

**Counter**: Configure sandbox to restrict write paths to just the project directory. This is enforcement, not policy.

### 3. Audit/Visibility
"Observer gives insight into what Claude is being asked."

**Counter**: Audit logging after execution serves the same purpose without the latency or false sense of security.

### 4. User Tiers
"Tiers let you give less trusted users less power."

**Counter**: Maybe simpler to just trust or not trust (binary). If you don't trust them, don't give them access.

---

## Key Files to Review

For context, here are the files that would be affected:

**Would be simplified/removed:**
- `src/security/permissions.ts` - Tier definitions, allowedTools arrays
- `src/security/observer.ts` - Claude Haiku pre-analysis
- `src/security/fast-path.ts` - Regex pattern matching
- `src/security/approvals.ts` - Approval workflow
- `.claude/skills/security-gate/SKILL.md` - Observer skill

**Would remain:**
- `src/security/linking.ts` - Authorization
- `src/security/rate-limit.ts` - Rate limiting
- `src/security/audit.ts` - Logging
- `src/sandbox/manager.ts` - OS sandbox (would become THE security layer)
- `src/totp-daemon/` - Optional 2FA

---

## Questions for Discussion

1. **Is the current complexity justified?** Does having bypassable software checks provide meaningful security, or just a false sense of security?

2. **What's the threat model?** Are we protecting against:
   - Accidental damage by Claude? (Sandbox handles this)
   - Malicious users? (Authorization handles this)
   - Prompt injection? (Only sandbox can handle this)

3. **Is "trust but verify at the boundary" the right model?** Run Claude with full power inside a sandbox, rather than trying to limit its power through software.

4. **What about the TOTP system?** Keep it for additional auth, or also simplify?

5. **Docker vs OS sandbox?** For production, should we mandate Docker instead of relying on seatbelt/bubblewrap?

---

## Summary

The proposal is to shift from **7 security layers** (many bypassable) to **3 layers** (all enforceable):

| Current | Proposed |
|---------|----------|
| Fast-path regex | (removed) |
| Observer (Haiku) | (removed) |
| Permission tiers | (removed) |
| Approval workflows | (removed) |
| Rate limiting | **Rate limiting** |
| Identity linking | **Authorization** |
| OS Sandbox | **OS Sandbox** (THE boundary) |

The philosophy: **Hard boundaries beat soft policies.**

---

# Full Source Code Follows

The complete codebase is included below for context.

---

