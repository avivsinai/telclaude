# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in telclaude, please report it responsibly:

1. **Preferred**: Use [GitHub's private vulnerability reporting](https://github.com/avivsinai/telclaude/security/advisories/new)
2. **Alternative**: Contact project maintainer(s) directly via GitHub

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution**: Depends on severity and complexity

---

## Security Model

Telclaude is designed with defense-in-depth security for running Claude AI with access to your development environment via Telegram.

### Threat Model

We protect against:

1. **Prompt Injection** — Malicious prompts attempting to bypass security
2. **Privilege Escalation** — Users attempting to exceed their permission tier
3. **Credential Theft** — Attempts to access secrets (SSH keys, API tokens, etc.)
4. **Denial of Service** — Rate limit abuse
5. **Unauthorized Access** — Unlinked users or blocked chats

### Security Layers

| Layer | Component | Protection |
|-------|-----------|------------|
| **1. Screening** | Fast Path + Observer | Blocks dangerous prompts before execution |
| **2. Policy** | Rate Limiter + Approvals | Prevents abuse, human-in-loop for risky ops |
| **3. Permissions** | Tier System | Controls which tools Claude can use |
| **4. Enforcement** | OS Sandbox | Kernel-level isolation of file/network access |

---

## Permission Tiers

### READ_ONLY (Default)

Lowest privilege tier. Claude can:
- Read files
- Search codebase (Glob, Grep)
- Fetch web content

Cannot:
- Write or modify files
- Execute shell commands
- Access restricted paths

### WRITE_LOCAL

Medium privilege tier. Additionally can:
- Write and edit files
- Execute restricted Bash commands

Blocked Bash commands: `rm`, `rmdir`, `mv`, `chmod`, `chown`, `kill`, `pkill`, `sudo`, `su`

**Security Note**: WRITE_LOCAL prevents *accidental* damage, not *malicious* attacks. Determined attackers could write scripts that perform blocked operations. For true isolation, run in a container.

### FULL_ACCESS

Maximum privilege tier. No tool restrictions.

**Every request requires human approval.** This is intentional — FULL_ACCESS grants unrestricted capabilities, so each action must be explicitly approved.

---

## OS-Level Sandbox

All Claude queries execute inside an OS-level sandbox:

- **macOS**: Seatbelt (`sandbox-exec`) — kernel-level enforcement
- **Linux**: bubblewrap — namespace-based isolation

### Blocked Paths

The sandbox prevents access to:

- `~/.telclaude/` — Configuration and secrets
- `~/.ssh/` — SSH keys
- `~/.gnupg/` — GPG keys
- `~/.aws/` — AWS credentials
- `~/.config/` — Application secrets
- `/etc/passwd`, `/etc/shadow` — System files

### Write Restrictions

- **READ_ONLY**: No writes allowed
- **WRITE_LOCAL/FULL_ACCESS**: Writes limited to current working directory + private temp (`~/.telclaude/sandbox-tmp`). Host `/tmp`/`/var/tmp` are deny-read.

---

## TOTP 2FA

Two-factor authentication secrets are stored in a separate process:

- **Process Isolation**: TOTP daemon runs independently from the main relay
- **OS Keychain**: Secrets stored via `keytar` (macOS Keychain, Linux secret-service)
- **Unix Socket IPC**: Communication via `~/.telclaude/totp.sock` (permissions 0600)

This architecture ensures that even if Claude is compromised via prompt injection, it cannot:
1. Read TOTP secrets (separate process)
2. Bypass 2FA (requires daemon verification)
3. Access OS keychain (sandbox blocks it)

---

## Rate Limiting

Rate limits protect against abuse:

- **Global limits**: Per minute and per hour
- **Per-user limits**: Individual user caps
- **Per-tier limits**: Stricter limits for higher privileges

Rate limiting **fails closed**: If the rate limiting system errors, requests are blocked (not allowed).

---

## Audit Logging

All interactions are logged for security review:

- Timestamp
- User identity
- Message content
- Security classification
- Tool invocations
- Response summary

Audit logs should be protected and regularly reviewed.

---

## Secure Deployment Checklist

When deploying telclaude:

- [ ] **Set `TELCLAUDE_ADMIN_SECRET`** — Prevents scanner bots from claiming admin first
- [ ] Use a dedicated bot token (not shared with other services)
- [ ] Configure `allowedChats` to restrict which chats can interact
- [ ] Set `defaultTier` to `READ_ONLY`
- [ ] Assign higher tiers only to trusted, linked identities
- [ ] Enable the security observer (`security.observer.enabled: true`)
- [ ] Set `fallbackOnTimeout: "block"` for observer failures
- [ ] Run the TOTP daemon for 2FA on sensitive operations
- [ ] Review audit logs regularly
- [ ] Keep dependencies updated

### Admin Claim Security

By default, the first person to DM the bot can claim admin. **This is a bootstrap race condition.**

To prevent scanner bots from claiming admin:
```bash
export TELCLAUDE_ADMIN_SECRET="your-secure-random-secret"
```

Then claim admin with: `/claim your-secure-random-secret`

### Additional Hardening

For high-security environments:

- Run in a container with limited capabilities
- Use network policies to restrict outbound access
- Implement additional monitoring/alerting
- Consider running on isolated infrastructure

---

## ⚠️ Important Security Caveats

Before deploying, understand these fundamental limitations:

### 1. WRITE_LOCAL Is NOT a Security Boundary

**WRITE_LOCAL provides accident prevention, NOT security isolation.**

The tier blocks common destructive commands (`rm`, `chmod`, `sudo`) but can be trivially bypassed:
```bash
# All of these bypass WRITE_LOCAL command blocking:
python3 -c "import os; os.remove('file')"
node -e "require('fs').unlinkSync('file')"
echo "rm -rf /" > script.sh && bash script.sh
```

**For actual security isolation against malicious inputs:**
- Run in a container with dropped capabilities
- Mount the workspace read-only where possible
- Use the OS sandbox's strict network policies

### 2. Linux Sandbox Has Static Filesystem View

On Linux (bubblewrap), sensitive file patterns (`**/.env`, `secrets.*`) are expanded to literal paths **at startup**.

**TOCTOU Issue**: Files created AFTER the relay starts are NOT protected:
```bash
# At startup: ~/.env blocked, myproject/.env blocked (existed at init)
# After startup: myproject/new-secret/.env is readable (created after init)
```

**Mitigation**: Restart the relay after creating new sensitive files, or run in Docker where bind mounts provide additional isolation.

### 3. DNS Rebinding Risk (Open Network Mode)

When `TELCLAUDE_NETWORK_MODE=open` or `permissive`, the DNS resolution check can be bypassed via DNS rebinding:
1. First lookup returns a public IP (allowed)
2. Second lookup (by the actual tool) returns `127.0.0.1` or metadata endpoint

**Mitigation**: Keep the default strict network allowlist. Only use `open`/`permissive` mode on isolated networks.

### 4. Output Filter Bypass

The secret output filter uses regex patterns. Obfuscation can bypass detection:
```
# Detected: sk-ant-abc123
# Not detected: s k - a n t - a b c 1 2 3
```

**Mitigation**: This is inherent to LLM monitoring. Document that FULL_ACCESS = potential data exfiltration regardless of filters.

---

## Known Limitations

### WRITE_LOCAL Escape

The WRITE_LOCAL tier blocks specific Bash commands but cannot prevent:
- Writing scripts that perform blocked operations
- Using alternative tools (e.g., `perl -e 'unlink("file")'`)
- Modifying interpreter scripts

**Mitigation**: For true isolation, use containerization or the OS sandbox's more restrictive modes.

### Prompt Injection

While the security observer analyzes messages, sophisticated prompt injection attacks may evade detection.

**Mitigation**:
- OS sandbox provides defense-in-depth
- FULL_ACCESS tier requires human approval
- Rate limiting prevents rapid exploitation attempts

### Network Access

By default, Claude has network access for web fetching. Malicious prompts could potentially:
- Exfiltrate data to external servers
- Access internal network services

**Mitigation**:
- Configure network allowlists in sandbox configuration
- Monitor audit logs for suspicious network activity

### Approval Shows Request, Not Commands

Approval messages show the user's original request, not the actual commands Claude will execute. This is because approvals happen before Claude processes the request.

**Risk**: User approves "Delete temp files" but Claude executes `rm -rf ~`.

**Mitigation**:
- Use READ_ONLY for untrusted users (no approvals needed, just read access)
- Only grant FULL_ACCESS to users who understand they're approving intent, not specific commands
- Review audit logs to see what commands were actually executed

---

## Security Updates

Security updates will be released as needed. Watch the repository for:
- Security advisories
- Patch releases
- Breaking changes that affect security

---

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors to security improvements will be acknowledged (with permission) in release notes.
