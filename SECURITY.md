# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in telclaude, please report it responsibly:

1. **Email**: Send details to the maintainer (check the repository for contact info)
2. **Private Disclosure**: Use [GitHub's private vulnerability reporting](https://github.com/avivsinai/telclaude/security/advisories/new) if available

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

### WRITE_SAFE

Medium privilege tier. Additionally can:
- Write and edit files
- Execute restricted Bash commands

Blocked Bash commands: `rm`, `rmdir`, `mv`, `chmod`, `chown`, `kill`, `pkill`, `sudo`, `su`

**Security Note**: WRITE_SAFE prevents *accidental* damage, not *malicious* attacks. Determined attackers could write scripts that perform blocked operations. For true isolation, run in a container.

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
- **WRITE_SAFE/FULL_ACCESS**: Writes limited to current working directory + `/tmp`

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

- [ ] Use a dedicated bot token (not shared with other services)
- [ ] Configure `allowedChats` to restrict which chats can interact
- [ ] Set `defaultTier` to `READ_ONLY`
- [ ] Assign higher tiers only to trusted, linked identities
- [ ] Enable the security observer (`security.observer.enabled: true`)
- [ ] Set `fallbackOnTimeout: "block"` for observer failures
- [ ] Run the TOTP daemon for 2FA on sensitive operations
- [ ] Review audit logs regularly
- [ ] Keep dependencies updated

### Additional Hardening

For high-security environments:

- Run in a container with limited capabilities
- Use network policies to restrict outbound access
- Implement additional monitoring/alerting
- Consider running on isolated infrastructure

---

## Known Limitations

### WRITE_SAFE Escape

The WRITE_SAFE tier blocks specific Bash commands but cannot prevent:
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

---

## Security Updates

Security updates will be released as needed. Watch the repository for:
- Security advisories
- Patch releases
- Breaking changes that affect security

---

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors to security improvements will be acknowledged (with permission) in release notes.
