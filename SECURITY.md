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

#### Google Services

The Google services sidecar (Gmail, Calendar, Drive, Contacts) adds provider-specific threats:

6. **Token Replay** — Reusing a previously approved action token to repeat or modify an operation. Mitigated by: one-time JTI (SQLite atomic insert), max 300s TTL, SHA-256 params hash binding (changing any parameter invalidates the token).
7. **Approval Forgery** — Forging an approval token without user consent. Mitigated by: Ed25519 signing via vault (agent never sees signing key), domain-separated signatures (`approval-v1\n<payload>`).
8. **Direct API Access** — Agent bypassing the relay to call Google APIs directly. Mitigated by: `google-egress` network only routes from the sidecar container; agents have no network path to `googleapis.com`; PreToolUse hook blocks WebFetch to `googleapis.com`.

#### Hermes Private Runtime

The no-fork Hermes wrapper runs a pinned upstream Hermes runtime as the private persona's execution engine. The contained runtime is untrusted compute, which adds runtime-specific threats:

9. **Upstream Tampering** — Modifying the pinned Hermes checkout (a fork, patch, monkeypatch, or runtime source replacement) to defeat the security envelope. Mitigated by: the no-fork proof (`src/hermes/no-fork-proof.ts`) — Ed25519 runner-attested git checks (`checkout.present`, `checkout.pinned`, `checkout.statusClean`/`diffClean`/`indexClean`, plus post-run equivalents) require the checkout to match the pinned ref (default `hermes-agent` @ `v2026.5.29`) byte-for-byte, with `runner.noRuntimeSourceReplacement` and `runner.noMonkeypatch` checks.
10. **Client Authority Injection** — The contained runtime forging its own permission scope by supplying authority fields on MCP calls. Mitigated by: the live MCP relay server strips client-supplied authority/connection fields (`authority`, `authorityHandle`, `connection`, `sessionKey`, `profileId`, `memorySource`, `peerAddress`, etc.) and resolves authority only from an opaque, connection-bound handle in the relay-side registry.
11. **Side-Effect Abuse** — The runtime executing provider writes or outbound messages without operator consent. Mitigated by: two-phase side-effect ledger (prepare → human approval token → execute) with per-record params/body hash binding, 60s approval-token TTL, JTI replay prevention (`hermes_mcp_side_effect_approval_jti.sqlite`), and a self-approval block (actor cannot be its own approver).
12. **Model-Credential Exfiltration / Direct Model Egress** — The runtime reaching model providers directly or extracting model secrets. Mitigated by: model traffic is relay-mediated through the OpenAI Codex proxy with peer-bound tokens; the contained container has model-provider hostnames pinned to a blocked address (`192.0.2.1`) and no raw model credentials in its environment.
13. **Cross-Domain Memory Leakage** — The private runtime reading or persisting public/social memory. Mitigated by: the served-MCP memory bridge enforces a memory-source gate — a private (telegram-profile) authority cannot read social rows, and a social/bare-legacy source cannot satisfy a private read.

### Security Layers

| Layer | Component | Protection |
|-------|-----------|------------|
| **1. Screening** | Fast Path + Observer | Blocks dangerous prompts before execution |
| **2. Policy** | Rate Limiter + Approvals | Prevents abuse, human-in-loop for risky ops |
| **3. Permissions** | Tier System | Controls which tools Claude can use |
| **4. Enforcement** | Isolation boundary | contained Hermes runtime, relay-owned MCP/capability services, and Docker firewall |
| **5. Runtime attestation** | No-fork proof + served-MCP authority | Hermes runtime is pinned and unmodified; its capabilities and side effects flow only through relay-owned MCP tools |

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

### SOCIAL

Social persona tier. Can use file tools + Bash + WebFetch/WebSearch, but with trust-gating:
- Bash access gated by actor type: operator queries and proactive posting get Bash; notification processing does not
- WebFetch permissive (public internet, RFC1918/metadata blocked)
- Write/Edit blocked to skills, auth, and memory paths
- Skill invocations require explicit `allowedSkills` in service config (fail-closed if omitted)

### FULL_ACCESS

Maximum privilege tier. No tool restrictions.

**Requires human approval** unless the user is a claimed admin. Admins bypass per-request approval but remain sandboxed and subject to all other security layers (secret filtering, rate limits, audit).

---

## Isolation Boundary (Mode-Dependent)

All LLM/persona runtime execution uses the contained Hermes boundary:

- **Docker/prod**: relay + sidecars + `tc-hermes-contained` / `tc-hermes-social` overlay with firewall and internal-only networks
- **Native relay dev**: the relay process may run natively, but Telegram/social/cron/observer execution still targets Hermes

### Blocked Paths

The contained runtime never mounts high-value host paths. Application policy and Docker mounts block access to:

- `~/.telclaude/` — Configuration and secrets
- `~/.ssh/` — SSH keys
- `~/.gnupg/` — GPG keys
- `~/.aws/` — AWS credentials
- `~/.config/` — Application secrets
- `/etc/passwd`, `/etc/shadow` — System files

In Docker mode, the relay container does not mount the workspace and the contained Hermes runtimes receive only curated runtime surfaces. Application guards still block sensitive paths if they appear.

### Write Restrictions

- **READ_ONLY**: No writes allowed.
- **WRITE_LOCAL/FULL_ACCESS**: Writes are constrained by Hermes authority, relay policy, container filesystem boundaries, and explicit side-effect approval.

---

## Hermes Private Runtime (No-Fork Wrapper)

The relay routes persona work to a pinned upstream Hermes runtime. The relay remains the security boundary; Hermes is treated as untrusted compute. Enforcement rests on four mechanisms:

### 1. No-Fork Proof

The wrapper must prove the Hermes checkout is unmodified upstream — not a fork, patch, monkeypatch, or runtime source replacement. The proof (`src/hermes/no-fork-proof.ts`) emits Ed25519 runner-attested git checks: the checkout is present, `HEAD` matches the pinned ref commit, the working tree/index/diff are clean before and after the wrapper run, and the run produced no runtime source replacement or monkeypatch. `cutover-check` fails closed unless every check passes and the runner attestation is signed and bound to the evidence.

### 2. Contained Runtime Posture (Docker)

The `docker-compose.hermes.yml` overlay runs the relay plus separate private and social Hermes containers — `telclaude`, `tc-hermes-contained`, and `tc-hermes-social` — on **separate internal**, non-routable bridge networks. The relay joins both networks (`telclaude-hermes-private` and `telclaude-hermes-social`); `tc-hermes-contained` and `tc-hermes-social` do not share L3/TCP reachability with each other. The contained runtimes:

- Uses a pinned image digest (`nousresearch/hermes-agent@sha256:…`), runs as non-root (`10000:10000`), drops all capabilities, and sets `no-new-privileges`.
- Has a read-only root filesystem with `noexec` tmpfs for `/tmp`, `/home/hermes`, and `/run`.
- Mounts the relay source read-only and a curated skill allowlist read-only (`hermes-contained-skills.allowlist` for private/cron/observer, `hermes-social-skills.allowlist` for social); it never mounts the workspace or any credential volume.
- Has model-provider hostnames (`api.openai.com`, `api.anthropic.com`, `chatgpt.com`, `generativelanguage.googleapis.com`, etc.) pinned to a blocked address (`192.0.2.1`), so direct model egress fails at the network layer.

### 3. Served-MCP Authority Model

Hermes does not receive raw local tool grants. Instead, the relay hosts a **live MCP server** (HTTP, `transport: http_relay_internal_network`, relay-internal only, `runsInHermesContainer: false`) exposing a fixed set of relay-owned tools — provider read/prepare-write/execute-write, memory search/write, attachment get, outbound prepare/execute, and audit note. Every call is bound to an opaque, connection-scoped authority handle resolved in the relay-side registry (15-minute default TTL). The server strips any client-supplied authority, connection, session, profile, or `memorySource` fields, so the runtime cannot widen its own scope. Provider scope, outbound channels, and memory trust level are derived from the authority, never from runtime input. A private (telegram-profile) authority cannot read social memory; a social or bare-legacy source cannot satisfy a private read.

### 4. Two-Phase Side Effects

Provider writes and outbound messages are first-class ledger records, not inline tool calls. The flow is **prepare → human approval → execute**:

- `prepare` stages a record with canonical params/body hashes.
- Execution requires a signed approval token (`v1.<claims>.<sig>`, Ed25519 via vault) whose binding must match the staged record exactly. Tokens carry a 60-second max TTL, are single-use via a JTI store (`hermes_mcp_side_effect_approval_jti.sqlite`), and are rejected if expired, future-issued, replayed, or rebound.
- The ledger enforces a **self-approval block**: the approver actor must differ from the requesting actor.

This is the Hermes-side analogue of the Google sidecar's approval-token model — a compromised runtime cannot reuse, mutate, or self-approve an action.

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
- [ ] **Google services**: Run `setup-google` to store OAuth credentials in vault
- [ ] **Google services**: Verify `google-services` container uses `google-egress` network (googleapis.com only)
- [ ] **Google services**: Confirm agents have no route to `google-services` container
- [ ] **Hermes runtime**: Run `telclaude hermes prove --upstream-clean` (no-fork proof) — checkout pinned, clean, no source replacement
- [ ] **Hermes runtime**: Run `telclaude hermes cutover-check --strict` before any production cutover; resolve every gate (no-fork, network probes, parity roster) rather than scoping around it
- [ ] **Hermes runtime**: Generate `TELCLAUDE_HERMES_API_SERVER_KEY` and `TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY` as ephemeral per-deploy secrets; confirm `tc-hermes-contained` and `tc-hermes-social` run on the internal network with model-provider hosts blocked and no credential volumes mounted

### Admin Claim Security

The bot **ignores all messages unless `allowedChats` is configured**. Admin claim is only available
from **private chats** that are on the allowlist.

If no admin exists and no secret is configured, the **first private DM in `allowedChats` can claim
admin**. This is a bootstrap race condition.

To prevent scanner bots from claiming admin:
```bash
export TELCLAUDE_ADMIN_SECRET="your-secure-random-secret"
```

Then claim admin with: `/claim your-secure-random-secret`

### Identity Linking Security

Identity linking (`/link`) is **only permitted in private chats** to avoid group-level
authentication ambiguity. Use a direct message with the bot to link a user.

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

### 4. HTTP Method Restrictions Are Not Enforced

Domain allowlists are enforced, but HTTP method restrictions (GET-only vs POST) are not enforced at runtime.
If a domain is allowlisted, the tool can still make non-GET requests and send data in request bodies.

**Mitigation**:
- Treat domain allowlists as the only enforced control.
- Use a proxy or firewall that can enforce method/body restrictions if needed.
- Avoid exposing bearer tokens to tool environments unless absolutely necessary.

### 5. Output Filter Bypass

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
- In Docker mode, the firewall enforces egress allowlists (agent runs tools; relay still restricted)
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
