# Telclaude

Telegram-Claude bridge with comprehensive security layer. This project enables Claude Code to respond to Telegram messages with proper security controls.

## Development Guidelines

- **No backward compatibility** - This is an unreleased project. Do not write migration code, compatibility shims, deprecation warnings, or version-specific logic. Just change things directly. No need to preserve configs, DB schemas, APIs, or stored state - expect to reset data when changing things. No version numbering in names either (e.g., don't call things "V2 Session Pool").
- **Pristine code** - Write clean, idiomatic TypeScript. No dead code, no legacy cruft.
- **Claude Agent SDK** - Use `@anthropic-ai/claude-agent-sdk` for all Claude interactions, not CLI spawning.
- **Skills** - Use `.claude/skills/` for Claude's behavior customization. Skills are auto-loaded by the SDK.

## Architecture Overview

```
Telegram Bot API (grammY)
         │
         ▼
┌─────────────────────────────────────┐
│          Security Layer             │
│  ┌──────────┐  ┌───────────────┐   │
│  │Fast Path │→ │   Observer    │   │
│  │(regex)   │  │(SDK + skill)  │   │
│  └──────────┘  └───────────────┘   │
│        │              │             │
│        ▼              ▼             │
│  ┌──────────────────────────────┐  │
│  │   Permission Tier System     │  │
│  │ READ_ONLY│WRITE_SAFE│FULL    │  │
│  └──────────────────────────────┘  │
│        │                            │
│  ┌──────────┐  ┌───────────────┐   │
│  │Rate Limit│  │ Audit Logger  │   │
│  └──────────┘  └───────────────┘   │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│    OS-Level Sandbox (MANDATORY)     │
│  (Seatbelt/macOS, bubblewrap/Linux) │
│  • Tier-aligned filesystem config   │
│  • Network filtering                │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│         Session Pool                │
│  • Reuses SDK connections           │
│  • Per-user session pooling         │
│  • Fallback to stable query() API   │
└─────────────────────────────────────┘
         │
         ▼
  Claude Agent SDK
  (allowedTools per tier)

┌─────────────────────────────────────┐
│        TOTP Daemon (separate)       │
│  • Secrets in OS keychain (keytar)  │
│  • Unix socket IPC only             │
│  • Never exposed to Claude          │
└─────────────────────────────────────┘
```

## Key Concepts

### Security Architecture

The security architecture provides two profiles and five security pillars:

#### Security Profiles

- **simple** (default): Hard enforcement only
  - Sandbox (filesystem, environment, network)
  - Secret output filter (CORE patterns + entropy detection)
  - Rate limiting
  - Audit logging
  - No observer, no approval workflows

- **strict** (opt-in): Adds soft policy layers
  - All "simple" features plus:
  - Security observer (Claude Haiku analysis)
  - Approval workflows for risky operations
  - Permission tier enforcement

- **test**: No security (for testing only)

#### Five Security Pillars

1. **Filesystem Isolation**: Sandbox blocks access to sensitive paths (~/.ssh, ~/.aws, ~/.telclaude, etc.)
2. **Environment Isolation**: Allowlist-only model - only safe env vars pass through (PATH, LANG, NODE_ENV, etc.)
3. **Network Isolation**: Cloud metadata endpoints blocked (169.254.169.254, etc.) to prevent SSRF
4. **Secret Output Filtering**: CORE patterns detect and redact secrets in output (Telegram tokens, API keys, private keys, JWTs)
5. **Auth/TOTP/Rate Limiting/Audit**: Identity verification, 2FA, rate limits, and audit trail

#### Key Features

- **Private /tmp**: Sandbox gets its own /tmp (mounted from ~/.telclaude/sandbox-tmp) to prevent reading host secrets
- **Streaming Redaction**: Handles secrets split across message chunks
- **Entropy Detection**: Catches high-entropy blobs that might be encoded secrets
- **CORE Patterns**: 18+ secret patterns that are NEVER configurable, NEVER removable
- **denyWrite Patterns**: Blocks writing sensitive file patterns (id_rsa, *.pem, .env, etc.) even to allowed paths

### Permission Tiers

Three tiers control what Claude can do (via SDK `allowedTools`):

1. **READ_ONLY**: Claude can only read files, search, and browse the web
   - Tools: `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch`
   - ⚠️ **Upstream Limitation**: `@anthropic-ai/sandbox-runtime` adds default write paths internally (`/tmp/claude`, `~/.claude/debug`) that we cannot disable. Telclaude mitigates this with `denyWrite` patterns that block sensitive file types (SSH keys, .env files, etc.) in ALL paths including sandbox-runtime's defaults.

2. **WRITE_SAFE**: Can write/edit files but restricted shell commands
   - Tools: `Read`, `Glob`, `Grep`, `WebFetch`, `WebSearch`, `Write`, `Edit`, `Bash`
   - Blocked Bash commands: `rm`, `rmdir`, `mv`, `chmod`, `chown`, `kill`, `pkill`, `sudo`, `su`
   - ⚠️ **Security Note**: WRITE_SAFE prevents *accidental* damage, not *malicious* attacks. Users can escape by writing scripts that perform blocked operations. For true isolation, run in a container.

3. **FULL_ACCESS**: No tool restrictions, but requires human approval for each request
   - Uses `bypassPermissions` mode with `allowDangerouslySkipPermissions`
   - ⚠️ **Every request requires approval** - This is intentional for safety. FULL_ACCESS grants unrestricted tool use, so human-in-the-loop approval prevents accidental or malicious damage.
   - Future: Time-based approval windows (e.g., "approve for 2 hours") to reduce friction while maintaining security.

### OS-Level Sandbox (MANDATORY)

All Claude queries run inside an OS-level sandbox using `@anthropic-ai/sandbox-runtime`. **Sandbox is mandatory** - the relay will not start if sandboxing is unavailable.

- **macOS**: Uses Seatbelt (`sandbox-exec`) for kernel-level enforcement
- **Linux**: Uses bubblewrap for namespace-based isolation

The sandbox enforces:
- **Filesystem restrictions**: Blocks access to `~/.telclaude`, `~/.ssh`, `~/.gnupg`, `~/.aws`, etc.
- **Tier-aligned write restrictions**:
  - READ_ONLY: No writes allowed (empty allowWrite)
  - WRITE_SAFE/FULL_ACCESS: Writes to cwd + `/tmp`
- **Network filtering**: Configurable domain allowlist (default: permissive)

**Design principle**: The permission tier defines *policy* (what Claude should do), while the sandbox provides *enforcement* (what Claude can do). The sandbox config matches the tier, not more restrictive.

This provides defense-in-depth against prompt injection attacks - even if Claude is tricked into running malicious commands, the OS kernel prevents access to sensitive data.

### Session Pool

SDK connections are pooled per user for performance:

- **Connection reuse**: Persistent SDK sessions reduce process spawn overhead
- **Automatic lifecycle**: Sessions are cleaned up after idle timeout (5 minutes)
- **Fallback**: If unstable API fails, automatically falls back to stable `query()` API

The pool is keyed by session key (derived from chat/user ID), so each user gets their own pooled connection. This is especially beneficial for multi-turn conversations.

### TOTP Daemon

Two-factor authentication secrets are stored in a separate process:

- **Process isolation**: TOTP daemon runs separately from the main relay
- **OS keychain storage**: Secrets stored via `keytar` (macOS Keychain, Linux secret-service)
- **Unix socket IPC**: Communication via `~/.telclaude/totp.sock` (permissions 0600)
- **Per-user scope**: TOTP requires an identity link first (per-user, not per-chat)

The daemon must be running for 2FA to work:
```bash
# Start the TOTP daemon (in a separate terminal or as a service)
telclaude totp-daemon

# Or run it in the background
telclaude totp-daemon &
```

This architecture ensures that even if Claude is compromised via prompt injection, it cannot:
1. Read TOTP secrets (they're in a separate process)
2. Bypass 2FA (it requires the daemon to verify codes)
3. Access the OS keychain (sandbox blocks it)

### Security Observer

Claude Haiku analyzes incoming messages before processing:
- Returns `ALLOW`, `WARN`, or `BLOCK` classification
- Fast-path regex handles obvious safe/dangerous patterns
- Configurable confidence thresholds
- **Circuit breaker**: Prevents cascading failures when SDK is slow/failing

### Storage

All security-critical state is persisted in SQLite (`~/.telclaude/telclaude.db`):
- **Approvals**: Pending approval requests survive restarts
- **Rate limits**: Counter state persists across restarts
- **Identity links**: Telegram-to-user mappings
- **Sessions**: Conversation state for multi-turn interactions

SQLite provides ACID transactions for atomic operations (e.g., consuming an approval).

### Rate Limiting

- Global limits (per minute/hour)
- Per-user limits
- Per-tier limits (stricter for FULL_ACCESS)
- **Fails closed**: If rate limiting errors, requests are blocked (not allowed)
- SQLite-backed for persistence across restarts

### First-Time Admin Claim

When no admin is configured, the first private chat message triggers an admin claim flow:

1. User sends any message to the bot in a **private chat**
2. Bot responds with a confirmation code: `Reply /approve ABC123 to claim admin`
3. User replies `/approve ABC123` within 5 minutes
4. User is linked as admin and prompted to set up TOTP

**Security constraints:**
- Admin claim only works in **private chats** (groups/channels are rejected)
- Each claim requires explicit confirmation with a unique code
- Code expires after 5 minutes
- Audit logged for security review

To reset and re-claim admin:
```bash
telclaude reset-auth  # Requires typing "RESET" to confirm
```

### Identity Linking

Links Telegram users to authorized identities via out-of-band verification:

1. Admin generates a link code: `telclaude link tg:123456789`
2. User enters the code in Telegram: `/link abc123`
3. If valid, their identity is linked and they receive assigned permissions

Control-plane commands (handled before Claude sees them):
- `/link <code>` - Link identity with verification code
- `/unlink` - Remove identity link
- `/whoami` - Show current identity link status

### Command Approval

Risky requests require human-in-the-loop approval:

1. Security observer flags request as requiring approval
2. User is shown the request details with approval code
3. User replies `/approve <code>` or `/deny <code>`
4. Approved requests execute; denied requests are logged

Approval is required for:
- FULL_ACCESS tier requests
- BLOCK classification (can be overridden)
- WARN classification with WRITE_SAFE tier
- Low-confidence warnings (< 0.5)

## Project Structure

```
src/
├── index.ts              # Main entry point
├── globals.ts            # Global state (verbose flag)
├── logging.ts            # Pino logger setup
├── runtime.ts            # Runtime environment detection
├── utils.ts              # Utility functions
├── env.ts                # Environment variable handling
│
├── cli/
│   ├── program.ts        # Commander CLI setup
│   └── index.ts
│
├── commands/
│   ├── send.ts           # Send message command
│   ├── relay.ts          # Start relay command
│   ├── status.ts         # Show status command
│   ├── link.ts           # Identity linking command
│   ├── doctor.ts         # Health check command
│   ├── totp-daemon.ts    # TOTP daemon command
│   ├── totp-setup.ts     # TOTP setup command
│   ├── reset-auth.ts     # Reset auth state command (DANGEROUS)
│   └── index.ts
│
├── config/
│   ├── config.ts         # Configuration schema (Zod)
│   ├── path.ts           # Config path resolution
│   ├── sessions.ts       # Session management (SQLite-backed)
│   └── index.ts
│
├── storage/
│   ├── db.ts             # SQLite database setup and migrations
│   └── index.ts
│
├── sdk/
│   ├── client.ts         # Claude Agent SDK wrapper
│   ├── session-pool.ts   # Session Pool for connection reuse
│   ├── message-guards.ts # Type guards for SDK messages
│   └── index.ts
│
├── sandbox/
│   ├── config.ts         # Sandbox configuration (paths, network)
│   ├── env.ts            # Environment isolation (allowlist model)
│   ├── manager.ts        # SandboxManager wrapper
│   └── index.ts
│
├── totp-daemon/
│   ├── protocol.ts       # IPC protocol types (Zod schemas)
│   ├── keychain.ts       # OS keychain wrapper (keytar)
│   ├── server.ts         # Unix socket server
│   └── index.ts
│
├── totp-client/
│   ├── client.ts         # IPC client for TOTP daemon
│   └── index.ts
│
├── telegram/
│   ├── types.ts          # Telegram-specific types
│   ├── client.ts         # grammY bot creation
│   ├── inbound.ts        # Message reception
│   ├── outbound.ts       # Message sending
│   ├── reconnect.ts      # Reconnection logic
│   ├── auto-reply.ts     # Main monitoring loop
│   └── index.ts
│
├── security/
│   ├── types.ts          # Security types
│   ├── pipeline.ts       # SecurityPipeline abstraction (simple/strict/test profiles)
│   ├── streaming-redactor.ts # Streaming secret redaction across chunk boundaries
│   ├── output-filter.ts  # CORE secret patterns + entropy detection
│   ├── admin-claim.ts    # First-time admin claim flow (private chats only)
│   ├── fast-path.ts      # Regex-based quick decisions
│   ├── observer.ts       # SDK-based security analysis (with circuit breaker)
│   ├── permissions.ts    # Tier system and tool arrays
│   ├── rate-limit.ts     # Rate limiting (SQLite-backed, fails closed)
│   ├── circuit-breaker.ts # Circuit breaker for observer failures
│   ├── audit.ts          # Audit logging
│   ├── linking.ts        # Identity linking (SQLite-backed)
│   ├── approvals.ts      # Command approval mechanism (SQLite-backed)
│   └── index.ts
│
├── auto-reply/
│   ├── templating.ts     # Message context types
│   └── index.ts
│
└── media/
    ├── store.ts          # Media storage
    └── index.ts
```

## Configuration

Config file: `~/.telclaude/telclaude.json` (or set via `--config` flag or `TELCLAUDE_CONFIG` env var)

```json
{
  "telegram": {
    "allowedChats": [123456789],
    "polling": {
      "timeout": 30,
      "limit": 100
    },
    "reconnect": {
      "initialMs": 1000,
      "maxMs": 60000,
      "factor": 2.0,
      "jitter": 0.3,
      "maxAttempts": 0
    }
  },
  "security": {
    "profile": "simple",
    "observer": {
      "enabled": true,
      "maxLatencyMs": 2000,
      "dangerThreshold": 0.7,
      "fallbackOnTimeout": "block"
    },
    "secretFilter": {
      "additionalPatterns": [
        { "id": "my_api_key", "pattern": "my-api-[a-z0-9]{32}" }
      ],
      "entropyDetection": {
        "enabled": true,
        "threshold": 4.5,
        "minLength": 32
      }
    },
    "permissions": {
      "defaultTier": "READ_ONLY",
      "users": {
        "tg:123456789": {
          "tier": "WRITE_SAFE",
          "rateLimit": { "perMinute": 20, "perHour": 100 }
        }
      }
    },
    "rateLimits": {
      "global": { "perMinute": 100, "perHour": 1000 },
      "perUser": { "perMinute": 10, "perHour": 60 },
      "perTier": {
        "READ_ONLY": { "perMinute": 20, "perHour": 200 },
        "WRITE_SAFE": { "perMinute": 10, "perHour": 100 },
        "FULL_ACCESS": { "perMinute": 5, "perHour": 30 }
      }
    },
    "audit": {
      "enabled": true,
      "logFile": "/var/log/telclaude/audit.log"
    }
  },
  "inbound": {
    "reply": {
      "enabled": true,
      "timeoutSeconds": 600,
      "session": {
        "scope": "per-sender",
        "idleMinutes": 30,
        "resetTriggers": ["/new", "/reset"]
      }
    }
  },
  "logging": {
    "level": "info"
  }
}
```

**Mandatory allowlist:** `allowedChats` must include your chat ID *before* you DM the bot. The relay refuses all messages (including first-time admin claim) from chats not on this list. Obtain your ID via a helper bot like `@userinfobot` and add it here to begin setup.

## Environment Variables

Required:
- `TELEGRAM_BOT_TOKEN` - Bot token from @BotFather

Optional:
- `ANTHROPIC_API_KEY` - API key (alternative to `claude login`)
- `TELCLAUDE_CONFIG` - Custom config file path
- `TELCLAUDE_LOG_LEVEL` - Log level (debug/info/warn/error)
- `TELCLAUDE_DATA_DIR` - Data directory (default: `~/.telclaude`)
- `TELCLAUDE_TOTP_SOCKET` - Custom path for TOTP daemon socket (default: `~/.telclaude/totp.sock`)

Docker-only (file-based TOTP storage):
- `TOTP_STORAGE_BACKEND` - `keytar` (default, OS keychain) or `file` (encrypted file)
- `TOTP_ENCRYPTION_KEY` - AES-256-GCM key for file backend (generate with: `openssl rand -base64 32`)
- `TOTP_SECRETS_FILE` - Custom path for encrypted secrets file

## Claude Agent SDK

Telclaude uses the `@anthropic-ai/claude-agent-sdk` package for programmatic Claude interaction. This requires:

1. **Claude CLI installed**: `brew install anthropic-ai/cli/claude` (macOS)
2. **Logged in**: Run `claude login` to authenticate
3. **Skills**: Keep the working directory at the repo root so `.claude/skills/` auto-loads

The SDK provides:
- Streaming responses via `AsyncGenerator`
- Tool control via `allowedTools` array
- Custom permission logic via `canUseTool` callback
- Automatic skill loading via `settingSources: ['project']`

### Session Pool (Experimental)

Telclaude uses the unstable SDK session API for connection pooling:

```typescript
// Unstable session API usage
import { unstable_v2_createSession, unstable_v2_resumeSession } from '@anthropic-ai/claude-agent-sdk';

// Sessions are pooled and reused across messages
const session = unstable_v2_createSession(options);
await session.send(message);
for await (const msg of session.receive()) { ... }
session.close();
```

Benefits:
- **Reduced latency**: Reuse persistent connections instead of spawning new processes
- **Automatic fallback**: If unstable API fails, falls back to stable `query()` API
- **Lifecycle management**: Idle sessions are automatically cleaned up

The unstable session API is wrapped in `src/sdk/session-pool.ts` to isolate the unstable API surface.

## CLI Commands

```bash
# Start the relay (default: simple profile)
telclaude relay

# Start with strict profile (enables observer + approvals)
telclaude relay --profile strict

# Start with test profile (NO SECURITY - testing only)
telclaude relay --profile test

# Send a message
telclaude send <chatId> "Hello!"
telclaude send <chatId> --media ./image.png --caption "Check this out"

# Check status
telclaude status
telclaude status --json

# Doctor (verify Claude CLI + skills + sandbox + security pillars)
telclaude doctor

Example output:
```
=== telclaude doctor ===

📦 Claude CLI
   Version: claude version 1.15.0
   Logged in: ✓ yes
   Local skills: ✓ 2 found
     - security-gate
     - telegram-reply

🔒 Security
   Profile: simple
     Observer: disabled (simple profile)
     Approvals: disabled (simple profile)

🛡️  Security Pillars
   1. Filesystem isolation: ✓ available
   2. Environment isolation: ✓ 15 allowed, 42 blocked
   3. Network isolation: ✓ metadata endpoints blocked
   4. Secret filtering: ✓ 18 CORE patterns
   5. Auth/TOTP: ✓ daemon running

📦 Sandbox
   Status: ✓ available

🔐 TOTP Daemon
   Status: ✓ running

📊 Overall Health
   ✓ All checks passed
```

# Start the TOTP daemon (required for 2FA)
telclaude totp-daemon

# Identity linking (generate code for out-of-band verification)
telclaude link <user-id>           # Generate a link code for a user
telclaude link --list              # List all linked identities
telclaude link --remove <user-id>  # Remove a linked identity

# Set up TOTP 2FA for a user (requires totp-daemon running)
telclaude totp-setup <user-id>     # Interactive setup with QR code and verification

# Reset auth state (DANGEROUS - requires confirmation)
telclaude reset-auth               # Nuke all identity links and TOTP sessions
telclaude reset-auth --force       # Skip confirmation prompt
```

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Run in development
pnpm dev relay

# Type check
pnpm typecheck

# Lint
pnpm lint
pnpm lint:fix

# Format
pnpm format
```

## Key Implementation Details

### Message Flow

1. **Telegram message received** via grammY middleware
2. **Echo detection** - skip if we sent this message
3. **Control-plane intercept** - handle /link, /approve, /deny, /unlink, /whoami
4. **Rate limit check** - reject if exceeded
5. **Security observer** - analyze message content (via SDK)
6. **Approval check** - if risky, create pending approval and wait
7. **Session lookup** - find or create session
8. **Permission tier lookup** - get user's tier (check identity links)
9. **SDK query execution** - with tier-specific `allowedTools`
10. **Streaming response** - chunks sent back to Telegram as they arrive
11. **Audit logged** - record the interaction with cost tracking

### Session Handling

Sessions track conversation state:
- `per-sender` scope: One session per chat
- `global` scope: Single session for all chats
- Auto-reset after idle timeout
- Manual reset via trigger commands (`/new`, `/reset`)

### Security Observer

The observer uses the Claude Agent SDK with the `security-gate` skill to analyze messages:

1. **Fast-path check** - Regex patterns for obvious safe/dangerous patterns (instant, no API call)
2. **SDK analysis** - Sends message to Claude with security context for classification

Response format:
```json
{
  "classification": "ALLOW" | "WARN" | "BLOCK",
  "confidence": 0.0-1.0,
  "reason": "Brief explanation"
}
```

Classification is adjusted by `dangerThreshold`:
- BLOCK downgraded to WARN if confidence < threshold
- WARN downgraded to ALLOW if confidence < threshold * 0.5

## Testing

Run the test suite:
```bash
pnpm test
```

For manual testing:
1. Create a test bot via @BotFather
2. Set `TELEGRAM_BOT_TOKEN`
3. Run `telclaude relay -v`
4. Send messages to your bot

## Common Tasks

### Adding a new command

1. Create `src/commands/mycommand.ts`
2. Export `registerMyCommand(program: Command)`
3. Import and register in `src/index.ts`

### Modifying security rules

- Fast-path patterns: `src/security/fast-path.ts`
- Observer prompts: `src/security/observer.ts`
- Permission tiers and tool arrays: `src/security/permissions.ts`
- Security gate skill: `.claude/skills/security-gate/SKILL.md`

### Adding a new permission tier

1. Add to `PermissionTier` type in `src/config/config.ts`
2. Add capability flags in `src/security/permissions.ts`
3. Update rate limits in `src/security/rate-limit.ts`

## Troubleshooting

### "TELEGRAM_BOT_TOKEN not set"
Set the environment variable with your bot token from @BotFather.

### "SDK query error" / Observer fallback
Install the Claude CLI (`brew install anthropic-ai/cli/claude` on macOS) and run `claude login`. If the SDK cannot execute queries, the observer uses the fallback policy (default: block).

### Rate limited
Check audit logs and adjust limits in config. Consider user tier assignment.

### Messages not received
1. Check `allowedChats` config
2. Verify bot permissions in the chat
3. Check Telegram API status

### "TOTP daemon unavailable"
Start the TOTP daemon in a separate terminal: `telclaude totp-daemon`. The daemon must be running for 2FA to work.

### "Sandbox unavailable" (relay won't start)
Sandbox is mandatory for telclaude. On macOS, the sandbox should work out of the box. On Linux, install `bubblewrap`:
- Debian/Ubuntu: `apt install bubblewrap`
- Fedora: `dnf install bubblewrap`
- Arch: `pacman -S bubblewrap`
- Windows: Not supported - run in Docker or WSL2

If running in Docker, the container may need `--privileged` or specific capabilities for bubblewrap to work.

### 2FA not working
1. Ensure an identity link exists: `/whoami`
2. Check the TOTP daemon is running: `telclaude doctor`
3. Verify the authenticator app time is synced

## Lineage

This project is derived from [Warelay](../warelay), replacing WhatsApp with Telegram and adding a comprehensive security layer. Key differences:

- **Provider**: Telegram Bot API (official, stable) vs WhatsApp Web (unofficial, fragile)
- **Security**: Multi-layer security vs no security layer
- **Permissions**: Tiered system vs unrestricted
- **Library**: grammY (TypeScript-first) vs Baileys (reverse-engineered)
