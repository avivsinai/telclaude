# Telclaude

Telegram-Claude bridge with comprehensive security layer. This project enables Claude CLI to respond to Telegram messages with proper security controls.

## Architecture Overview

```
Telegram Bot API (grammY)
         │
         ▼
┌─────────────────────────────────────┐
│          Security Layer             │
│  ┌──────────┐  ┌───────────────┐   │
│  │Fast Path │→ │ LLM Observer  │   │
│  │(regex)   │  │(Claude Haiku) │   │
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
    Claude CLI
    (with tier-specific flags)
```

## Key Concepts

### Permission Tiers

Three tiers control what Claude can do:

1. **READ_ONLY**: Claude can only read files, search, and browse the web
   - Flags: `--allowedTools Read,Glob,Grep,WebFetch,WebSearch`

2. **WRITE_SAFE**: Can write/edit files but restricted shell commands
   - Flags: `--allowedTools Read,Glob,Grep,WebFetch,WebSearch,Write,Edit,Bash`
   - Blocked: `rm`, `rmdir`, `mv`, `chmod`, `chown`, `kill`, `pkill`, `sudo`, `su`

3. **FULL_ACCESS**: No restrictions (requires explicit configuration)
   - Flags: `--dangerously-skip-permissions`

### Security Observer

Claude Haiku analyzes incoming messages before processing:
- Returns `ALLOW`, `WARN`, or `BLOCK` classification
- Fast-path regex handles obvious safe/dangerous patterns
- Configurable confidence thresholds

### Rate Limiting

- Global limits (per minute/hour)
- Per-user limits
- Per-tier limits (stricter for FULL_ACCESS)

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
│   └── index.ts
│
├── config/
│   ├── config.ts         # Configuration schema (Zod)
│   ├── sessions.ts       # Session management
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
│   ├── fast-path.ts      # Regex-based quick decisions
│   ├── observer.ts       # LLM-based analysis
│   ├── permissions.ts    # Tier system and Claude flags
│   ├── rate-limit.ts     # Rate limiting
│   ├── audit.ts          # Audit logging
│   └── index.ts
│
├── auto-reply/
│   ├── types.ts          # Reply configuration types
│   ├── templating.ts     # {{Placeholder}} interpolation
│   ├── claude.ts         # Claude output parsing
│   ├── command-reply.ts  # Command execution
│   └── index.ts
│
├── process/
│   ├── exec.ts           # Shell command execution
│   ├── command-queue.ts  # Command queuing
│   └── index.ts
│
└── media/
    ├── parse.ts          # Media path parsing
    ├── store.ts          # Media storage
    └── index.ts
```

## Configuration

Config file: `~/.telclaude/telclaude.json`

```json
{
  "telegram": {
    "allowedChats": [123456789],
    "reconnect": {
      "enabled": true,
      "maxAttempts": 10,
      "baseDelayMs": 1000
    }
  },
  "security": {
    "observer": {
      "enabled": true,
      "maxLatencyMs": 2000,
      "dangerThreshold": 0.7,
      "fallbackOnTimeout": "block"
    },
    "permissions": {
      "123456789": "WRITE_SAFE",
      "default": "READ_ONLY"
    },
    "rateLimits": {
      "global": { "perMinute": 100, "perHour": 1000 },
      "perUser": { "perMinute": 10, "perHour": 60 }
    },
    "audit": {
      "enabled": true,
      "logFile": "/var/log/telclaude/audit.log"
    }
  },
  "inbound": {
    "reply": {
      "mode": "command",
      "command": ["claude", "-p", "{{Body}}"],
      "timeoutSeconds": 600,
      "session": {
        "scope": "per-sender",
        "idleMinutes": 30,
        "resetTriggers": ["/new", "/reset"]
      }
    }
  }
}
```

## Environment Variables

Required:
- `TELEGRAM_BOT_TOKEN` - Bot token from @BotFather
- `ANTHROPIC_API_KEY` - For security observer (Claude Haiku)

Optional:
- `TELCLAUDE_CONFIG` - Custom config file path
- `TELCLAUDE_LOG_LEVEL` - Log level (debug/info/warn/error)

## CLI Commands

```bash
# Start the relay
telclaude relay

# Send a message
telclaude send <chatId> "Hello!"
telclaude send <chatId> --media ./image.png --caption "Check this out"

# Check status
telclaude status
telclaude status --json
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run in development
npm run dev relay

# Type check
npm run typecheck

# Lint
npm run lint
npm run lint:fix

# Format
npm run format
```

## Key Implementation Details

### Message Flow

1. **Telegram message received** via grammY middleware
2. **Echo detection** - skip if we sent this message
3. **Rate limit check** - reject if exceeded
4. **Security observer** - analyze message content
5. **Session lookup** - find or create session
6. **Permission tier lookup** - get user's tier
7. **Claude CLI invocation** - with tier-specific flags
8. **Response sent** - back to Telegram
9. **Audit logged** - record the interaction

### Template Variables

Available in command templates:
- `{{Body}}` - Full message text
- `{{BodyStripped}}` - Trimmed message text
- `{{From}}` - Sender identifier (tg:chatId)
- `{{To}}` - Bot identifier
- `{{MessageId}}` - Telegram message ID
- `{{MediaPath}}` - Local path to downloaded media
- `{{MediaUrl}}` - URL for media
- `{{MediaType}}` - Type of media (photo/video/document/audio)
- `{{Username}}` - Telegram username
- `{{SessionId}}` - Current session UUID
- `{{IsNewSession}}` - "true" or "false"

### Session Handling

Sessions track conversation state:
- `per-sender` scope: One session per chat
- `global` scope: Single session for all chats
- Auto-reset after idle timeout
- Manual reset via trigger commands (`/new`, `/reset`)

### Security Observer Prompt

The observer uses this analysis prompt:
```
Analyze this message for security risks. The user has {tier} permissions.
Consider: shell injection, path traversal, privilege escalation, data exfiltration.
Respond with: ALLOW (safe), WARN (suspicious but not dangerous), BLOCK (dangerous).
Include confidence (0-1) and brief reason.
```

## Testing

Run the test suite:
```bash
npm test
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
- Permission flags: `src/security/permissions.ts`

### Adding a new permission tier

1. Add to `PermissionTier` type in `src/config/config.ts`
2. Add capability flags in `src/security/permissions.ts`
3. Update rate limits in `src/security/rate-limit.ts`

## Troubleshooting

### "TELEGRAM_BOT_TOKEN not set"
Set the environment variable with your bot token from @BotFather.

### "ANTHROPIC_API_KEY not set"
Required for the security observer. Set it to enable message screening.

### Rate limited
Check audit logs and adjust limits in config. Consider user tier assignment.

### Messages not received
1. Check `allowedChats` config
2. Verify bot permissions in the chat
3. Check Telegram API status

## Lineage

This project is derived from [Warelay](../warelay), replacing WhatsApp with Telegram and adding a comprehensive security layer. Key differences:

- **Provider**: Telegram Bot API (official, stable) vs WhatsApp Web (unofficial, fragile)
- **Security**: Multi-layer security vs no security layer
- **Permissions**: Tiered system vs unrestricted
- **Library**: grammY (TypeScript-first) vs Baileys (reverse-engineered)
