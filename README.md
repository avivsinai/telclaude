# telclaude

Secure Telegram-Claude bridge with LLM-based command screening and tiered permissions.

[![CI](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Telegram Bot API** via grammY (stable, official API)
- **Security Observer** using Claude Code CLI for message screening
- **Tiered Permissions**: READ_ONLY, WRITE_SAFE, FULL_ACCESS
- **Rate Limiting** per-user, per-tier, and global
- **Session Management** with idle timeouts and reset triggers
- **Audit Logging** for compliance and debugging

## Quick Start

```bash
# Install globally
pnpm add -g telclaude

# Set up environment
cp .env.example .env
# Edit .env with your TELEGRAM_BOT_TOKEN

# Install and log into Claude CLI (once)
brew install anthropic-ai/cli/claude   # macOS example
claude login

# Start the relay from the project root so .claude/skills are auto-loaded
telclaude relay --verbose
```

## Requirements

- Node.js 22+
- Telegram bot token from [@BotFather](https://t.me/BotFather)
- Claude CLI installed and logged in (`claude login`)

## Commands

| Command | Description |
| --- | --- |
| `telclaude relay` | Start the message relay with auto-reply |
| `telclaude send <chatId> "message"` | Send a message to a chat |
| `telclaude status` | Show current status and configuration |
| `telclaude doctor` | Check Claude CLI install/login and list local skills |

## Configuration

Create `~/.telclaude/telclaude.json`:

```json5
{
  "telegram": {
    "allowedChats": [123456789]
  },
  "security": {
    "observer": {
      "enabled": true,
      "dangerThreshold": 0.7
    },
    "permissions": {
      "123456789": "WRITE_SAFE",
      "default": "READ_ONLY"
    }
  },
  "inbound": {
    "reply": {
      "mode": "command",
      "command": ["claude", "-p", "{{Body}}"],
      "timeoutSeconds": 600
    }
  }
}
```

## Claude Skills

This repo ships first-class Claude Code Skills under `.claude/skills/`:
- `security-gate`: classifies inbound messages as ALLOW/WARN/BLOCK with reasons.
- `telegram-reply`: guides reply style, media handling, and heartbeat behavior.

Keep the CLI working directory at the repo root (or copy the skills into `~/.claude/skills/`) so Claude auto-loads them during `telclaude relay`.

## Permission Tiers

| Tier | Capabilities |
| --- | --- |
| `READ_ONLY` | Read files, search, web browsing |
| `WRITE_SAFE` | Write/edit files, restricted shell (no rm, sudo, etc.) |
| `FULL_ACCESS` | No restrictions (requires explicit configuration) |

## Security

The security layer provides defense-in-depth:

1. **Fast Path**: Regex-based quick decisions for obvious patterns
2. **LLM Observer**: Claude Haiku analyzes ambiguous messages
3. **Rate Limiting**: Prevents abuse with configurable limits
4. **Audit Logging**: Records all interactions for review

## Development

```bash
# Clone and install
git clone https://github.com/avivsinai/telclaude.git
cd telclaude
pnpm install

# Development mode
pnpm dev relay

# Build
pnpm build

# Lint and format
pnpm lint
pnpm format

# Type check
pnpm typecheck

# Run tests
pnpm test
```

## Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | Yes | Bot token from @BotFather |
| `TELCLAUDE_CONFIG` | No | Custom config file path |
| `TELCLAUDE_LOG_LEVEL` | No | Log level (debug/info/warn/error) |

## License

MIT - see [LICENSE](LICENSE)
