# telclaude

Secure Telegram-Claude bridge with LLM-based security screening and tiered permissions.

[![CI](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml/badge.svg)](https://github.com/avivsinai/telclaude/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Telegram                                    │
│                                 │                                        │
│                                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                        Security Layer                             │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │   │
│  │  │ Fast Path  │─▶│  Observer  │─▶│ Rate Limit │─▶│  Approval  │  │   │
│  │  │  (regex)   │  │  (Haiku)   │  │  (SQLite)  │  │  (human)   │  │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Permission Tiers                             │   │
│  │  READ_ONLY          WRITE_SAFE           FULL_ACCESS              │   │
│  │  (5 tools)          (8 tools)            (all, +approval)         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    OS Sandbox (mandatory)                         │   │
│  │            macOS: Seatbelt  │  Linux: bubblewrap                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                 │                                        │
│                                 ▼                                        │
│                        Claude Agent SDK                                  │
│                                                                          │
│  ┌────────────────────┐                                                  │
│  │    TOTP Daemon     │◄─── separate process, OS keychain               │
│  └────────────────────┘                                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Prerequisites: Node 22+, pnpm, Claude CLI (brew install anthropic-ai/cli/claude)

git clone https://github.com/avivsinai/telclaude.git && cd telclaude
pnpm install
claude login

# Set TELEGRAM_BOT_TOKEN in .env (get from @BotFather)
cp .env.example .env

pnpm dev doctor   # verify setup
pnpm dev relay    # start
```

## Configuration

Config: `~/.telclaude/telclaude.json`

```json
{
  "telegram": { "allowedChats": [] },
  "security": {
    "permissions": {
      "defaultTier": "READ_ONLY",
      "users": { "tg:123456789": { "tier": "WRITE_SAFE" } }
    }
  }
}
```

See [CLAUDE.md](CLAUDE.md) for full configuration reference.

## Development

```bash
pnpm dev relay    # dev mode
pnpm typecheck    # type check
pnpm lint         # lint
pnpm test         # test
pnpm build        # build
```

## Documentation

- **[CLAUDE.md](CLAUDE.md)** — Architecture, configuration, implementation details
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Contributor guidelines
- **[SECURITY.md](SECURITY.md)** — Security policy, threat model

## License

MIT
