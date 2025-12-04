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

**First-time setup:** Send a message to your bot in a private chat. You'll be prompted to confirm admin claim with `/approve <code>`. TOTP setup is recommended.

⚠️ **Allowlist required:** The bot ignores *all* chats unless their IDs are listed in `telegram.allowedChats`. Add your own chat ID before first contact (e.g., ask `@userinfobot` for your ID) or the bot will not reply and admin claim will never start. This is intentional to prevent unsolicited access.

## Configuration

Config: `~/.telclaude/telclaude.json`

```json
{
  "telegram": { "allowedChats": [] },
  "security": {
    "profile": "simple"
  }
}
```

**Security profiles:**
- `simple` (default): Hard enforcement only (sandbox, secret filter, rate limits)
- `strict`: Adds observer + approvals + permission tiers
- `test`: No security (testing only)

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
- **[docker/README.md](docker/README.md)** — Docker deployment guide
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Contributor guidelines
- **[SECURITY.md](SECURITY.md)** — Security policy, threat model

## License

MIT
