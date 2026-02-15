# Configuration Examples

Copy one of these to `~/.telclaude/telclaude.json` and customize.

## Files

| File | Use case |
|------|----------|
| `minimal.json5` | Quickest way to start; defaults handle security |
| `personal.json5` | Single trusted user with write access |
| `team.json5` | Multiple users with different permission levels |

## Key concepts

**Permission tiers** control what Claude can do:
- `READ_ONLY` — Read files, search, web access. No writes.
- `WRITE_LOCAL` — Adds write/edit/bash. Blocks destructive commands (rm, chmod, etc).
- `SOCIAL` — File tools + bash + web access, with trust-gated bash and protected paths. Used by social agents.
- `FULL_ACCESS` — All tools. Requires human approval for each request.

**Security profiles** control which layers are active:
- `simple` (default) — Sandbox + secret filter + rate limits + audit.
- `strict` — Adds Haiku observer and approval workflow.

**Group guardrail** (optional):
- `telegram.groupChat.requireMention: true` to ignore group/supergroup messages unless they mention the bot or reply to it.

**User IDs** use the format `tg:<telegram-user-id>` (e.g., `tg:123456789`).

## Finding your Telegram IDs

1. Message [@userinfobot](https://t.me/userinfobot) to get your user ID
2. For group chats: add the bot, then check logs or use `/chatid` if you add that command

## Defaults

Everything not specified uses secure defaults:
- `defaultTier`: `READ_ONLY`
- `profile`: `simple`
- Rate limits: 10/min, 60/hour per user
- Audit: enabled
- Secret filter: enabled with entropy detection

See the main `README.md` for all options, or `src/config/config.ts` for the full schema.
