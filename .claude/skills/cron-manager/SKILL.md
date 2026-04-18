---
name: cron-manager
description: Use when the user wants to create, inspect, update, or remove telclaude scheduled jobs, especially natural-language schedules like "every weekday at 9am". Prefer this skill for cron CRUD behind WRITE_LOCAL+.
---

# Cron Manager

Use the telclaude maintenance cron CLI for scheduled-job CRUD.

## Read

List jobs with machine-readable output first:

```bash
pnpm dev maintenance cron list --all --json
```

Use `pnpm dev maintenance cron status --json` when you need scheduler state or next-run data.

## Create

Choose exactly one schedule flag:

- `--at <iso>`
- `--every <duration>`
- `--cron "<minute hour day month weekday>"`

Choose exactly one action:

- `--social [serviceId]`
- `--private`
- `--prompt "<user-facing task>"`

Delivery targets:

- `--delivery origin`
- `--delivery home --owner <ownerId>`
- `--delivery chat --chat-id <chatId> [--thread-id <threadId>]`

Examples:

```bash
pnpm dev maintenance cron add \
  --name "weekday-hn" \
  --cron "0 9 * * 1-5" \
  --prompt "Check Hacker News and post a short summary here." \
  --delivery home \
  --owner admin \
  --json
```

```bash
pnpm dev maintenance cron add \
  --name "team-digest" \
  --cron "30 14 * * 1-5" \
  --prompt "Summarize open background jobs for the team." \
  --delivery chat \
  --chat-id 123456789 \
  --thread-id 42 \
  --json
```

## Update / Delete

- Enable: `pnpm dev maintenance cron enable <id>`
- Disable: `pnpm dev maintenance cron disable <id>`
- Remove: `pnpm dev maintenance cron remove <id>`
- Run now: `pnpm dev maintenance cron run <id>`

## Telegram-specific notes

- `/sethome` persists the delivery destination for `--delivery home`.
- If the system prompt includes `identity: <localUserId> (linked)`, use that as `--owner`.
- If the chat is unlinked, use `tg:<chatId>` as the owner id.
- Cron expressions are UTC. Be explicit about that when translating natural-language schedules.
