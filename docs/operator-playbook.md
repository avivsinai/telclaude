# Telclaude Operator Playbook

How to run telclaude as an operator-control surface for a personal Claude agent. Operational guide; for the security model see `docs/architecture.md`, for project conventions see `CLAUDE.md`.

## Framing

Telclaude is the secure Telegram-bridged operator-control surface for a personal Claude agent. The relay holds secrets and enforces tiers; the vault sidecar holds credentials and signs approval tokens; private and social personas are air-gapped at the memory boundary; recurring work is driven by the cron scheduler and signed webhooks. As an operator you live mostly on Telegram and only drop into the CLI for setup, surgery, and emergency controls.

## Maturity ladder

Four levels. Each level is additive; you never lose the previous level's controls.

### Level 1 — Single chat, default profile

One Telegram chat in `telegram.allowedChats`, one user in `security.permissions.users`, no `profiles[]` configured. The implicit `default` profile is in force for every chat (`src/config/profiles.ts:IMPLICIT_DEFAULT_PROFILE_ID`). Private memory is sourced from `telegram` with no profile suffix. Soul overlay is whatever `docs/soul.md` already provides through the SDK system prompt.

Cron is optional at this level; the private heartbeat (`telegram.heartbeat.intervalHours`) plus the curator's local scan are usually enough.

### Level 2 — Multiple operator profiles

Declare `profiles[]` in `telclaude.json` and switch between them on a per-chat basis from Telegram:

```
/profile list
/profile show
/profile switch engineer
```

Profile config (`src/config/config.ts:OperatorProfileConfigSchema`):

```jsonc
{
  "profiles": [
    {
      "id": "engineer",
      "label": "Engineer",
      "description": "Repo-focused build/debug mode",
      "soulPath": "docs/soul-engineer.md",
      "allowedSkills": ["telegram-reply", "summarize", "browser-automation"],
      "defaultModel": { "providerId": "anthropic", "modelId": "claude-opus-4-7" }
    },
    {
      "id": "homeops",
      "label": "HomeOps",
      "soulPath": "docs/soul-homeops.md",
      "allowedSkills": ["telegram-reply", "weather", "external-provider"]
    }
  ]
}
```

What a profile binds:

- `soulPath` — extra soul overlay layered on top of `docs/soul.md`. Must resolve inside the repo root (`validateProfileSoulPaths` in `src/config/config.ts`).
- `allowedSkills` — narrows the private-agent skill set. Omit for "all private skills", set to `[]` for "no skills".
- `defaultModel` — applied to private chats unless a per-chat `/model` preference is set (`src/config/model-preferences.ts`).
- Memory source — `telegram:<profile-id>`. Reads, writes, episodic captures, and scheduled private runs use that scoped source. Switching profiles switches what memory the agent sees.

Per-chat binding lives in the chat sessions table (`src/config/profiles.ts:resolveChatProfile`). It survives restarts; `/profile switch` rebinds, no `reset` subcommand — switch to `default` to drop back.

Memory reads must be profile-scoped from the CLI too:

```
pnpm dev memory read --chat-id <id> --categories profile,interests
```

### Level 3 — Profiles plus cron

Once a profile shape is stable, hang recurring work off it via the cron scheduler (`src/cron/`). Cron jobs run with a fixed action and a delivery target, decoupled from any live chat:

```
pnpm dev maintenance cron add \
  --name daily-brief \
  --cron "30 7 * * *" \
  --prompt "Summarise overnight repo activity and email queue" \
  --skill summarize --skill telegram-reply \
  --delivery chat --chat-id <chat-id>
pnpm dev maintenance cron list
pnpm dev maintenance cron run <id>
pnpm dev maintenance cron status
```

Schedule shapes (mutually exclusive): `--at <iso>` for one-shot, `--every <duration>` for fixed interval, `--cron <expr>` for 5-field UTC cron. Delivery targets: `origin`, `home`, or `chat` (`src/commands/cron.ts`).

Cron actions cover `--private`, `--social [serviceId]`, `--curator-scan`, and `--prompt <text>`. Scheduled `--prompt` runs honour the profile bound to the delivery chat (so `defaultModel`, `soulPath`, and memory source apply).

Cron jobs and the legacy interval heartbeat are mutually exclusive per target — pick one or the other.

### Level 4 — Cron, signed webhooks, and a Codex peer

External systems trigger cron jobs over a localhost-only signed webhook receiver (`src/webhooks/server.ts`). Operators register a webhook against a preconfigured cron job, with HMAC, CIDR allowlist, and per-webhook rate limit:

```
echo -n "$WEBHOOK_SECRET" | pnpm dev maintenance webhooks add \
  --slug daily-brief \
  --target-cron-job <cron-job-id> \
  --secret-stdin \
  --allowed-cidrs 127.0.0.1/32 \
  --rate-limit-per-hour 12 \
  --enabled
pnpm dev maintenance webhooks list
```

The receiver requires a loopback `Host`, valid signature in the `X-Webhook-Signature` header, and the target cron job to be enabled; otherwise it fails closed (`src/webhooks/auth.ts`, `src/webhooks/policy.ts`, `src/webhooks/server.ts`).

Codex is the delegated work-unit peer (`src/agent-runtime/codex-work-unit.ts`, `.claude/skills/codex-work-unit/SKILL.md`). From Telegram:

```
/codex --model gpt-5.4 --cwd src/cron --write Audit cron actions for missing tier checks
```

Defaults: read-only sandbox, no `--write` without FULL_ACCESS, blocked entirely for SOCIAL chats, `--cwd` confined to the workspace, model must be in `CODEX_EXECUTABLE_MODELS`. Results land as background-job cards; treat them as untrusted data per the skill instructions.

At this level the operator stops starting most tasks manually — cron and webhooks push work into the chat, Codex absorbs bounded delegations, and Telegram is mostly a review surface.

## Control room vs runtime

Two distinct surfaces. Don't conflate them.

**Control room** — the git repo. Operator edits go here:

- `telclaude.json` — policy: providers, security profile, network, observer, rate limits, SDK config, cron defaults, `profiles[]`.
- `telclaude-private.json` — PII: `telegram.allowedChats`, `security.permissions.users`, social admin chats. Relay-only, merged via `TELCLAUDE_PRIVATE_CONFIG`.
- `docs/soul.md` plus any profile-specific `soul-*.md` files referenced by `soulPath`.
- `.claude/skills/` and `.agents/skills/` — user-authored skill source.

**Runtime** — `~/.telclaude/` on host (or the mounted data dir inside Docker, see `src/utils.ts:CONFIG_DIR`):

- SQLite stores: cards, cron jobs, webhooks, curator queue, sessions, audit logs, skill telemetry, JTI replay table.
- Snapshots from `skill-manage` operations (`.telclaude-managed.json` metadata + tarball snapshots).
- Vault encrypted credential file, vault Unix socket.
- Generated `MEMORY.md` materialised into Claude's project memory path immediately before each query.

Docker volumes mirror this split: per-agent profile volumes, vault-socket tmpfs, shared standalone skill catalog.

Operators edit the control room and deploy; telclaude consumes. Never edit runtime SQLite or vault files by hand.

## Prototype to production for cron jobs

Move workflows up this ladder one rung at a time.

1. **Chat prototype.** Spin the workflow up by talking to the agent in the active profile. Iterate on the prompt and what integrations it needs (skills, providers, memory categories).
2. **One-shot scheduled job.** Once the prompt is stable, freeze it as a one-shot:

   ```
   pnpm dev maintenance cron add --name brief-test \
     --at 2026-05-17T07:30:00Z \
     --prompt "<frozen prompt>" \
     --skill summarize --skill telegram-reply \
     --delivery chat --chat-id <id>
   ```
3. **Recurring.** Promote to `--every` or `--cron`. Use `pnpm dev maintenance cron run <id>` to dry-run before the next scheduled tick.
4. **Profile graduation.** If the workflow needs a persistent identity (different soul, narrower `allowedSkills`, a specific `defaultModel`), promote it from a free-standing cron prompt into a named profile and bind the delivery chat to that profile before re-running. The cron job stays the same shape; the persona around it changes.

If the workflow needs an external trigger, attach a signed webhook in step 3 instead of waiting for the cron tick.

## Interaction modes

Three ways telclaude receives work:

1. **Direct chat.** Whatever profile is currently bound to the chat answers. Tier, allowed skills, soul overlay, default model all come from that profile.
2. **`/profile switch <id>`.** Rebinds the chat. Subsequent messages, including async cards landing in the chat, use the new profile.
3. **Cron + webhooks.** Asynchronous delivery. Results show up as cards in the configured `--delivery` target. The card lifecycle (revision counter, callback ACK, liveness re-check) is the source of truth, not in-flight memory — see `docs/architecture.md`'s "Telegram Cards" section.

The curator inbox (`/curator`, `src/commands/curator.ts`) sits across all three: it collects local suggestions (unused skills, cron hardening, background attention, memory queue) and lets the operator accept or reject them. Signed producer items from peer agents (`claude-code`, `codex`) flow through `curator sign-producer` and `curator submit-signed`.

## Workflow recipes

Concrete cron-job invocations operators can copy-paste. TODO stubs — fill in once the real prompts settle.

### Daily brief

TODO. Sketch: `--cron "30 7 * * *"`, `--prompt "Summarise overnight activity"`, `--skill summarize --skill telegram-reply`, `--delivery chat --chat-id <ops-chat>`. Decide whether to bind the chat to a `morning` profile first.

### Meeting prep

TODO. Sketch: `--every 1h` during business hours via `--cron "0 9-17 * * 1-5"`, `--prompt` pulling Google Calendar agenda for the next two hours, requires `setup-google` and the Google provider, plus the `external-provider` skill in `allowedSkills`.

### Weekly report

TODO. Sketch: `--cron "0 16 * * 5"`, `--prompt` aggregating Codex work-unit results and curator decisions from the week, `--delivery chat --chat-id <ops-chat>`. Probably wants a `researcher` profile with its own memory.

Each recipe will note: required profile config, required providers, required skills, expected runtime, and whether a webhook trigger is appropriate.

## Security stays on at every level

Levels 1 through 4 add capability, not authority. The vault still gates credentials, approval tokens still bind writes to a specific request, persona memory air-gap still keeps social timeline content out of the private agent. No level skips security — see `docs/architecture.md` for the invariants.
