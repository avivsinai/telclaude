# Telclaude Agent Playbook

@docs/architecture.md

## Intent
- Status: alpha (0.x); breaking changes allowed until 1.0.
- Goal: keep this file lean for project memory; use imports for depth.

## Ground rules
- Write clean TypeScript; remove dead code.
- Use `@anthropic-ai/claude-agent-sdk` (no CLI spawning).
- Skills live under `.claude/skills/` and auto-load from repo root.

## Security essentials
- Permission tiers
  - `READ_ONLY`: tools Read/Glob/Grep/WebFetch/WebSearch; no writes.
  - `WRITE_LOCAL`: +Write/Edit/Bash; blocks destructive patterns; accident guard only.
  - `FULL_ACCESS`: all tools; human approval required unless user is claimed admin.
  - `SOCIAL`: file tools + Bash + WebFetch/WebSearch; Bash trust-gated (operator/autonomous/proactive only); WebFetch permissive (public internet, RFC1918/metadata blocked); Write/Edit blocked to skills/auth/memory paths.
- Approvals: required for FULL_ACCESS (non-admin), BLOCK classifications, WARN+WRITE_LOCAL; TTL 5 minutes.
- Infrastructure secrets are non-overridable blocks.
- Secret filter: CORE patterns + entropy; output is redacted streamingly.
- **Settings isolation**: `settingSources: ["project"]` prevents disableAllHooks bypass.
- **PreToolUse hooks**: PRIMARY enforcement; run unconditionally, even in acceptEdits mode.
- **canUseTool**: FALLBACK only; runs only when a permission prompt would appear (so not for auto-approved calls in acceptEdits mode).
- **Skill allowlisting**: SOCIAL tier requires explicit `allowedSkills` when `enableSkills` is true; omitting fail-closes (denies all Skill calls). Non-SOCIAL tiers are unaffected. Enforced by PreToolUse hook (primary) + canUseTool (fallback).
- Network: PreToolUse hook blocks RFC1918/metadata (including CGNAT 100.64.0.0/10 for Tailscale); Bash uses SDK sandbox (native) or Docker firewall; WebSearch not filtered (server-side). `TELCLAUDE_NETWORK_MODE=open|permissive` broadens WebFetch egress.
- Profiles: simple (default, rate limits + audit), strict (+observer + approvals + tier enforcement), test (all disabled, requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`).

## SDK References (authoritative)
- **Permissions**: https://code.claude.com/docs/en/sdk/sdk-permissions
  - canUseTool fires ONLY when a permission prompt would appear (so not for auto-approved calls in acceptEdits mode)
  - Use PreToolUse hooks for guaranteed enforcement
- **Hooks**: https://docs.claude.com/en/docs/claude-code/hooks
  - Response format: `{ hookSpecificOutput: { permissionDecision: "deny", permissionDecisionReason: "..." } }`
  - Deprecated: `decision: "block"` (maps to `permissionDecision: "deny"`)
- **Sandboxing**: https://www.anthropic.com/engineering/claude-code-sandboxing
  - "Effective sandboxing requires both filesystem and network isolation"
  - ONE isolation boundary recommended (Docker container OR SDK sandbox, not both)

## Workflow
1) Plan → propose files to touch.
2) Use `apply_patch` for small diffs; keep edits minimal.
3) Run checks: `pnpm typecheck`, `pnpm lint`, `pnpm test`.
4) Summarize changes and call out risks/todos.
5) Ask before destructive ops.

## Repo map
- `src/security/` — pipeline, permissions, observer, approvals, rate limits, output filter, streaming redactor.
- `src/sandbox/` — mode detection, constants, SDK settings builder.
- `src/sdk/` — Claude SDK integration, session manager, message guards.
- `src/relay/` — Anthropic proxy, HTTP credential proxy, git proxy, provider proxy, token manager, capabilities.
- `src/agent/` — agent server/client, memory client, token client.
- `src/services/` — dual-mode service layer (memory, summarize, image-gen, TTS, transcription, git credentials, video processing).
- `src/telegram/` — inbound/outbound bot, mention/command gating, streaming state machine.
- `src/cron/` — cron scheduler, SQLite job store, schedule parsing.
- `src/social/` — social services: handler, scheduler, identity, context, activity log.
- `src/social/backends/` — per-service API clients (moltbook, xtwitter).
- `src/oauth/` — OAuth2 PKCE flow, service registry.
- `src/providers/` — external provider integration, health, validation, skill injection.
- `src/google-services/` — Google Services sidecar (Gmail, Calendar, Drive, Contacts); Fastify REST server with approval-gated actions.
- `src/vault-daemon/` — credential vault daemon.
- `src/totp-daemon/` — TOTP daemon; `src/totp-client/` — client.
- `src/secrets/` — keychain integration.
- `src/memory/` — memory subsystem.
- `src/media/` — media store.
- `src/storage/` — SQLite storage layer.
- `src/config/` — configuration loading.
- `src/auto-reply/` — auto-reply templating.
- `src/infra/` — infrastructure utilities (network errors, retry, timeout, unhandled rejections).
- `src/commands/` — CLI commands; `src/cli/` — CLI program entry.
- `.claude/skills/` — security-gate, telegram-reply, image-generator, text-to-speech, browser-automation, integration-test, memory, summarize, external-provider, social-posting.
- `docs/architecture.md` — design rationale & security invariants.
- `docs/soul.md` — agent identity (personality, voice, interests); injected into both personas.
- `docs/providers.md` — provider integration guide (sidecar pattern, adding new providers).
- `docker/` — container stack.

## Common commands

| Command | Description |
|---------|-------------|
| `pnpm install` | Install dependencies |
| `pnpm dev relay --profile simple` | Start relay (dev mode) |
| `pnpm dev totp-daemon` | Start TOTP daemon |
| `pnpm dev doctor --network --secrets` | Health check |
| `pnpm lint` / `pnpm format` | Lint and format |
| `pnpm typecheck` | Type check |
| `pnpm test` | Run tests |
| `pnpm dev integration-test --all` | Integration tests |
| `pnpm dev memory read --categories profile,interests` | Read memory entries |
| `pnpm dev memory write "fact" --category meta` | Write memory entry |
| `pnpm dev memory quarantine "post idea"` | Quarantine post idea |
| `pnpm dev oauth authorize xtwitter` | OAuth authorize |
| `pnpm dev oauth list` / `pnpm dev oauth revoke xtwitter` | OAuth list / revoke |
| `pnpm dev keygen <scope>` | Generate Ed25519 RPC keypair (`{SCOPE}_RPC_AGENT_*` / `{SCOPE}_RPC_RELAY_*`) |
| `pnpm dev cron status` | Cron scheduler status |
| `pnpm dev cron list [--all] [--json]` | List cron jobs |
| `pnpm dev cron add --name <n> --every <dur>\|--cron <expr>\|--at <iso> --social\|--private` | Add cron job |
| `pnpm dev cron run <id>` | Run cron job immediately |
| `pnpm dev sessions [--active <min>] [--json]` | List active sessions |
| `pnpm dev setup-google` | Configure Google OAuth credentials |

## Auth & control plane

- `allowedChats` must include the chat before first DM.
- First admin claim (private chat): bot replies with `/approve CODE`; send it back to become admin.
- Emergency controls (CLI-only): `telclaude ban`, `telclaude unban`, `telclaude force-reauth`.

### Telegram commands

| Command | Description |
|---------|-------------|
| `/link <code>` / `/unlink` | Identity linking (code generated via CLI) |
| `/approve <nonce>` / `/deny <nonce>` | Approval workflow (TTL 5 minutes) |
| `/setup-2fa` / `/verify-2fa <code>` | TOTP setup and verification |
| `/2fa-logout` / `/disable-2fa` | TOTP session / permanent disable |
| `/pending` | List quarantined post ideas |
| `/promote <id>` | Approve quarantined idea for social posting |
| `/public-log [serviceId] [hours]` | Metadata-only summary of social actions |
| `/ask-public <question>` | Query social persona (routed through relay) |

### Scheduler config
- Private heartbeat: `telegram.heartbeat.enabled`, `intervalHours` (default 6), WRITE_LOCAL tier, `notifyOnActivity` (default true).
- Cron scheduler: `cron.enabled` (default true), `pollIntervalSeconds` (default 15), `timeoutSeconds` (default 900). Cron jobs and interval heartbeats are mutually exclusive per target.

## Tier-based key exposure
API keys (OpenAI, GitHub) are exposed for FULL_ACCESS tier only. READ_ONLY and WRITE_LOCAL never get keys. Configure via `setup-openai`/`setup-git` or env vars.

## Troubleshooting
- Bot silent: confirm `allowedChats`, rate limits, and observer not blocking.
- TOTP failing: ensure daemon running and device time synced.
- SDK errors: `claude` CLI installed and `claude login` performed.

## Docker notes
- **Node version**: Docker images use `node:22-bookworm-slim`.
- **5 images**: `telclaude:latest` (relay), `telclaude-agent:latest` (agents + Chromium), `telclaude-google-services:latest` (Google sidecar), `telclaude-totp:latest`, `telclaude-vault:latest`.
- **6 containers**: `telclaude` (relay), `telclaude-agent` (private persona), `agent-social` (social persona), `google-services`, `totp`, `vault`.
- **Secrets storage**: `telclaude setup-openai`, `telclaude setup-git`; encrypted in volume.
- **Workspace path**: `WORKSPACE_PATH` in `docker/.env` must point to valid host path.
- **Claude profiles**: Docker uses a shared skills profile (`/home/telclaude-skills`) and a relay-only auth profile (`/home/telclaude-auth`). Anthropic access goes through the relay proxy; credentials never mount in agent containers.
- **Weak local servers**: Build locally and transfer images instead of building on device:
  ```bash
  cd docker && docker compose build
  docker save telclaude:latest telclaude-agent:latest telclaude-google-services:latest telclaude-totp:latest telclaude-vault:latest \
    | ssh <server> "docker load"
  ssh <server> "cd telclaude/docker && docker compose up -d"
  ```
