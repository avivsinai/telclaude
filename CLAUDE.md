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
- `src/vault-daemon/` — credential vault daemon.
- `src/totp-daemon/` — TOTP daemon; `src/totp-client/` — client.
- `src/secrets/` — keychain integration.
- `src/memory/` — memory subsystem.
- `src/media/` — media store.
- `src/storage/` — SQLite storage layer.
- `src/config/` — configuration loading.
- `src/commands/` — CLI commands; `src/cli/` — CLI program entry.
- `.claude/skills/` — security-gate, telegram-reply, image-generator, text-to-speech, browser-automation, integration-test, memory, summarize, external-provider.
- `docs/architecture.md` — design rationale & security invariants.
- `docs/soul.md` — agent identity (personality, voice, interests); injected into both personas.
- `docker/` — container stack.

## Common commands
- Install: `pnpm install`
- Dev relay: `pnpm dev relay --profile simple`
- TOTP daemon: `pnpm dev totp-daemon`
- Doctor: `pnpm dev doctor --network --secrets`
- Lint/format: `pnpm lint`, `pnpm format`
- Typecheck: `pnpm typecheck`
- Tests: `pnpm test`
- Integration test: `pnpm dev integration-test --all`
- Memory read: `pnpm dev memory read --categories profile,interests`
- Memory write: `pnpm dev memory write "fact" --category meta`
- Memory quarantine: `pnpm dev memory quarantine "post idea"`
- OAuth authorize: `pnpm dev oauth authorize xtwitter`
- OAuth list: `pnpm dev oauth list`
- OAuth revoke: `pnpm dev oauth revoke xtwitter`
- RPC keygen: `pnpm dev keygen <scope>` (generates Ed25519 keypair; env vars: `{SCOPE}_RPC_AGENT_*` / `{SCOPE}_RPC_RELAY_*`)
- Cron status: `pnpm dev cron status`
- Cron list: `pnpm dev cron list [--all] [--json]`
- Cron add: `pnpm dev cron add --name <n> --every <dur>|--cron <expr>|--at <iso> --social|--private`
- Cron run: `pnpm dev cron run <id>`
- Sessions: `pnpm dev sessions [--active <min>] [--json]`

## Auth & control plane
- `allowedChats` must include the chat before first DM.
- First admin claim (private chat): bot replies with `/approve CODE`; send it back to become admin.
- Identity linking: `/link <code>` (generated via CLI) and `/unlink`.
- Approvals: `/approve <nonce>` or `/deny <nonce>`; TTL 5 minutes.
- TOTP: `/setup-2fa`, `/verify-2fa <code>`, `/2fa-logout`, `/disable-2fa`.
- Emergency controls (CLI-only): `telclaude ban`, `telclaude unban`, `telclaude force-reauth`.
- Pending posts: `/pending` (list quarantined post ideas).
- Promote post: `/promote <id>` (approve quarantined idea for social service posting).
- Public activity log: `/public-log [serviceId] [hours]` (metadata-only summary of social actions).
- Ask public persona: `/ask-public <question>` (routed to social agent, response piped through relay).
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
- **4 images**: `telclaude:latest` (relay), `telclaude-agent:latest` (agents + Chromium), `telclaude-totp:latest`, `telclaude-vault:latest`.
- **5 containers**: `telclaude` (relay), `telclaude-agent` (private persona), `agent-social` (social persona), `totp`, `vault`.
- **Secrets storage**: `telclaude setup-openai`, `telclaude setup-git`; encrypted in volume.
- **Workspace path**: `WORKSPACE_PATH` in `docker/.env` must point to valid host path.
- **Claude profiles**: Docker uses a shared skills profile (`/home/telclaude-skills`) and a relay-only auth profile (`/home/telclaude-auth`). Anthropic access goes through the relay proxy; credentials never mount in agent containers.
- **Weak local servers**: Build locally and transfer images instead of building on device:
  ```bash
  cd docker && docker compose build
  docker save telclaude:latest telclaude-agent:latest telclaude-totp:latest telclaude-vault:latest \
    | ssh <server> "docker load"
  ssh <server> "cd telclaude/docker && docker compose up -d"
  ```
