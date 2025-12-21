# Telclaude Agent Playbook

@docs/architecture.md

## Intent
- Status: alpha (0.1.x); breaking changes allowed until 1.0.
- Sandbox is mandatory; relay aborts if Seatbelt/bubblewrap unavailable.
- Goal: keep this file lean for Opus 4.5 project memory; use imports for depth.

## Ground rules
- No backward compatibility shims or migrations.
- Write clean TypeScript; remove dead code.
- Use `@anthropic-ai/claude-agent-sdk` (no CLI spawning).
- Skills live under `.claude/skills/` and auto-load from repo root.

## Security essentials (policy vs enforcement)
- Permission tiers  
  - `READ_ONLY`: tools Read/Glob/Grep/WebFetch/WebSearch; no writes.  
  - `WRITE_LOCAL`: +Write/Edit/Bash; blocks destructive/dangerous patterns (rm/rmdir/mv/chmod/chown/kill/ sudo/su/bash -c rm, curl|sh, netcat, git hooks, path redirects); accident guard only.  
  - `FULL_ACCESS`: all tools; human approval required unless user is claimed admin.  
- Approvals: required for FULL_ACCESS (non-admin), BLOCK classifications, WARN+WRITE_LOCAL, and low-confidence WARN; TTL 5 minutes.  
- Infrastructure secrets (bot tokens, Anthropic keys, private keys) are non-overridable blocks.  
- Secret filter: CORE patterns + entropy; output is redacted streamingly.  
- Sandbox enforcement: tier-aligned writes (READ_ONLY none; others = cwd + `~/.telclaude/sandbox-tmp`), deny-read of `~/.ssh`, `~/.aws`, `~/.telclaude`, shell histories, host `/tmp`/`/var/tmp`/`/run/user`; private temp at `~/.telclaude/sandbox-tmp`.
- Network enforcement:
  - **Bash**: SDK sandbox `allowedDomains` (OS-level, strict allowlist always)
  - **WebFetch**: PreToolUse hook (cannot be bypassed) + `canUseTool` fallback.
  - **WebSearch**: NOT filtered. Uses `query` parameter (not `url`); requests made server-side by Anthropic.
- `TELCLAUDE_NETWORK_MODE=open|permissive`: enables broad egress for WebFetch only. Private/metadata always blocked.
- **Settings isolation**: Only project settings loaded (`settingSources: ["project"]`); user settings ignored. Writes to `.claude/settings*.json` blocked via sensitive paths. This prevents `disableAllHooks` bypass attacks.

## Workflow (Opus 4.5 friendly)
1) Plan → propose files to touch.  
2) Use `apply_patch` for small diffs; keep edits minimal.  
3) Run checks when relevant: `pnpm typecheck`, `pnpm lint`, `pnpm test`, `pnpm dev doctor --network --secrets`.  
4) Summarize changes and call out risks/todos.  
5) Ask before destructive ops or config resets.

## Repo map (hot paths)
- `src/security/` — pipeline, permissions, observer, approvals, rate limits, output filter.  
- `src/sandbox/` — sandbox configs, env allowlist, network proxy.  
- `src/sdk/` — Claude SDK integration, session manager (30 min resume).  
- `src/telegram/` — inbound/outbound bot.  
- `src/commands/` — CLI commands.  
- `.claude/skills/` — security-gate, telegram-reply skills.  
- `docs/architecture.md` — deep architecture & flow.  
- `docker/` — container stack and hardening.

## Common commands
- Install: `pnpm install`
- Dev relay (native, srt sandbox): `pnpm dev relay --profile simple`
- TOTP daemon: `pnpm dev totp-daemon`
- Doctor: `pnpm dev doctor --network --secrets`
- Lint/format: `pnpm lint`, `pnpm format`
- Typecheck: `pnpm typecheck`
- Tests: `pnpm test`
- Git setup: `telclaude setup-git` (interactive), `telclaude git-test` (verify connectivity)
- SDK sandbox provides OS-level network isolation for Bash only. WebFetch uses PreToolUse hook for network enforcement (blocks RFC1918/metadata unconditionally). WebSearch is NOT filtered (server-side by Anthropic).

## Auth & control plane
- `allowedChats` must include the chat before first DM.  
- First admin claim (private chat): bot replies with `/approve CODE`; send it back to become admin. If `TELCLAUDE_ADMIN_SECRET` is set, start with `/claim <secret>` first.  
- Identity linking: `/link <code>` (generated via CLI) and `/unlink`.  
- Approvals (intent confirmation): `/approve <nonce>` or `/deny <nonce>`; nonce-based, only one pending per chat; TTL 5 minutes.
- TOTP (identity verification): periodic auth gate when session expires. Start daemon, `/setup-2fa`, then `/verify-2fa <code>`. Commands: `/2fa-logout`, `/disable-2fa`, `/force-reauth [chat-id]`.
- Emergency controls (CLI-only): `telclaude ban <chat-id>`, `telclaude unban <chat-id>`, `telclaude force-reauth <chat-id>`, `telclaude list-bans`.

## Sandbox notes
- Linux globs expanded once at startup; new matching files after init are not auto-blocked.
- Host `/tmp` is denied; use `~/.telclaude/sandbox-tmp` (set via TMPDIR).
- Network method/port restrictions are policy-only; domain allowlist + private/metadata blocks are enforced.
- **Tier-based key exposure**: API keys (OpenAI, GitHub) are automatically exposed to sandbox for WRITE_LOCAL and FULL_ACCESS tiers. READ_ONLY never gets keys. Configure via `setup-openai`/`setup-git` or env vars.

## Troubleshooting (quick)
- Sandbox unavailable: install bubblewrap/socat/rg (Linux) or ensure Seatbelt + rg (macOS); rerun relay.
- Bot silent: confirm `allowedChats`, rate limits, and observer not blocking (see audit).
- TOTP failing: ensure daemon running and device time synced.
- SDK errors: `claude` CLI installed and `claude login` performed.

## Docker notes
- **Node version**: Docker images MUST use `node:22-bookworm-slim`. Node 25+ removed corepack by default, breaking pnpm installation in Docker builds. Do not upgrade to node:25+ without adding explicit pnpm installation.
- **Secrets storage**: OpenAI key via `telclaude setup-openai`, git credentials via `telclaude setup-git`; both persist in Docker volume (`telclaude-data:/data/secrets.json`), encrypted with `SECRETS_ENCRYPTION_KEY`.
- **Git bot setup**: Create a GitHub bot account (e.g., `myproject-bot`), generate a fine-grained PAT, run `docker exec -it telclaude telclaude setup-git`. Alternatively, set `GIT_USERNAME`, `GIT_EMAIL`, `GITHUB_TOKEN` env vars.
- **Workspace path**: Ensure `WORKSPACE_PATH` in `docker/.env` points to a valid host path (not macOS paths on Linux hosts).
- **docker/.env is gitignored**: Only `.env.example` is tracked; never commit personal paths or tokens.
