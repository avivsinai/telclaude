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
  - `WRITE_SAFE`: +Write/Edit/Bash; blocks destructive/dangerous patterns (rm/rmdir/mv/chmod/chown/kill/ sudo/su/bash -c rm, curl|sh, netcat, git hooks, path redirects); accident guard only.  
  - `FULL_ACCESS`: all tools; human approval required unless user is claimed admin.  
- Approvals: required for FULL_ACCESS (non-admin), BLOCK classifications, WARN+WRITE_SAFE, and low-confidence WARN; TTL 5 minutes.  
- Infrastructure secrets (bot tokens, Anthropic keys, private keys) are non-overridable blocks.  
- Secret filter: CORE patterns + entropy; output is redacted streamingly.  
- Sandbox enforcement: tier-aligned writes (READ_ONLY none; others = cwd + `~/.telclaude/sandbox-tmp`), deny-read of `~/.ssh`, `~/.aws`, `~/.telclaude`, shell histories, host `/tmp`/`/var/tmp`/`/run/user`; private temp at `~/.telclaude/sandbox-tmp`. Network default allowlist (npm/pypi/docs/github/Anthropic API); metadata + RFC1918 always blocked; `TELCLAUDE_NETWORK_MODE=open|permissive` enables `*`.  
- Wrapper: `srt` sandboxes all Claude tools; if it fails, relay falls back to Bash-only sandbox and logs a warning.

## Workflow (Opus 4.5 friendly)
1) Plan → propose files to touch.  
2) Use `apply_patch` for small diffs; keep edits minimal.  
3) Run checks when relevant: `pnpm typecheck`, `pnpm lint`, `pnpm test`, `pnpm dev doctor --network --secrets`.  
4) Summarize changes and call out risks/todos.  
5) Ask before destructive ops or config resets.

## Repo map (hot paths)
- `src/security/` — pipeline, permissions, observer, approvals, rate limits, output filter.  
- `src/sandbox/` — sandbox configs, env allowlist, wrapper, network proxy.  
- `src/sdk/` — Claude SDK wrapper, session manager (30 min resume).  
- `src/telegram/` — inbound/outbound bot.  
- `src/commands/` — CLI commands.  
- `.claude/skills/` — security-gate, telegram-reply skills.  
- `docs/architecture.md` — deep architecture & flow.  
- `docker/` — container stack and hardening.

## Common commands
- Install: `pnpm install`  
- Dev relay: `pnpm dev relay --profile strict`  
- TOTP daemon: `pnpm dev totp-daemon`  
- Doctor: `pnpm dev doctor --network --secrets`  
- Lint/format: `pnpm lint`, `pnpm format`  
- Typecheck: `pnpm typecheck`  
- Tests: `pnpm test`

## Auth & control plane
- `allowedChats` must include the chat before first DM.  
- First admin claim (private chat): bot replies with `/approve CODE`; send it back to become admin.  
- Identity linking: `/link <code>` (generated via CLI) and `/unlink`.  
- Approvals: `/approve <code>` or `/deny <code>`; only one pending per chat; TTL 5 minutes.  
- TOTP: start daemon, `/setup-2fa`, then `/verify-2fa <code>`; `/disable-2fa` to remove.

## Sandbox notes
- Linux globs expanded once at startup; new matching files after init are not auto-blocked.  
- Host `/tmp` is denied; use `~/.telclaude/sandbox-tmp` (set via TMPDIR).  
- Network method/port restrictions are policy-only; domain allowlist + private/metadata blocks are enforced.

## Troubleshooting (quick)
- Sandbox unavailable: install bubblewrap/socat/rg (Linux) or ensure Seatbelt + rg (macOS); rerun relay.  
- Bot silent: confirm `allowedChats`, rate limits, and observer not blocking (see audit).  
- TOTP failing: ensure daemon running and device time synced.  
- SDK errors: `claude` CLI installed and `claude login` performed.

