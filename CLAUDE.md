# Telclaude Agent Playbook

@docs/architecture.md

## Intent
- Status: alpha (0.1.x); breaking changes allowed until 1.0.
- Goal: keep this file lean for Opus 4.5 project memory; use imports for depth.

## Ground rules
- Write clean TypeScript; remove dead code.
- Use `@anthropic-ai/claude-agent-sdk` (no CLI spawning).
- Skills live under `.claude/skills/` and auto-load from repo root.

## Dual-Mode Architecture
- **Docker mode**: SDK sandbox disabled. Relay + agent containers provide isolation; firewall enforced in Docker.
- **Native mode**: SDK sandbox enabled. bubblewrap (Linux) or Seatbelt (macOS).
- Mode auto-detected via `/.dockerenv` or `TELCLAUDE_DOCKER=1` env var.

## Security essentials
- Permission tiers
  - `READ_ONLY`: tools Read/Glob/Grep/WebFetch/WebSearch; no writes.
  - `WRITE_LOCAL`: +Write/Edit/Bash; blocks destructive patterns; accident guard only.
  - `FULL_ACCESS`: all tools; human approval required unless user is claimed admin.
- Approvals: required for FULL_ACCESS (non-admin), BLOCK classifications, WARN+WRITE_LOCAL; TTL 5 minutes.
- Infrastructure secrets are non-overridable blocks.
- Secret filter: CORE patterns + entropy; output is redacted streamingly.
- **Settings isolation**: `settingSources: ["project"]` prevents disableAllHooks bypass.
- **PreToolUse hooks**: PRIMARY enforcement; run unconditionally, even in acceptEdits mode.
- **canUseTool**: FALLBACK only; does NOT fire in acceptEdits mode.

## SDK References (authoritative)
- **Permissions**: https://code.claude.com/docs/en/sdk/sdk-permissions
  - canUseTool fires ONLY when permission prompt would appear (NOT in acceptEdits mode)
  - Use PreToolUse hooks for guaranteed enforcement
- **Hooks**: https://docs.claude.com/en/docs/claude-code/hooks
  - Response format: `{ hookSpecificOutput: { permissionDecision: "deny", permissionDecisionReason: "..." } }`
  - Deprecated: `decision: "block"` (maps to `permissionDecision: "deny"`)
- **Sandboxing**: https://www.anthropic.com/engineering/claude-code-sandboxing
  - "Effective sandboxing requires both filesystem and network isolation"
  - ONE isolation boundary recommended (Docker container OR SDK sandbox, not both)

## Network enforcement
- **Bash**: SDK sandbox `allowedDomains` (native mode); Docker network (container mode).
- **WebFetch**: PreToolUse hook blocks RFC1918/metadata unconditionally.
- **WebSearch**: NOT filtered (server-side by Anthropic).
- `TELCLAUDE_NETWORK_MODE=open|permissive`: broad egress for WebFetch only.

## Workflow
1) Plan → propose files to touch.
2) Use `apply_patch` for small diffs; keep edits minimal.
3) Run checks: `pnpm typecheck`, `pnpm lint`, `pnpm test`.
4) Summarize changes and call out risks/todos.
5) Ask before destructive ops.

## Repo map
- `src/security/` — pipeline, permissions, observer, approvals, rate limits, output filter.
- `src/sandbox/` — mode detection, constants, SDK settings builder.
- `src/sdk/` — Claude SDK integration, session manager.
- `src/telegram/` — inbound/outbound bot.
- `src/commands/` — CLI commands.
- `.claude/skills/` — security-gate, telegram-reply, image-generator skills.
- `docs/architecture.md` — deep architecture & flow.
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

## Auth & control plane
- `allowedChats` must include the chat before first DM.
- First admin claim (private chat): bot replies with `/approve CODE`; send it back to become admin.
- Identity linking: `/link <code>` (generated via CLI) and `/unlink`.
- Approvals: `/approve <nonce>` or `/deny <nonce>`; TTL 5 minutes.
- TOTP: `/setup-2fa`, `/verify-2fa <code>`, `/2fa-logout`, `/disable-2fa`.
- Emergency controls (CLI-only): `telclaude ban`, `telclaude unban`, `telclaude force-reauth`.

## Tier-based key exposure
API keys (OpenAI, GitHub) are exposed for FULL_ACCESS tier only. READ_ONLY and WRITE_LOCAL never get keys. Configure via `setup-openai`/`setup-git` or env vars.

## Troubleshooting
- Bot silent: confirm `allowedChats`, rate limits, and observer not blocking.
- TOTP failing: ensure daemon running and device time synced.
- SDK errors: `claude` CLI installed and `claude login` performed.

## Docker notes
- **Node version**: Docker images use `node:22-bookworm-slim`.
- **Secrets storage**: `telclaude setup-openai`, `telclaude setup-git`; encrypted in volume.
- **Workspace path**: `WORKSPACE_PATH` in `docker/.env` must point to valid host path.
- **Weak local servers**: Build locally and transfer images instead of building on device:
  ```bash
  cd docker && docker compose build
  docker save telclaude:latest telclaude-totp:latest | ssh <server> "docker load"
  ssh <server> "cd telclaude/docker && docker compose up -d"
  ```
