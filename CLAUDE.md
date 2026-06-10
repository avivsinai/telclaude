# Telclaude Agent Playbook

@docs/architecture.md

## Intent
- Status: alpha (0.x); breaking changes allowed until 1.0.
- Goal: keep this file lean for project memory; use imports for depth.
- Hermes wrapper: all LLM/persona runtime execution is a pristine **no-fork wrapper** around upstream Hermes (pinned `nousresearch/hermes-agent`), not a fork or patch set. The relay stays the security envelope; private Telegram, social, cron, and observer work route to contained Hermes via the relay-owned MCP bridge. Hermes production readiness is all-or-nothing per workflow bundle, gated by strict parity + no-fork proof (`src/hermes/`, `telclaude hermes cutover-check`).

## Ground rules
- Write clean TypeScript; remove dead code.
- Skills live under `.claude/skills/` for Claude Code and `.agents/skills/` for Codex-compatible agents. Keep shared operator skills mirrored across both roots unless intentionally runtime-specific.
- Pristine implementation: no legacy cruft, compatibility shims, or deprecation layers. Delete old code when you replace it.
- No backward compatibility until 1.0. The user base is us. Hard-break DB migrations, API surfaces, CLI commands, config shapes, cards, directives — whatever needs to change. Document the break in the commit.

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
- Network: Hermes containment and relay MCP policy block direct provider/model/vault/metadata egress; Docker firewall enforces container egress; WebSearch is server-side. `TELCLAUDE_NETWORK_MODE=open|permissive` broadens WebFetch egress only where explicitly wired.
- Profiles: simple (default, rate limits + audit), strict (+observer + approvals + tier enforcement), test (all disabled, requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`).

## Workflow
1) Plan → propose files to touch.
2) Use `apply_patch` for small diffs; keep edits minimal.
3) Run checks: `pnpm typecheck`, `pnpm lint`, `pnpm test`.
4) Summarize changes and call out risks/todos.
5) Ask before destructive ops.

## Yoetz / ChatGPT Pro review
- Use the native Yoetz browser extension for ChatGPT Pro review when available; do not run a canary first if the extension is already connected.
- Send a fresh, full-context bundle with the actual code, artifacts, commands, and current status. Do not send stale shards or context-light excerpts.
- Ask for an open-ended review by default. Avoid steering Pro toward expected findings unless doing a narrow follow-up on a specific issue.

## Repo map
- `src/security/` — pipeline, permissions, observer, approvals, rate limits, output filter, streaming redactor, external-content (untrusted-input injection detection + risk wrapping for inbound/social/web content).
- `src/sandbox/` — Docker/native posture detection, constants, network-domain helpers, and firewall/fetch policy utilities.
- `src/relay/` — Anthropic proxy, HTTP credential proxy, git proxy, provider proxy, token manager, capabilities. Hermes additions: `openai-codex-proxy` + `openai-codex-relay-proof` (relay-mediated model route with per-request peer-bound tokens), `edge-channel-connector` / `whatsapp-edge-channel-connector` (channel layer), `outbound-delivery-dispatcher` (the only executor of an authorized `PreparedOutbound`).
- `src/services/` — relay-owned service layer (memory, summarize, image-gen, TTS, transcription, git credentials, video processing).
- `src/telegram/` — inbound/outbound bot, mention/command gating, streaming state machine.
- `src/telegram/cards/` — card system: types, SQLite store, callback tokens, lifecycle, 7 renderers.
- `src/telegram/wizard/` — wizard prompter for guided multi-step Telegram flows.
- `src/telegram/intent-router.ts` — NL intent resolution to typed domain intents.
- `src/telegram/status-reactions.ts` — emoji progress indicators (queued→thinking→tool→done/error).
- `src/telegram/directives.ts` — directive tags (@social, @reply, @silent, @card, @tts, @reaction).
- `src/telegram/typing.ts` — debounced typing indicator controller.
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
- `src/infra/` — infrastructure utilities (network errors, retry, timeout, unhandled rejections).
- `src/hermes/` — no-fork Hermes wrapper: `foundation` (artifact schemas + `evaluateCutoverCheck`), `parity-roster` (canonical parity rows + descope), `no-fork-proof` / `no-fork-attestation` (pinned-checkout-clean proof + runner attestation), `inventory`, `private-runtime` / `private-execute` / `private-runtime-control` (Hermes private dispatch and relay-observed runtime state), `api-adapter` (`HermesApiRuntimeAdapter` → contained Hermes API server), `api-server-containment`, `relay-conversation-store` / `session-map` (relay-owned conversation + session authority), `model-relay`, `approval-continuation*`, edge probes (`edge-adapter-contract` with `PreparedOutbound`/`AttachmentRef`/`DeliveryReceipt`, `edge-adapter-runtime`/`-probes`/`-attestation`), `served-mcp-*` (memory/provider/containment evidence + attestations), `skills-allowlist-*`, `network-probe*`, `provider-*-probe`, `workflow-*` / `*-ledger*` (run + side-effect ledgers), `rollback-rehearsal`, `pro-review`, `attestation-validation`.
- `src/hermes/mcp/` — relay-owned MCP bridge (NOT an agent tool allowlist): `live-server` / `live-runtime` / `live-listen` (relay-internal HTTP `/mcp`, 9 `tc_*` tools), `authority-registry` (opaque handle ↔ actor/domain/scope binding), `bridge` (per-connection request validation + dispatch), `side-effect-ledger` (+`-attestation`/`-probe`) (two-phase prepare→approve→execute for provider/outbound side effects), `approval-token` (Ed25519 one-time JTI side-effect tokens), `side-effect-human-approval`, `ledger-execute`, `provider-routing` / `provider-sidecar-token`, `live-connection-resolver` / `live-admin` / `live-probe-tokens` (connection auth + adversarial probe tokens), `policy`.
- `src/commands/` — CLI commands; `src/cli/` — CLI program entry.
- `.claude/skills/` and `.agents/skills/` — operator skills, including codex-work-unit, security-gate, telegram-reply, image-generator, text-to-speech, browser-automation, memory, summarize, external-provider, social-posting, weather, video-frames, gifgrep.
- `docs/architecture.md` — design rationale & security invariants.
- `docs/soul.md` — agent identity (personality, voice, interests); injected into both personas.
- `docs/providers.md` — provider integration guide (sidecar pattern, adding new providers).
- `docs/hermes/` — generated Hermes artifacts (feature-probe matrices, compat lockfiles); not hand-edited.
- `docker/` — container stack, including `docker-compose.hermes.yml` (contained Hermes overlay) + `hermes-contained-*` (entrypoint, curated skill allowlist).

## Common commands

| Command | Description |
|---------|-------------|
| `pnpm install` | Install dependencies |
| `pnpm dev onboard` | Interactive first-run wizard (relay bootstrap, bot token, admin claim, OAuth) |
| `pnpm dev relay --profile simple` | Start relay (dev mode) |
| `pnpm dev doctor` | Full health check (pass/warn/fail across every subsystem) |
| `pnpm dev doctor --json` | Same, structured JSON for CI |
| `pnpm dev runtimes status --json` | Check Claude Code and Codex runtime readiness |
| `pnpm lint` / `pnpm format` | Lint and format |
| `pnpm typecheck` | Type check |
| `pnpm test` | Run tests |
| `pnpm dev identity link --generate` | Generate identity link code |
| `pnpm dev auth oauth authorize xtwitter` | OAuth authorize |
| `pnpm dev auth oauth list` / `pnpm dev auth oauth revoke xtwitter` | OAuth list / revoke |
| `pnpm dev social pending` | List pending post ideas |
| `pnpm dev social promote <id>` | Promote post idea |
| `pnpm dev maintenance cron status` | Cron scheduler status |
| `pnpm dev maintenance cron list [--all] [--json]` | List cron jobs |
| `pnpm dev maintenance cron add --name <n> --every <dur>\|--cron <expr>` | Add cron job |
| `pnpm dev maintenance cron run <id>` | Run cron job immediately |
| `pnpm dev secrets setup-google` | Configure Google OAuth |
| `pnpm dev memory read --chat-id <id> --categories profile,interests` | Read memory entries for the chat's active operator profile |
| `pnpm dev memory write "fact" --category meta` | Write memory entry |
| `pnpm dev curator scan\|list\|show\|accept\|reject` | Review local Curator suggestions |
| `pnpm dev curator sign-producer --item item.json --producer-kind codex --producer-id codex:<id>` | Sign a Codex/Claude Curator item through the vault |
| `pnpm dev curator submit-signed --item item.json --envelope envelope.json` | Verify and submit a signed producer Curator item |
| `pnpm dev sessions [--active <min>] [--json]` | List active sessions |

### Hermes wrapper commands
The `hermes` group builds and evaluates the no-fork cutover proof spine. Most subcommands support `--json`; cutover evaluators such as `cutover-check` use exit 0 (safe), 1 (semantic fail), and 2 (input error), while generator commands report their own status in JSON.

| Command | Description |
|---------|-------------|
| `pnpm dev hermes doctor [--pin <p>] [--probes] [--compat-lock]` | Pinned Hermes wrapper readiness |
| `pnpm dev hermes prove --upstream-clean [--p0]` | No-fork proof; `--p0` requires an existing proof bundle and evidence inputs |
| `pnpm dev hermes inventory` | Phase-0 workflow roster |
| `pnpm dev hermes probes` / `probe <surface> [--allow-run]` | Feature-probe matrix / single-surface probe |
| `pnpm dev hermes network-probes [--allow-run] [--posture <p>]` | Egress isolation probes (deny direct provider/model/vault/DNS) |
| `pnpm dev hermes fixtures` / `generate` | Parity fixture results / profile artifacts |
| `pnpm dev hermes proof-bundle --inventory <path> --scope-manifest <path> --decision-log <path> --compatibility-lockfile <path> --feature-probe-matrix <path> --fixture-results <path> --nofork-proof-file <path> --network-probe-bundle <path> --queue-snapshot <path> --rollback-evidence <path>` | Byte-bind all required proof artifacts into one bundle |
| `pnpm dev hermes cutover-check [--strict] [--scoped] [--dry-run]` | Strict cutover evidence evaluation (parity-roster closure) |
| `pnpm dev hermes live-mcp probe-tokens` | Issue MCP probe tokens via relay admin socket |

## Auth & control plane

- `allowedChats` must include the chat before first DM.
- First admin claim (private chat): bot replies with `/approve CODE`; send it back to become admin.
- Emergency controls (CLI-only): `telclaude admin ban`, `telclaude admin unban`, `telclaude auth force-reauth`.

### Telegram commands

| Command | Description |
|---------|-------------|
| `/help [topic]` | Contextual help, topic list |
| `/me [link\|unlink]` | Identity management |
| `/auth [setup\|verify\|logout\|disable\|skip]` | 2FA management |
| `/system [sessions\|cron]` | System introspection |
| `/profile [list\|switch <id>\|reset]` | Operator profile selection for the chat |
| `/social [queue\|promote <id>\|run [svc]\|log [svc] [hours]\|ask [svc] <q>]` | Social persona |
| `/skills [drafts\|promote <name>\|reload]` | Skill management |
| `/curator` | Review automation suggestions |
| `/codex [--model <id>] [--cwd <relative-path>] [--write] <prompt>` | Queue a single-shot Codex work unit as a background job |
| `/approve <code>` | Fast-path approval |
| `/new` | Reset conversation session |

### Operator profiles
- Top-level `profiles[]` entries define named private-agent modes with `id`, `label`, optional `description`, `soulPath`, `allowedSkills`, and `defaultModel`.
- `soulPath` adds a profile-specific prompt overlay; `allowedSkills` narrows private skill loading; `defaultModel` applies unless the chat has an explicit `/model` preference.
- `/profile switch <id>` binds a chat to that profile. Memory reads, normal replies, scheduled private runs, and capture use the matching `telegram:<profile-id>` source.

### Scheduler config
- Private heartbeat: `telegram.heartbeat.enabled`, `intervalHours` (default 6), WRITE_LOCAL tier, `notifyOnActivity` (default true).
- Cron scheduler: `cron.enabled` (default true), `pollIntervalSeconds` (default 15), `timeoutSeconds` (default 900). Cron jobs and interval heartbeats are mutually exclusive per target.

## Tier-based key exposure
API keys (OpenAI, GitHub) are exposed for FULL_ACCESS tier only. READ_ONLY and WRITE_LOCAL never get keys. Configure via `telclaude secrets setup-openai` / `telclaude secrets setup-git` or env vars.

## Troubleshooting
- Bot silent: confirm `allowedChats`, rate limits, and observer not blocking.
- TOTP failing: ensure daemon running and device time synced.
- Hermes unavailable: confirm `TELCLAUDE_HERMES_API_BASE_URL`, `TELCLAUDE_HERMES_API_KEY`, the Hermes overlay, and live MCP are up.

## Docker notes
- **Node version**: Docker images use `node:22-bookworm-slim`.
- **4 images**: `telclaude:latest` (relay), `telclaude-google-services:latest` (Google sidecar), `telclaude-totp:latest`, `telclaude-vault:latest`.
- **4 base containers**: `telclaude` (relay), `google-services`, `totp`, `vault`; all LLM/persona runtime execution uses the Hermes overlay.
- **Secrets storage**: `telclaude secrets setup-openai`, `telclaude secrets setup-git`; encrypted in volume.
- **Workspace path**: `WORKSPACE_PATH` in `docker/.env` must point to valid host path.
- **Skill catalog**: Docker uses relay auth/profile state (`/home/telclaude-auth`) plus the shared standalone skill catalog (`/home/telclaude-skill-catalog`). Hermes contained mounts curated skills from the relay-owned catalog; credentials never enter the contained runtime.
- **Remote deployment**: Build locally and transfer images to the deployment target:
  ```bash
  cd docker && docker compose build
  docker save telclaude:latest telclaude-google-services:latest telclaude-totp:latest telclaude-vault:latest \
    | ssh <server> "docker load"
  ssh <server> "cd telclaude/docker && docker compose up -d"
  ```
- **Hermes overlay** (`docker-compose.hermes.yml`): adds contained private and social runtime topology on two internal-only networks. `telclaude` joins both (`192.0.2.10` on `telclaude-hermes-private`, `192.0.3.10` on `telclaude-hermes-social`) and runs live MCP listeners on both interfaces. `tc-hermes-contained` joins only the private network (`192.0.2.11`); `tc-hermes-social` joins only the social network (`192.0.3.11`). To start it, set ephemeral `TELCLAUDE_HERMES_API_SERVER_KEY` and `TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY`, operator RPC public/signing keys, and `TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN`. Model-provider hostnames are routed to a blocked address; egress goes through the relay's `openai-codex-proxy` only.
- **Contained posture**: `tc-hermes-contained` and `tc-hermes-social` run non-root `10000:10000`, `cap_drop ALL`, `no-new-privileges`, read-only root with noexec tmpfs (`/tmp`, `/home/hermes`, `/run`). The entrypoint curates skills into `$HERMES_HOME/skills` from read-only allowlists: `docker/hermes-contained-skills.allowlist` for private/cron/observer and `docker/hermes-social-skills.allowlist` for social. Credentials never enter the containers.
