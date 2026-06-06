# Telclaude Operator Playbook

How to run telclaude as an operator-control surface for a personal Claude agent. Operational guide; for the security model see `docs/architecture.md`, for project conventions see `CLAUDE.md`.

## Framing

Telclaude is the secure Telegram-bridged operator-control surface for a personal Claude agent. The relay holds secrets and enforces tiers; the vault sidecar holds credentials and signs approval tokens; private and social personas are air-gapped at the memory boundary; recurring work is driven by the cron scheduler and signed webhooks. The private agent can run on the default Claude runtime or, once proven, on a contained no-fork Hermes runtime that the relay drives through operator RPC. As an operator you live mostly on Telegram and only drop into the CLI for setup, surgery, and emergency controls.

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

## Hermes private runtime

The private agent has two execution backends. The default is the Claude runtime described above. The second is the **no-fork Hermes wrapper**: upstream Hermes, pinned and run unmodified inside a contained sidecar, with the relay supplying every credential, provider call, memory read, and outbound action through a relay-internal MCP bridge. The operator surface for this lives under one CLI command group (`pnpm dev hermes ...`, `src/commands/hermes.ts:registerHermesCommand`).

### Switching the runtime mode

Mode is durable relay state, toggled through operator RPC — not a config-file edit:

```
pnpm dev hermes private-runtime status
pnpm dev hermes private-runtime status --json
pnpm dev hermes private-runtime set hermes
pnpm dev hermes private-runtime set legacy
```

`set` accepts only `hermes` or `legacy`. `status` reports the relay-observed `effectiveMode`, the control mode/source, and whether rollout is allowed (`src/commands/hermes.ts` `private-runtime` subcommands). The effective runtime also requires `TELCLAUDE_HERMES_PRIVATE_RUNTIME=1`; when that rollout env flag is off, the relay reports `legacy` regardless of durable mode. Treat `set hermes` as the last step of a graduation, after strict cutover evidence is safe and reviewed, because the setter itself only flips durable relay state.

### The contained runtime (Docker)

In Docker the Hermes runtime is a second compose overlay, `docker/docker-compose.hermes.yml`, with exactly two containers on an internal-only bridge network (`telclaude-hermes-relay` — the compose key is `hermes-relay-net`; default subnet `192.0.2.0/24`):

- `telclaude` — the relay (default `192.0.2.10`), hosting the live MCP bridge on port `8793` and the admin socket for probe-token issuance.
- `tc-hermes-contained` — pinned upstream Hermes (image digest in the compose file), default `192.0.2.11`, running its API server on port `8642`.

The contained container is hardened: non-root `10000:10000`, all capabilities dropped, read-only root filesystem, `noexec` tmpfs for `/tmp`, `/home/hermes`, and `/run`, 2GB / 2 CPU / 256 PID caps. Its entrypoint (`docker/hermes-contained-entrypoint.sh`) curates skills from the source tree into `HERMES_HOME` against the read-only allowlist in `docker/hermes-contained-skills.allowlist` — rejecting path traversal and any entry missing a `SKILL.md` — and mints a peer-bound OpenAI Codex relay token so model traffic only reaches the relay's proxy route (`HERMES_CODEX_BASE_URL=http://telclaude:8790/v1/openai-codex-proxy`). Model-provider hosts are routed to a blackhole address; the container has no path to providers, vault, or the public internet except through the relay.

Operator-supplied inputs to the overlay (`docker/.env` or shell):

- `TELCLAUDE_HERMES_PRIVATE_RUNTIME=1` — enable the overlay.
- `TELCLAUDE_HERMES_API_SERVER_KEY=<ephemeral>` — shared Bearer between relay and contained API server (generate per `compose up`, e.g. `openssl rand -base64 48 | tr '+/' '-_' | tr -d '='`).
- `TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN=<relay-scoped>` — the relay-owned OpenAI Codex subscription token.
- `OPERATOR_RPC_AGENT_PUBLIC_KEY` / `OPERATOR_RPC_RELAY_PRIVATE_KEY` — operator RPC keypair from `pnpm dev keygen operator`, used to sign the proof attestations below.

### Proving parity before cutover

Cutover is all-or-nothing: operators only enter `hermes` mode once a strict evidence chain proves the contained runtime is at parity with the Claude path. The artifacts are produced by the `hermes` subcommands and then byte-bound into a single bundle:

```
pnpm dev hermes doctor --probes --compat-lock
pnpm dev hermes inventory --out <inventory>
pnpm dev hermes prove --upstream-clean --out <nofork>
pnpm dev hermes network-probes --allow-run
pnpm dev hermes proof-bundle \
  --inventory <inventory> --scope-manifest <scope> --decision-log <decisions> \
  --compatibility-lockfile <lockfile> --feature-probe-matrix <probes> \
  --fixture-results <fixtures> --nofork-proof-file <nofork> \
  --network-probe-bundle <netprobes> --queue-snapshot <queue> \
  --rollback-evidence <rollback> --out <bundle>
pnpm dev hermes cutover-check \
  --inventory <inventory> --scope <scope> --decisions <decisions> \
  --proof-bundle <bundle> --lockfile <lockfile> --feature-probes <probes> \
  --fixtures <fixtures> --nofork <nofork> --network-probes <netprobes> \
  --queue-snapshot <queue> --rollback <rollback>
```

What the chain proves:

- **`prove --upstream-clean`** — the pinned Hermes checkout is byte-identical to upstream: no diff, no patch, no monkeypatch, no runtime source replacement. `--p0` is a follow-up classifier after the proof bundle and P0 evidence inputs already exist; it reads that bundle, so do not run it before `proof-bundle` has been built.
- **`network-probes`** — gated egress isolation: the relay/control URL stays reachable while direct calls to providers, the vault, the model provider, and DNS exfil targets are all denied. `--posture` is `agent-iptables` or `contained-internal`; `--allow-run` permits real probes (otherwise it emits a pending matrix). Use `--defer-attestation` to capture an unsigned run report on the runner and `--from-report` to promote it into signed artifacts later.
- **`proof-bundle`** — byte-binds all ten required artifacts (inventory, scope, decisions, lockfile, feature-probe matrix, fixtures, no-fork proof, network probes, queue snapshot, rollback rehearsal). Every flag is required; the bundle records the exact `pnpm dev hermes ...` command that regenerates each input.
- **`cutover-check`** — the gate. `--strict` is the default; non-strict input fails closed. It evaluates the full gate pipeline (workflow scope, resolved decisions, profile-generation proof, feature probes, lockfile consistency, fixtures, no-fork cleanliness, network posture, queue ownership, rollback rehearsal) plus, for a complete-parity cutover, the parity roster. `--scoped` evaluates only the included workflow set and is allowed for dry-run diagnostics only — strict live cutover rejects `--scoped` because production demands the full roster. Exit codes: `0` safe, `1` gate failure, `2` input error. Add `--dry-run` to evaluate evidence without touching runtime state.

Roster rows can be explicitly descoped with an accepted decision-log entry (`parity-descope:<row>`), but the non-descopable core (cutover, redaction, private-chat, approval-tokens, identity-migration, memory, skills) fails loudly if you try (`src/hermes/parity-roster.ts`). The proof evidence itself is signed Ed25519 attestations from the operator relay key — the contained agent cannot hold that key, so it cannot forge its own parity proof.

## Security stays on at every level

Levels 1 through 4 add capability, not authority. The vault still gates credentials, approval tokens still bind writes to a specific request, persona memory air-gap still keeps social timeline content out of the private agent. The Hermes runtime inherits the same envelope: it never sees raw credentials, model traffic stays on the relay proxy path, and production procedure refuses promotion until parity is proven and signed. No level skips security — see `docs/architecture.md` for the invariants.
