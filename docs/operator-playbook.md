# Telclaude Operator Playbook

How to run telclaude as an operator-control surface for a personal Claude agent. Operational guide; for the security model see `docs/architecture.md`, for project conventions see `CLAUDE.md`.

## Framing

Telclaude is the secure Telegram-bridged operator-control surface for a personal agent. The relay holds secrets and enforces tiers; the vault sidecar holds credentials and signs approval tokens; private and social personas are air-gapped at the memory boundary; recurring work is driven by the cron scheduler and signed webhooks. The private agent runs on a contained no-fork Hermes runtime that the relay drives through relay-owned MCP and operator RPC. As an operator you live mostly on Telegram and only drop into the CLI for setup, surgery, and emergency controls.

## Maturity ladder

Four levels. Each level is additive; you never lose the previous level's controls.

### Level 1 — Single chat, default profile

One Telegram chat in `telegram.allowedChats`, one user in `security.permissions.users`, no `profiles[]` configured. The implicit `default` profile is in force for every chat (`src/config/profiles.ts:IMPLICIT_DEFAULT_PROFILE_ID`). Private memory is sourced from `telegram` with no profile suffix. Soul overlay is whatever `docs/soul.md` already provides through the runtime prompt.

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

Cron jobs and the interval heartbeat are mutually exclusive per target — pick one or the other.

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

- `telclaude.json` — policy: providers, security profile, network, observer, rate limits, Hermes/runtime config, cron defaults, `profiles[]`.
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

The private agent has one documented execution backend: the **no-fork Hermes wrapper**. Upstream Hermes is pinned and run unmodified inside a contained sidecar, with the relay supplying every credential, provider call, memory read, and outbound action through a relay-internal MCP bridge. There is no documented alternate worker or private-runtime selector. The operator surface for Hermes readiness and evidence lives under one CLI command group (`pnpm dev hermes ...`, `src/commands/hermes.ts:registerHermesCommand`).

### Runtime readiness

Hermes private-runtime readiness is proven through generated evidence rather than a runtime-mode toggle:

```
pnpm dev hermes doctor --probes --compat-lock
pnpm dev hermes prove --upstream-clean
pnpm dev hermes network-probes --allow-run
pnpm dev hermes verify-live
```

Treat `doctor` + `probes` + `verify-live` as the readiness gate: doctor fails closed unless the pinned feature-probe matrix and compatibility lockfile are present and green, `prove --upstream-clean` proves the checkout is unmodified upstream, and `verify-live` exercises the live contained runtime end to end.

### Connector readiness

Personal/family usability needs more than a contained runtime. The operational baseline is:

- **Google provider:** `providers[].id="google"` with `gmail`, `calendar`, `drive`, and `contacts`, plus a matching `security.network.privateEndpoints` entry for `google-services:3002`. Hermes gets this only through relay-issued authority (`hermes.privateRuntime.providerScopes` or the bound profile's `providerScopes`). An unscoped authority still denies provider reads and writes.
- **Provider writes:** Gmail draft creation, calendar mutations, Drive writes, and future write-capable providers must stay on the two-phase path: `tc_provider_prepare_write` -> human approval/TOTP -> `tc_provider_execute_write`. Do not add inline write shortcuts to connector setup.
- **Web:** `web.fetch` is relay-served; arbitrary public browsing needs `TELCLAUDE_NETWORK_MODE=permissive` while metadata and RFC1918 destinations remain blocked. `web.search` additionally needs `TELCLAUDE_BRAVE_SEARCH_API_KEY` or the Brave key in the host keychain.
- **Edge channels:** Telegram is the primary inbound operator surface. WhatsApp is the live edge transport through `whatsapp-bridge`; outbound sends require `TELCLAUDE_WHATSAPP_BRIDGE_SECRET` plus `TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS`, and inbound bridge events require `TELCLAUDE_WHATSAPP_INBOUND_SECRET` plus `TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES`. Keep real phone numbers in local `.env` / private deployment secrets only. Gmail/email access is the Google provider, not a standalone edge email connector.

Run `pnpm dev doctor --json` and inspect the `Hermes Connectors` category for advisory readiness. These checks intentionally skip optional missing connectors instead of hard-failing minimal deployments; the runtime and MCP policy layers remain fail-closed when a scoped authority, provider, bridge, or approval token is absent.

### The contained runtime (Docker)

In Docker the Hermes runtime is a second compose overlay, `docker/docker-compose.hermes.yml`, with the relay plus separate private/social runtime containers on separate internal-only bridge networks:

- `telclaude` — the relay, joined to `telclaude-hermes-private` (`172.30.92.10`) and `telclaude-hermes-social` (`172.30.93.10`), hosting live MCP listeners on port `8793` and the admin socket for probe-token issuance.
- `tc-hermes-contained` — pinned upstream Hermes for private/cron/observer work (image digest in the compose file), default `172.30.92.11`, running its API server on port `8642`.
- `tc-hermes-social` — pinned upstream Hermes for social work, default `172.30.93.11`, running its own API server on port `8642`.

The contained containers are hardened: non-root `10000:10000`, all capabilities dropped, read-only root filesystem, `noexec` tmpfs for `/tmp`, `/home/hermes`, and `/run`, 2GB / 2 CPU / 256 PID caps. The entrypoint (`docker/hermes-contained-entrypoint.sh`) curates skills from the source tree into `HERMES_HOME` against read-only allowlists — `docker/hermes-contained-skills.allowlist` for private/cron/observer and `docker/hermes-social-skills.allowlist` for social — rejecting path traversal and any entry missing a `SKILL.md`, and mints a peer-bound OpenAI Codex relay token so model traffic only reaches the relay's proxy route (`HERMES_CODEX_BASE_URL=http://telclaude:8790/v1/openai-codex-proxy`). Model-provider hosts are routed to a blackhole address; the containers have no path to providers, vault, or the public internet except through the relay.

Operator-supplied inputs to the overlay (`docker/.env` or shell):

- `TELCLAUDE_HERMES_API_SERVER_KEY=<ephemeral>` — shared Bearer between relay and private contained API server (generate per `compose up`, e.g. `openssl rand -base64 48 | tr '+/' '-_' | tr -d '='`).
- `TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY=<ephemeral>` — separate shared Bearer between relay and social contained API server.
- `TELCLAUDE_HERMES_MCP_RELAY_TOKEN=<ephemeral>` — shared live-MCP transport token between the relay and contained Hermes peers.
- `TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN=<relay-scoped>` — the relay-owned OpenAI Codex subscription token.
- `OPERATOR_RPC_AGENT_PUBLIC_KEY` / `OPERATOR_RPC_RELAY_PRIVATE_KEY` — operator RPC keypair from `pnpm dev keygen operator`, used to sign the proof attestations below.

### Management plane

Hermes production management deliberately stays on three supported layers:

1. **Docker Compose** owns the live resource graph: the relay, vault, TOTP,
   provider sidecars, and the private/social Hermes runtime overlay. Runtime
   changes should be service-scoped (`up --no-deps --wait`, `restart` for the
   affected Hermes runtimes) rather than full-stack `down`/`up` operations.
2. **Private release automation** owns host-specific overlays, secrets, seed
   manifests, and acceptance checks outside the OSS repository. A production
   host may attach this automation to a self-hosted CI runner post-job hook, but
   the hook must call the same fail-closed gate an operator can run manually.
3. **`telclaude hermes` evidence commands** own the steady-state proofs:
   no-fork proof, feature probes, network probes, served-MCP/skills evidence,
   and the live verification canary.

Do not introduce a second runtime orchestrator for Hermes unless the deployment
has actually outgrown a single Compose host. Kubernetes, Nomad, UI auto-updaters,
and broad "restart everything" release tools add failure modes without improving
the core invariant: the relay remains the security boundary and Hermes remains
contained, no-fork runtime compute.

Generic MCP catalog or gateway tools can be useful for non-privileged MCP server
inventory, but they are not a substitute for Telclaude's relay-owned live MCP
bridge. The live bridge resolves opaque authority handles server-side, strips
client-supplied scope/provenance, binds provider and memory access to the relay's
policy, and is covered by the steady-state Hermes proofs.

### Steady-state proofs

The cutover completed; Hermes is the only runtime. What remains is the recurring proof loop, run after every Hermes pin bump or containment change:

- **`prove --upstream-clean`** — the pinned Hermes checkout is byte-identical to upstream: no diff, no patch, no monkeypatch, no runtime source replacement.
- **`probes` / `probe <surface> --allow-run`** — regenerate the feature-probe matrix from observed evidence (headless execution, API-server and served-MCP containment, served-MCP memory air-gap, skills allowlist, model relay, edge adapters, providers, workflows, side-effect ledger).
- **`network-probes --allow-run`** — gated egress isolation: the relay/control URL stays reachable while direct calls to providers, the vault, the model provider, and DNS exfil targets are all denied. `--posture` is `agent-iptables` or `contained-internal`. Use `--defer-attestation` to capture an unsigned run report on the runner and `--from-report` to promote it into signed artifacts later.
- **`doctor --probes --compat-lock`** — fails closed unless the matrix and the pin-bound compatibility lockfile are present, schema-valid, and green.
- **`verify-live`** — the live canary: exercises the contained runtime, live MCP, and provider canaries end to end.

The sensitive probes are signed Ed25519 attestations from the operator relay key — the contained agent cannot hold that key, so it cannot forge its own containment proof. Rollback is the previous container image: redeploy the prior pinned digest with the same overlay.

## Security stays on at every level

Levels 1 through 4 add capability, not authority. The vault still gates credentials, approval tokens still bind writes to a specific request, persona memory air-gap still keeps social timeline content out of the private agent. The Hermes runtime inherits the same envelope: it never sees raw credentials, model traffic stays on the relay proxy path, and production readiness is re-proven (doctor, probes, verify-live) on every pin bump. No level skips security — see `docs/architecture.md` for the invariants.
