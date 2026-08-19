# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The household and WhatsApp wave landed 2026-07-17 through 2026-07-19 (#208–#228 except #215/#223). Earlier unreleased work after v0.8.0 is listed in the same section. Follow-up OSS through 2026-08-19 includes provider session error codes (#237), recovered gated-off extra channel/email sinks (#243), Beads/OSS hygiene and Unreleased tracking (#244), the egress-broker report CLI (#245), undici 8.9.0 then grouped npm minors (#236, #241, #242), CI action pins (#203, #232, #229, #239), dependency overrides (#246, #248), network-probe spoof-denial hardening (#247), CI ffmpeg apt retries and Ubuntu archive rewrite (#249, #251), served-MCP tool-count docs (#252), Bash always-grant exec-policy tests (#253), cron copy-paste fixes (#254, #255), heartbeat `/system` remediation `--private` (#257), WhatsApp inbound upsert observability (#258), and vitest coverage-v8 4.1.10 (#196). Live household activation is still dark. Version stays 0.8.0 until an explicit 0.9.0 cut.

### Added

- **Hermes `network-egress-broker-report` CLI (#245)** — Generate a machine-observed contained-runtime egress-broker run report (`--allow-run`) for later promotion by `hermes probe --from-report`. Does not change `network-probes --run-report-out`.
- **Recovered extra outbound sinks, still gated off (#243)** — Restored email MIME/Gmail send and extra channel dispatcher paths from the hermes-delivery scout; extra sinks remain gated off. The dispatcher claims executing then releases on delivery failure.
- **Telegram `/learn` and slash-command guard (#199)** — Profile-scoped `/learn` write/list/forget, and unknown slash commands stay out of Hermes with rate-limited unmatched replies.
- **Telegram `/update` deploy command (#200)** — Operator can check running revision against GitHub main and dispatch the verify-gated deploy workflow.
- **WhatsApp household identity isolation (#209)** — Added explicit household profiles and bindings, profile-scoped memory, and fail-closed authority checks for inbound WhatsApp turns.
- **Phase 0 WhatsApp provider flow (#210)** — Added identity-bound household replies, provider challenge interception and login coordination, OTP and Israeli-ID redaction, and gated Clalit renewals.
- **Phase 0 household reminders (#211)** — Added durable reminder storage, confirmation and scheduled-fire flows, outbound authorization, send journaling, interception receipts, and an acceptance probe.
- **Phase 0 household media assistance (#212)** — Added durable attachment quarantine, bounded voice and document derivation, interactive choices, and confirmation-gated derived actions while preserving attachment metadata.
- **Deterministic household emergency layer (#216)** — Added emergency classification, fixed guidance, rate-limited operator control alerts, and authenticated inbound handling.
- **Household observability metrics (#217)** — Added content-free household counters, durable metric storage, digest execution, and operator/CLI surfaces.
- **Household activation preflight (#220)** — Added a read-only `telclaude household preflight` command with deterministic exit codes and rollout-gate checks for bindings, consent, media/data controls, switches, providers, bridge state, and rollout readiness.

### Changed

- **CI action pins (#203, #232, #229, #239)** — Bumped GitHub attest, `action-gh-release`, `actions/setup-node` v7, and atomic CodeQL init+analyze 4.37.0.
- **Dependabot grouped npm minors (#241, #242)** — Minor/patch group updates, including later undici and playwright-core bumps after the undici 8.9.0 floor.
- **vitest coverage-v8 4.1.10 (#196)** — Bumped `@vitest/coverage-v8` from 3.2.4 to 4.1.10.
- **GitHub Actions checkout 7 (#194)** — Bumped `actions/checkout` from 6.0.3 to 7.0.0.
- **WhatsApp bridge deployment pinning (#208)** — Pinned the bridge deploy image and added CI/config validation for the required bridge image settings.
- **Provider degradation handling (#213)** — Relay startup now stays available when provider health checks fail; `TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS=1` retains strict fail-fast behavior.
- **Reminder confirmation UX (#214)** — Streamlined household reminder confirmation and aligned the scheduled outbound authorization path.
- **Hermes compatibility lock in CI (#211)** — CI now runs `hermes doctor --probes --compat-lock` so the household reminder/media probe surfaces stay coherent.
- **CI apt-get ffmpeg retries (#249, #251)** — `scripts/ci-install-ffmpeg.sh` rewrites `azure.archive.ubuntu.com` to `archive.ubuntu.com`, then retries `apt-get update` so Azure archive hangs do not fail Verify. The system-dependency step timeout is 25 minutes so a third update plus ffmpeg install can finish.
- **Operator cron workflow recipes (#254)** — `docs/operator-playbook.md` replaces TODO stubs with copy-paste daily-brief, meeting-prep, and weekly-business-report jobs. Cron expressions stay UTC.
- **Bash `always` grant → exec-policy glob (#253)** — Document that `grantAllowlist` already persists the glob, and test the live path (safe command records `npm test*`; destructive and non-Bash grants do not).

### Security

- **Unauthenticated network-policy denials (#247)** — Hermes `network-probes` no longer treats HTTP 403 plus `x-telclaude-network-policy: denied` as proof. Only OS-level `DIRECT_EGRESS_NETWORK_DENIAL_ERROR_CODES` count, and contained-internal still needs firewall-sentinel attribution.
- **protobufjs 7.6.5 (#248)** — Overrode production-transitive protobufjs (Baileys / libsignal) to 7.6.5 so GHSA-j3f2-48v5-ccww is patched. playwright-core stays 1.62.1.
- **undici 8.9.0 (#236)** — Bumped undici to 8.9.0 (later grouped minors continue from that floor).
- **brace-expansion 5.0.9 and postcss 8.5.26 (#246)** — Overrode production-transitive brace-expansion and Vite's development postcss so GHSA-rgw5-rvv9-x895, GHSA-mh99-v99m-4gvg, GHSA-r28c-9q8g-f849, and GHSA-fxqj-rqcc-2cmp are patched. playwright-core stays 1.62.1.
- **Update-deploy token scope (#202)** — `/update` uses repo-scoped `contents: read`; `/update deploy` uses repo-scoped `actions: write`.
- **undici security floor (#215)** — Updated undici to pick up security fixes.
- **Household kill-switch revocation (#218)** — Enforced reminder switches, reconciled and purged durable state when bindings are removed, and revoked persisted conversations and turns.
- **Household DLP display sinks (#219)** — Added household-scoped Israeli phone redaction at outbound approval, emergency preview, and reminder proposal displays, with CORE-secret sanitization in generic approval renderers.
- **Key-aware structured redaction (#224)** — Preserved only provenance-scoped opaque relay identifiers under strict grammars and prevented verified crypto envelopes from corrupting audits, probes, tools, and approvals.
- **Household outbound auto-grants (#225)** — Added content-safety checks and atomic rate limiting for auto-granted household outbound actions.
- **Per-action Clalit policy (#227)** — Added fail-closed action parameter allowlists and removed subject selectors from household Clalit requests.

### Fixed

- **WhatsApp inbound upsert silence (#258)** — Companion DMs could be accepted on the phone while the bridge logged nothing, because `messages.upsert` was unobserved and the socket used a custom browser identity plus a silent Baileys logger. The bridge now logs content-free upsert counts, uses `Browsers.macOS("Chrome")` with a cacheable Signal key store and a small `getMessage` cache, and forwards only Baileys decrypt/unavailable strings (no JIDs or bodies).
- **Heartbeat `/system` copy-paste (#257)** — The missing-heartbeat remediation omitted `--private`, so `cron add` rejected the suggested command. It now includes `--private`.
- **daily-brief cron example (#254)** — The skill preset used `--private` and `--prompt` together; `cron add` allows exactly one action. The example now uses `--prompt` plus `--skill daily-brief`.
- **Past-dated cron `--at` examples (#255)** — Weekly-business-report and operator-playbook one-shots used May 2026 timestamps that `cron add` rejects. They now use a one-minute-ahead ISO timestamp, with a docs regression test.
- **Provider session error copy (#237)** — Sidecar 401s map to `credentials_missing` / `session_expired` / `auth_required`, and the external-provider skill points operators at `/providers enroll`.
- **Persistent Docker volumes (#201)** — Named persistent volumes are `external: true` so a missing volume fails closed instead of creating an empty replacement.
- **Household confirmation voice and gendered copy (#221)** — Corrected Gabriel's recurring-reminder decline voice and locked cross-surface gendered copy coverage.
- **Hermes evidence scanning and multimedia budgets (#222)** — Excluded verified attestation cryptography from secret scans and separated hourly and daily multimedia rate-limit buckets. Standalone #223 was closed unmerged; the midnight-UTC limiter fix landed here.
- **Repeated emergency alerts (#226)** — Repeated household emergency alerts now escalate instead of being suppressed.
- **Baileys v7 inbound identity resolution (#228)** — Resolves LID addresses to phone-number identity for sender and conversation binding, and fails closed when resolution is unavailable.

## [0.8.0] - 2026-07-01

### Added

- **Authenticated GitHub repo reads (`tc_github_*`)** — Relay-native, read-only GitHub repository surface for the contained Hermes private persona: `tc_github_list_repos`, `tc_github_list_refs`, `tc_github_get_tree`, `tc_github_read_file`, backed by the existing GitHub App installation token (never the git proxy, never an external provider). New opt-in `github.read` capability scope (fail-closed without an explicit grant); owner/repo/ref/path validated at the boundary via typed Octokit (no shell git); result counts and file bytes capped; binary, oversized, or non-base64 content fails closed to metadata. The served-MCP surface grows to 25 tools.

### Fixed

- **Private-runtime provider action catalog** — The contained Hermes agent knew its granted provider scopes but never the concrete action ids, so it guessed action names the sidecar rejected as invalid-action 404s — silently breaking Clalit and other provider reads. The relay now injects a scope-filtered action catalog (real `tc_provider_read` / `tc_provider_prepare_write` ids, read vs. write split, provider-derived ids validated against a strict identifier grammar before reaching the prompt) into the private-runtime system prompt, sourced from the cached provider `/v1/schema`.
- **Contained-runtime tool include-list drift** — The contained entrypoint's `mcp_servers.telclaudeRelay.tools.include` had fallen behind relay policy (`tc_browse`, `tc_browse_act*`, and `tc_github_*` were served and scoped but not visible in `tools/list`), so the agent fell back to wrong paths. Synced the include-list to the full served surface (visibility only; the authority/scope layer still gates each tool) and added a parity test to prevent silent drift.

### Changed

- **Docs** — Refreshed the served-MCP tool count (18 → 25) and the capability-scope enumerations (`browse.act`, `github.read`) across `docs/architecture.md`, `CLAUDE.md`, and `.claude/CLAUDE.md`.

## [0.7.2] - 2026-06-22

### Security

- **GitHub git proxy mediation** — Hardened Smart HTTP and LFS proxying with scoped, peer-bound git proxy tokens, repository/ref policy enforcement, mediated LFS action handles, private-network target blocking, and sanitized policy-denial logging.

### Fixed

- **Codex git access containment** — Kept Codex work-unit git tokens fetch-only, avoided exposing durable credentials to child runtimes, and preserved workspace-write network denial while routing GitHub reads through the relay.

## [0.7.1] - 2026-05-17

### Fixed

- **Docker Claude binary path (TC-OC-06)** — resolved a pre-Hermes Docker runtime issue where Claude Code launched the wrong bundled binary instead of `/usr/local/bin/claude`, producing "Claude Code native binary not found" errors on private heartbeats and pooled queries.
- **Stale Anthropic firewall entries** — Dropped `code.anthropic.com`, `www.code.anthropic.com`, and `console.code.anthropic.com` from `ANTHROPIC_DOMAINS` and `FIREWALL_WILDCARD_EXPANSIONS`. The hosts never resolved and produced "could not resolve" warnings on every firewall-refresh; Claude Code traffic uses `claude.ai`/`console.claude.ai`, which remain allowlisted.
- **gifgrep build input** — Pinned the Docker build copy for the gifgrep skill assets.

### Changed

- **CI deploy timeout + healthcheck grace** — Extended the production deploy job timeout and relay healthcheck grace to absorb cold-cache rebuilds on the self-hosted runner.

## [0.7.0] - 2026-05-16

### Added

- **Curator triage inbox** — Operator-reviewable suggestions store with `cron_hardening` and `unused-skill` collectors. Telegram card, dashboard route, accept/reject decisions, signed producer envelopes via `vault.signPayload` with `curator-producer-v1` domain prefix.
- **Skill self-evolution** — `skill_manage create | patch | archive | pin | unpin | rename` with persona-scoped paths (`agent/telegram/` and `agent/social/<service>/`), scanner-before-write, atomic temp+rename with cooperative mkdir-locks, pre-rename realpath revalidation, tar.gz snapshots (rolling 30), audit JSONL.
- **Operator profiles (Wave 2.1 A + B)** — `profiles[]` config schema, `chat_profiles` table keyed by chat_id, `/profile list|show|switch` Telegram commands, SOUL.md stacking, per-profile `defaultModel` + `allowedSkills`, profile-scoped private memory using `telegram:<profile-id>` source with one-shot migration from bare `telegram`.
- **Codex first-class** — `codex-work-unit` background payload kind, executor with `--ephemeral --ignore-user-config --sandbox <enum> --cd <confined>` + `sandbox_workspace_write.network_access=false`, `/codex [--model] [--cwd] [--write] <prompt>` Telegram command, shared `validateCodexModel` validator with closed `CODEX_EXECUTABLE_MODELS` allowlist.
- **Signed cron webhooks** — Loopback-only Fastify receiver with Stripe-style HMAC (`x-telclaude-webhook-signature: t=<unix>,v1=<hex>`), replay guard via `webhook_deliveries` `(slug, signature_digest)` atomic INSERT OR IGNORE, ingress + per-webhook + global rate limits, `trustedProxies`, CIDR allowlist, body never JSON-parsed (raw buffer + SHA-256 audit).
- **Cron preprocess + `[IDLE]`/`[SILENT]` suppression** — Subprocess sandbox with command allowlist, env-scrubbed, cwd-confined, output cap, timeout.
- **Skill invocation telemetry** — Metadata-only `skill_invocations` table (no raw args/outputs), fire-and-forget recording from `createSkillAllowlistHook` post-decision, auth-scope-authoritative source field, 365-day TTL prune.
- **Model fallback (TC-OC-05)** — Four-state `ModelRoute` (`default | override | profile | fallback`), executable vs catalog-only providers, two-layer model guards, `/system` surfaces `model_fallback_active`, `/model reset` clears stale chat prefs.
- **Maintenance hygiene** — Shared `src/maintenance/log-rotation.ts` with exact-timestamp regex (preserves manual backups), audit log rotation (10 MiB / 5 retain), `webhook_deliveries` 24h TTL, `webhook_hits` 30d TTL, `skill_invocations` 365d TTL, stale lock dirs / `.SKILL.md.*.tmp/.bak` / `.telclaude-rename-*` / `os.tmpdir/telclaude-skill-manage-*` cleanup on startup + 60s timer.
- **Provider scaffold + `/skills sign`** — `telclaude providers init <id>` generates inert sidecar boilerplate (`src/<id>-services/` + `docker/Dockerfile.<id>`). `/skills sign` Telegram bridge routes through vault-backed `signSkillByName`.
- **Operator playbook + router profile + workflow presets** — `docs/operator-playbook.md` four-level maturity ladder; `assets/profile-templates/router/SOUL.md` reference; `docs/profiles.md` router-profile convention; `daily-brief` / `meeting-prep` / `weekly-business-report` / `humanizer` skill pairs (`.claude/` + `.agents/`).
- **`telclaude curator sign-producer` + `submit-signed` CLI** — Sign and verify curator items from claude-code / codex producers via the vault.

### Changed

- **Memory source field** — Private telegram source becomes `telegram:<profile-id>`. Bare `telegram` migrates once to `telegram:default` and is rejected on new writes; legacy reads still tolerated via `isTelegramMemorySource`.
- **Three-layer write isolation** for memory RPC — HTTP scope + `hasExplicitTelegramSourceClaim` rejection + RPC-layer `isTelegramMemorySource` guard.
- **Chat-scoped exec policy** — approval policy resolution includes `chatId` + `isAdmin` on both initial and follow-up decisions.

### Security

- **Producer signing for non-system curator producers** — `upsertCuratorItem` rejects non-system producers at the store boundary; non-system writes must go through `upsertSignedCuratorItem` with a vault-verified envelope.
- **Webhook ingress rate limit before secret lookup** — `consumeWebhookIngressRateLimit` is the first call in the handler, before any signature check or audit write, to bound DoS via bad-signature flood.
- **SOCIAL tier denied** for `skill_manage` and `codex-work-unit` at three layers each (executor entry, CLI gate, Telegram parse).
- **Network egress confinement for Codex** — `-c sandbox_workspace_write.network_access=false` injected on every `codex exec` invocation.

### Fixed

- **Docker Go version pin** — Bumped `GO_VERSION` from 1.23.6 to 1.25.4 so `gifgrep@latest` (v0.3.0, requires Go >= 1.25.0) installs cleanly in image builds.

## [0.6.3] - 2026-04-23

### Added

- **Operator cockpit dashboard** - Added read-mostly dashboard views for sessions, run history, logs, background jobs, cron, provider health, social queue state, and persona status without exposing raw private content.
- **Social draft workbench** - Added public-content draft review tooling for queue inspection, metadata review, approval actions, and safer draft boundaries.
- **Live/replay integration harness** - Added provider, Telegram control-plane, dashboard route, and social workflow replay fixtures for repeatable integration coverage.

### Changed

- **Telegram gateway controls** - Polished `/stop`, pending queue, provider cards, and background-job controls so operator actions are clearer, scoped, and easier to recover from.
- **Persona profile status** - Surfaced private/social profile state, plugin installation status, and boundary summaries through status and dashboard endpoints.

### Security

- **Release dependency floor** - Raised dependency overrides for Fastify, Vite, Rollup, minimatch, and picomatch to clear high-severity audit findings.

## [0.6.2] - 2026-04-11

### Added

- **Relay-owned episodic private memory** - Successful Telegram turns are now captured into a scoped episodic archive and recalled as recent or query-relevant shared history.
- **Compiled Claude working memory** - The relay now materializes a derived `MEMORY.md` working set into Claude's local project-memory path before private queries and heartbeats.
- **Memory context inspection** - Added `telclaude memory context` to inspect the private prompt bundle or the compiled markdown view for a chat.

### Changed

- **Private memory recall** - Telegram queries and private heartbeats now use the same relay-built memory bundle, combining trusted semantic memory with sanitized episodic recall and an explicit memory policy prompt.
- **Memory skill guidance** - The memory skill now pushes harder on preserving durable details about life, work, preferences, shared history, and collaboration patterns.

### Fixed

- **Anthropic OAuth env fallback** - The relay now preserves the required Anthropic OAuth beta header when falling back from vault OAuth to env-provided OAuth tokens.

### Security

- **Docker FULL_ACCESS credential boundary** - Docker FULL_ACCESS runs now keep provider credentials inside relay/vault/proxy paths instead of exposing raw provider keys to the agent runtime.
- **Memory write validation unified** - Automatic private-memory extraction now uses the same validation rules as relay memory RPC, preventing instruction-like or secret-bearing content from being promoted as durable memory.
- **Episodic recall sanitization** - Archived turn text is now normalized, secret-redacted, and stripped of instruction-like content before it can be re-injected into prompt context or compiled into Claude's local memory file.

## [0.6.1] - 2026-03-12

### Added

- **Google Services sidecar** - Gmail, Calendar, Drive, and Contacts integration via an approval-gated Fastify API. Adds the `google-services` container and provider-side action schema and health endpoints.
- **Approval token signing flow** - Ed25519-signed one-time approval tokens for provider actions, plus vault `sign-payload` and `verify-payload` support for domain-separated signatures.
- **`setup-google` command** - OAuth2 PKCE setup flow for Google credentials with bundled scopes.
- **Telegram command registry** - Central command catalog with natural-language system help and stricter command target matching.
- **Autonomous social actions** - Autonomous engagement actions for the social agent, including X thread posting via reply-to-self chaining.

### Changed

- **6-container Docker topology** - Docker deployment now includes the Google sidecar alongside the relay, agent, TOTP, and vault services.
- **Provider and skill policy enforcement** - `allowedSkills` enforcement is now applied per service, with updated provider documentation and deployment docs.
- **Internal maintainability sweep** - Security, relay, SDK, command, crypto, sandbox, Telegram, and social modules were refactored across PRs #41-#50 while preserving the existing release flow.

### Fixed

- **Social spam mentions** - Notification processing now explicitly ignores spam mentions instead of replying with low-signal text.
- **Telegram quarantine commands** - `/pending` and `/promote` now find quarantined entries from both Telegram and the social agent.
- **Telegram output handling** - Message length limits and streaming overflow handling were corrected to avoid truncation and malformed updates.
- **Google/provider request flow** - Approval forwarding, `/v1/fetch` routing, Gmail base64url handling, sanitization, and degraded-provider behavior were corrected across the new sidecar path.
- **SDK and heartbeat reliability** - Added a first-chunk watchdog, fixed zombie session cleanup, removed a proactive posting SDK hang, and surfaced heartbeat phase failures back to Telegram.

### Security

- **Approval verification safety** - Google sidecar approval verification now preserves key rotation safety by avoiding stale public key caching.
- **Credential and secret scanning hygiene** - Gitleaks false positives introduced by new security checks and Telegram session key templates are explicitly suppressed so release automation stays green.

## [0.6.0] - 2026-02-23

### Added

- **Social services** — Dual-persona architecture with private (Telegram) and public (social) agents running on air-gapped networks with separate memory stores.
- **Memory system** — Persistent per-source memory with category-based storage (profile, interests, projects, post-ideas). CLI: `telclaude memory read|write|quarantine`. Source boundaries enforced at runtime.
- **OAuth2 PKCE** — Authorization code flow for social service credentials. CLI: `telclaude oauth authorize|list|revoke`. Token storage in vault with automatic refresh.
- **X/Twitter backend** — Timeline integration (pay-per-use), posting, engagement. Second social backend after Moltbook.
- **Moltbook backend** — Social network integration with notification processing, proactive posting, and autonomous timeline activity.
- **Three-phase social heartbeat** — Notifications (untrusted, Bash blocked), proactive posting (operator-approved, Bash enabled), autonomous activity (session-isolated).
- **Cross-persona queries** — `/ask-public` routes questions to social agent through relay; `/public-log` shows metadata-only activity summary; `/pending` and `/promote` for post idea quarantine flow.
- **SOCIAL permission tier** — Trust-gated Bash (operator/autonomous/proactive only), permissive WebFetch (public internet, RFC1918 blocked), protected path writes blocked.
- **Config split** — `telclaude.json` (policy, all containers) + `telclaude-private.json` (relay-only PII). Deep-merge via `TELCLAUDE_PRIVATE_CONFIG` env var.
- **Browser automation** — Chromium in agent containers with `agent-browser` CLI. New browser-automation skill.
- **Summarize skill** — URL content extraction for articles, YouTube, podcasts. CLI: `telclaude summarize`. Also available relay-side via summarize-core.
- **`/heartbeat` command** — Trigger social heartbeat on demand.
- **`/status` command** — Consolidated system status with enriched health endpoints.
- **Deploy compose** — 5-container topology with OAuth proxy, per-agent skill isolation, vault egress network.
- **Ed25519 RPC keygen** — `telclaude keygen <scope>` generates asymmetric keypairs for agent ↔ relay auth.
- **Anthropic API proxy** — Relay endpoint for credential injection into agent SDK calls.

### Changed

- **4 permission tiers** — Added SOCIAL tier (was 3: READ_ONLY, WRITE_LOCAL, FULL_ACCESS).
- **Moltbook demoted** — From first-class citizen to generic pluggable backend behind unified social service interface.
- **Social sandbox** — Container is the isolation boundary, not application-layer hooks. Matches Anthropic guidance: one boundary, not two.
- **Docker profiles** — Separate auth profile (relay-only, credentials) and skills profile (shared, no secrets).
- **Provider architecture** — Providers fetched from relay RPC instead of config mount. Firewall enforcement gated to relay-only containers.

### Fixed

- **Credential proxy truncation** — Compressed responses no longer truncated during proxying.
- **X/Twitter deployment** — Credential proxy, firewall rules, and free-tier API limits.
- **OAuth2 token exchange** — Public client flow + vault egress for token refresh.
- **Docker agent connectivity** — Skill discovery and env-var bypass hardening.
- **`/ask-public` timeout** — 5-minute minimum for interactive social queries.
- **Social agent prompt** — Quarantine → promote flow; agents no longer post directly.
- **AppArmor profiles** — Production-tested and corrected on ARM hosts.

### Security

- **Air-gap agent isolation** — Agents on separate relay networks; cannot reach each other. 4 red-team fixes.
- **Ed25519 asymmetric RPC auth** — Bidirectional agent ↔ relay authentication. Shared HMAC replaced.
- **Social notification hardening** — Notification payloads wrapped with injection warnings; Bash blocked for notification processing.
- **Memory isolation** — Source boundaries enforced at runtime. Telegram agent never sees social memory.
- **External audit fixes** — P0-P2 findings from pen test harness addressed.
- **Outbound scanning** — Telegram message hardening for control commands.
- **Pre-integration hardening** — Security baseline established before social service integration.
- **Settings isolation** — `settingSources: ["project"]` prevents disableAllHooks bypass.

### Removed

- **CODE_OF_CONDUCT.md** — Boilerplate for a single-user project.
- **CONTRIBUTING.md** — No external contributors; useful content lives in CLAUDE.md.
- **GOVERNANCE.md** — Governance document governing nobody.

## [0.5.5] - 2026-01-25

### Added

- **Credential Vault** - Sidecar daemon that stores credentials and injects them into HTTP requests transparently. Agents never see raw credentials. Supports bearer, api-key, basic, query, and OAuth2 auth types with automatic token refresh.
- **HTTP Credential Proxy** - Relay endpoint at port 8792 that proxies requests through the vault, injecting credentials based on target host.
- **Vault CLI** - New commands: `telclaude vault-daemon`, `telclaude vault list|add|remove|test` for credential management.

### Security

- **Credential isolation** - Vault runs with no network access (except OAuth refresh); credentials never reach the agent container.
- **Host allowlist** - Proxy only injects credentials for explicitly configured hosts.
- **Path restrictions** - Optional `allowedPaths` regex per host prevents SSRF to unexpected endpoints.
- **Encryption at rest** - AES-256-GCM with scrypt key derivation for stored credentials.

## [0.5.4] - 2026-01-23

### Added

- **Provider Query CLI** - New `telclaude provider-query` command for querying external providers through the relay's `/v1/provider/proxy` endpoint. Supports `--provider`, `--service`, `--action`, `--params`, `--subject-user-id`, and `--idempotency-key` options.
- **Telegram attachment instructions** - Updated telegram-reply skill with file sending guidance.

### Fixed

- **External provider skill** - Now uses CLI commands instead of WebFetch (which only supports GET). Added explicit rules to prevent agents from bypassing providers with local files.
- **Agent server timeouts** - Extended request timeout for long-running provider queries.
- **TOTP session TTL** - Extended from 24 hours to 1 week for better UX.

## [0.5.3] - 2026-01-18

### Added

- **READ_ONLY attachment delivery** - WebFetch can call relay `/v1/attachment/fetch` with internal auth injection, enabling attachment delivery without Bash.

### Fixed

- **External provider attachments (READ_ONLY)** - Skill now uses WebFetch for attachment fetch instead of the Bash CLI.

### Security

- **Defense in depth** - Block writes to telclaude source directories in sensitive path checks.

## [0.5.2] - 2026-01-18

### Added

- **Telegram reaction context** - Conversations now include context from message reactions
- **Attachment fetch endpoint** - New relay endpoint and `fetch-attachment` CLI command for retrieving provider attachments

### Fixed

- **Docker skills symlink** - Force symlink to prevent path divergence between relay and agent
- **Docker /data writability** - Entrypoint now checks writability before chmod
- **Docker volume protection** - Critical volumes protected from accidental deletion
- **User ID in Docker mode** - SDK now receives user ID correctly via request context
- **External provider noResults** - Skill correctly handles empty results from providers

### Security

- **Gitleaks pre-commit hooks** - Added hooks to catch secrets before commit
- **Strengthened .gitignore** - Additional patterns to prevent secret leaks

## [0.5.1] - 2026-01-11

### Added

- **GitHub CLI in Docker** - Added `gh` command for issue/PR management from within container

## [0.5.0] - 2026-01-11

### Added

- **External provider support** - Skills can now integrate with external services (sidecars) that return structured data with attachments
- **Document detection for media auto-send** - Files in `/documents/` directory are automatically sent via Telegram as documents (preserves files without compression)

### Fixed

- **Firewall DROP-all rule ordering** - Ensures DROP rule stays at end of chain after dynamic rule additions

## [0.4.1] - 2026-01-02

### Fixed

- **Streaming drops tail content** - Flushed content from redactor now appended to streamer, fixing incomplete/empty responses for short messages
- **Voice-only responses show false error** - Voice responses now show "🎤" indicator instead of error message
- **Secret filter bypass in fallback** - Fallback redactor now receives custom secretFilter config
- **Duplicate typing indicators** - Outer typing timer now only runs when streaming is disabled
- **Inline keyboards too noisy** - Changed `showInlineKeyboard` default to `false`
- **Streaming disabled by default** - Typing indicator is sufficient; streaming can be re-enabled in config

## [0.4.0] - 2025-12-27

### Added

- **Quickstart command** - `telclaude quickstart` for easy first-time setup with minimal configuration
- **Streaming responses** - Real-time message updates using Telegram editMessageText with debouncing
- **Inline keyboards** - Copy, expand, and regenerate buttons on responses (disabled by default)

### Changed

- **Security architecture**: Single isolation boundary by mode (native relay process or Docker container + firewall in Docker mode)
  - Local isolation blocks RFC1918/metadata endpoints
  - WebFetch/WebSearch are filtered by PreToolUse hooks + `canUseTool` allowlists
- Docker firewall (`init-firewall.sh`) now matches the allowlist (added OpenAI, more package registries, documentation sites)
- Docker firewall explicitly blocks metadata endpoints and RFC1918 before allowing whitelisted domains
- User ID for rate limiting now passed via system prompt to avoid race conditions in concurrent requests

### Fixed

- Fixed runtime hang when using a custom environment with isolation enabled.
- Fixed command injection vulnerability in git-proxy-init (use execFileSync with argument arrays)
- Fixed SSRF vulnerability in git-proxy (added host allowlist, only github.com allowed)
- Fixed TOCTOU race condition in quickstart config file creation (atomic write pattern)
- Image generation now works correctly through Claude's Bash tool with the OpenAI domain allowlisted.
- WebFetch/WebSearch network isolation now enforced via hooks/allowlists in all modes

## [0.3.0] - 2025-12-17

### Changed

- **Breaking**: Minimum Node.js version is 20+ (LTS)
- Simplified CI workflows with tag-based action versions (maintainability over SHA pinning)

### Added

- CodeQL workflow for static security analysis (SAST)
- Acknowledgments section crediting Clawdis as inspiration

### Fixed

- Gitleaks workflow now works on pull requests (added GITHUB_TOKEN)
- Release workflow extracts notes correctly (replaced non-existent action with inline awk)

### Removed

- OpenSSF Scorecard workflow (verification issues, maintenance burden outweighed benefits)

## [0.2.0] - 2025-12-17

### Added

- CLI command: `totp-disable <user-id>`
- Comprehensive README with Mermaid architecture diagrams
- CONTRIBUTING.md with contributor guidelines
- SECURITY.md with security policy and threat model
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- GitHub issue templates (bug report, feature request)
- GitHub PR template
- Dependabot configuration for automated dependency updates

### Changed

- Updated package.json with comprehensive metadata and keywords
- `TELCLAUDE_NETWORK_MODE=open|permissive` now enables broad egress (non-private) via sandboxAskCallback (metadata + private networks still blocked)
- Claude Code sandbox policy is passed per SDK invocation via `--settings` (no writes to `~/.claude`)

### Fixed

- CLI commands now exit cleanly (no module-import timers keeping the event loop alive)
- Telegram `/setup-2fa` and `/skip-totp` instructions now include the required `totp-setup <user-id>` usage
- Sandbox metadata denylist cleaned up (removed invalid patterns / duplicates) and tier sandbox configs are cached to avoid repeated Linux glob expansion work

## [0.1.0] - 2025-12-02

### Added

- Initial release
- Telegram Bot API integration via grammY
- Claude Agent SDK integration with V2 session pooling
- Security Observer with fast-path regex and LLM analysis
- Three-tier permission system (READ_ONLY, WRITE_LOCAL, FULL_ACCESS)
- OS-level sandbox (Seatbelt on macOS, bubblewrap on Linux)
- Rate limiting (global, per-user, per-tier)
- Identity linking with out-of-band verification
- Command approval system for risky operations
- TOTP 2FA daemon with OS keychain storage
- SQLite-backed persistent state
- Audit logging
- CLI commands: relay, send, status, doctor, link, totp-daemon
- Claude skills: security-gate, telegram-reply

### Security

- Mandatory OS-level sandboxing
- Defense-in-depth security architecture
- Credential isolation via TOTP daemon
- Rate limiting fails closed

[Unreleased]: https://github.com/avivsinai/telclaude/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/avivsinai/telclaude/compare/v0.7.2...v0.8.0
[0.6.2]: https://github.com/avivsinai/telclaude/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/avivsinai/telclaude/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/avivsinai/telclaude/compare/v0.5.5...v0.6.0
[0.5.5]: https://github.com/avivsinai/telclaude/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/avivsinai/telclaude/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/avivsinai/telclaude/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/avivsinai/telclaude/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/avivsinai/telclaude/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/avivsinai/telclaude/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/avivsinai/telclaude/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/avivsinai/telclaude/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/avivsinai/telclaude/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/avivsinai/telclaude/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/avivsinai/telclaude/releases/tag/v0.1.0
