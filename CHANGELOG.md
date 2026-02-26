# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Google Services sidecar** — Gmail, Calendar, Drive, Contacts integration via approval-gated Fastify REST API. 20 actions (18 read, 2 action-type). New container: `google-services`.
- **Approval token system** — Ed25519-signed, one-time-use tokens with JTI replay prevention, params hash binding, and domain-separated signatures for action-type provider operations.
- **Vault payload signing** — New `sign-payload` and `verify-payload` protocol messages for domain-separated Ed25519 operations.
- **`setup-google` command** — OAuth2 PKCE flow for Google credentials with scope bundles (read_core, read_plus_download, actions_v1).
- **Provider integration guide** — New `docs/providers.md` documenting the sidecar pattern and how to add new providers.

### Changed

- **6 containers** — Docker topology expanded from 5 to 6 containers (added `google-services`).
- **Documentation overhaul** — Architecture, security, and agent playbook docs updated for Google sidecar. Added SOCIAL tier to SECURITY.md. Fixed stale references and broken cross-links.

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
- **AppArmor profiles** — Production-tested and corrected on Pi4.

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

- **Security architecture**: Single isolation boundary by mode (SDK sandbox in native mode; Docker container + firewall in Docker mode)
  - SDK sandbox provides OS-level isolation for Bash in native mode and blocks RFC1918/metadata endpoints
  - WebFetch/WebSearch are filtered by PreToolUse hooks + `canUseTool` allowlists
- Docker firewall (`init-firewall.sh`) now matches the allowlist (added OpenAI, more package registries, documentation sites)
- Docker firewall explicitly blocks metadata endpoints and RFC1918 before allowing whitelisted domains
- User ID for rate limiting now passed via system prompt to avoid race conditions in concurrent requests

### Fixed

- Fixed SDK hang when using custom env with sandbox enabled (don't pass custom env in sandbox mode)
- Fixed command injection vulnerability in git-proxy-init (use execFileSync with argument arrays)
- Fixed SSRF vulnerability in git-proxy (added host allowlist, only github.com allowed)
- Fixed TOCTOU race condition in quickstart config file creation (atomic write pattern)
- Image generation now works correctly through Claude's Bash tool (SDK sandbox properly configured with OpenAI domain)
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

[Unreleased]: https://github.com/avivsinai/telclaude/compare/v0.6.0...HEAD
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
