# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/avivsinai/telclaude/compare/v0.5.3...HEAD
[0.5.3]: https://github.com/avivsinai/telclaude/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/avivsinai/telclaude/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/avivsinai/telclaude/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/avivsinai/telclaude/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/avivsinai/telclaude/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/avivsinai/telclaude/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/avivsinai/telclaude/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/avivsinai/telclaude/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/avivsinai/telclaude/releases/tag/v0.1.0
