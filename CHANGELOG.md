# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Streaming drops tail content** - Flushed content from redactor now appended to streamer, fixing incomplete/empty responses for short messages
- **Voice-only responses show false error** - Voice responses now show "🎤" indicator instead of error message
- **Secret filter bypass in fallback** - Fallback redactor now receives custom secretFilter config
- **Duplicate typing indicators** - Outer typing timer now only runs when streaming is disabled
- **Inline keyboards too noisy** - Changed `showInlineKeyboard` default to `false`

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

[Unreleased]: https://github.com/avivsinai/telclaude/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/avivsinai/telclaude/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/avivsinai/telclaude/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/avivsinai/telclaude/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/avivsinai/telclaude/releases/tag/v0.1.0
