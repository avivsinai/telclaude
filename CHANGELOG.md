# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Security architecture**: SDK sandbox is now the primary enforcement layer for ALL tools (Bash, WebFetch, WebSearch)
  - Provides OS-level network isolation that blocks RFC1918/metadata endpoints
  - Protects against DNS rebinding and redirect-based SSRF attacks
  - Belt-and-suspenders application-layer guards added for WebFetch/WebSearch in `canUseTool`
- Docker firewall (`init-firewall.sh`) now matches sandbox allowlist (added OpenAI, more package registries, documentation sites)
- Docker firewall explicitly blocks metadata endpoints and RFC1918 before allowing whitelisted domains

### Fixed

- Image generation now works correctly through Claude's Bash tool (SDK sandbox properly configured with OpenAI domain)
- WebFetch/WebSearch now have proper network isolation (previously unprotected when SDK sandbox was disabled)

## [0.3.0] - 2025-12-17

### Changed

- **Breaking**: Minimum Node.js version upgraded from 22 to 25
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

[Unreleased]: https://github.com/avivsinai/telclaude/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/avivsinai/telclaude/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/avivsinai/telclaude/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/avivsinai/telclaude/releases/tag/v0.1.0
