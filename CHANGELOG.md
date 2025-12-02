# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive README with Mermaid architecture diagrams
- CONTRIBUTING.md with contributor guidelines
- SECURITY.md with security policy and threat model
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- GitHub issue templates (bug report, feature request)
- GitHub PR template
- Dependabot configuration for automated dependency updates

### Changed

- Updated package.json with comprehensive metadata and keywords

## [0.1.0] - 2025-12-02

### Added

- Initial release
- Telegram Bot API integration via grammY
- Claude Agent SDK integration with V2 session pooling
- Security Observer with fast-path regex and LLM analysis
- Three-tier permission system (READ_ONLY, WRITE_SAFE, FULL_ACCESS)
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

[Unreleased]: https://github.com/avivsinai/telclaude/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/avivsinai/telclaude/releases/tag/v0.1.0
