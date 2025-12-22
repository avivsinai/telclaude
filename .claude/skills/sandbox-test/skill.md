---
name: sandbox-test
description: Diagnostic tool for testing sandbox configuration. Use after making changes to sandbox, network filtering, environment variable passing, or OpenAI API integration. Run before deploying to production to verify changes work correctly.
---

# Sandbox Test Skill

Verify sandbox configuration without the full Telegram/auth stack.

## When to Use

Run `telclaude sandbox-test` after modifying:
- `src/sandbox/` (sandbox configuration, env isolation)
- `src/services/openai-client.ts` (OpenAI API, ProxyAgent)
- Network filtering or domain allowlists
- Environment variable handling

## Quick Start

```bash
# Run all tests
telclaude sandbox-test --all

# Verbose output
telclaude sandbox-test --all -v

# Specific test categories
telclaude sandbox-test --env      # Environment variables
telclaude sandbox-test --network  # Network connectivity
telclaude sandbox-test --openai   # OpenAI API
```

## What It Tests

### Environment Tests (`--env`)
- HTTP_PROXY/HTTPS_PROXY availability (critical for Node.js fetch)
- OPENAI_API_KEY passed to sandboxed commands
- Basic env vars (PATH, HOME)

### Network Tests (`--network`)
- DNS resolution inside sandbox
- Connectivity to api.openai.com (allowed domain)
- Connectivity to registry.npmjs.org (allowed domain)
- RFC1918 blocking (Linux/Docker only)

### OpenAI Tests (`--openai`)
- API authentication via curl
- Node.js fetch with ProxyAgent (the actual code path)

## Interpreting Results

```
✓ = Test passed
✗ = Test failed (investigate)
○ = Skipped (platform limitation or not configured)
```

### Common Failures

| Failure | Cause | Fix |
|---------|-------|-----|
| HTTP_PROXY not set | Proxy vars stripped from env | Add to `ENV_ALLOWLIST` in `src/sandbox/env.ts` |
| OPENAI_API_KEY not set | Key not loaded or stripped | Check `buildEnvPrefixAsync()` in `src/sandbox/manager.ts` |
| OpenAI connection failed | Network blocked or proxy not working | Verify `api.openai.com` in allowed domains |
| Node.js fetch failed | ProxyAgent not configured | Check `src/services/openai-client.ts` uses `undici.ProxyAgent` |

## Platform Notes

- **macOS**: RFC1918 test skipped (Seatbelt doesn't block at OS level), network tests run directly
- **Linux/Docker**: Network tests skipped when run standalone (proxy started by SDK). Env tests still verify proxy vars are passed correctly.
- **No sandbox**: Tests will fail at initialization

## What This Tests vs Full Integration

`sandbox-test` verifies the sandbox configuration is correct:
- Env vars (HTTP_PROXY, OPENAI_API_KEY) pass through ✓
- Sandbox initializes correctly ✓
- RFC1918 blocking works (Linux only) ✓

For full network testing, run image generation via Telegram - this uses the SDK's sandbox which includes the network proxy.
