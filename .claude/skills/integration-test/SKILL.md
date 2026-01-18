---
name: integration-test
description: Full SDK integration test that runs actual queries through the Claude SDK sandbox. Use after making changes to SDK client code, session management, skill loading, network proxy, voice/TTS, or image generation. Runs real prompts through the SDK to verify the complete path works.
---

# Integration Test Skill

Run comprehensive integration tests for telclaude without manual Telegram interaction.

## When to Use

Invoke this skill after modifying:
- SDK client code (`src/sdk/`)
- Session management (`src/sdk/session-manager.ts`)
- Skill loading or any SKILL.md files
- Network proxy configuration
- Voice/TTS functionality (`src/services/tts.ts`)
- Image generation (`src/services/image-generation.ts`)
- Telegram media handling (`src/telegram/media-detection.ts`)

## Quick Start

```bash
# Run all integration tests
telclaude integration-test --all

# Specific tests
telclaude integration-test --echo      # Basic SDK communication
telclaude integration-test --env       # Environment variable passing
telclaude integration-test --network   # Network proxy verification
telclaude integration-test --image     # Image generation (needs OPENAI_API_KEY)
telclaude integration-test --voice     # Voice message response (needs OPENAI_API_KEY)

# Verbose output for debugging
telclaude integration-test --all -v

# Custom timeout (default 120s)
telclaude integration-test --timeout 180000
```

## Test Descriptions

### Echo Test (`--echo`)
Verifies basic SDK sandbox communication:
- Sends a simple bash command through the SDK
- Confirms output is returned correctly
- Tests: sandbox initialization, tool execution
- Expected: Output contains `INTEGRATION_TEST_OK`

### Environment Test (`--env`)
Verifies environment variables pass into sandbox:
- Checks if OPENAI_API_KEY is accessible inside sandbox
- Falls back to checking HOME if no API key
- Tests: env injection, security boundaries

### Network Test (`--network`)
Verifies network proxy configuration:
- Tests HTTP_PROXY environment in sandbox
- Makes actual HTTPS request through proxy to api.openai.com
- Tests: proxy chain, DNS resolution, firewall rules
- Passes even with 401 (means network worked)

### Image Test (`--image`)
Verifies image generation end-to-end:
- Calls OpenAI image API from within sandbox
- Saves generated image to disk
- Tests: API connectivity, file I/O, skill execution
- Skips if OPENAI_API_KEY not configured

### Voice Test (`--voice`)
**Critical test for voice message compliance:**

Simulates receiving a voice message and validates Claude follows TTS skill rules:

1. **Uses `--voice-message` flag** - Required for Telegram waveform display
2. **Output in `/voice/` directory** - Not `/tts/`
3. **Format is `.ogg`** - Not `.mp3`
4. **Minimal text output** - Path only, no "I've generated..."

This catches the common failure mode where Claude ignores skill instructions and outputs verbose text with wrong format.

## Interpreting Results

### Success
```
── Echo Test ──
  ✓ Echo via SDK (1234ms)

── Voice Message Response Test ──
  ✓ Voice message response (12345ms)

── Summary ──
✓ All 5 tests passed
```

### Voice Test Failures

**Wrong format (common issue):**
```
⚠ Voice message response: Generated audio but with issues
  • Missing --voice-message flag
  • Wrong directory: used /tts/ instead of /voice/
  • Wrong format: used .mp3 instead of .ogg
  • Excessive text in response (should be path only)
```

This means Claude generated audio but didn't follow the skill instructions. Check that:
1. Skills are loaded from `~/.claude/skills/` (user level)
2. No conflicting skills in workspace `.claude/skills/`
3. Session was reset after skill update

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Echo timeout | SDK sandbox not starting | Check bubblewrap/seatbelt installed |
| Env var not set | Key not injected | Verify OPENAI_API_KEY in environment |
| Network failure | Proxy misconfigured | Check firewall rules, allowed domains |
| Image skipped | No API key | Run `telclaude setup-openai` |
| Voice wrong format | Skill not loaded | Verify `~/.claude/skills/text-to-speech/` exists |
| Voice extra text | Old skill cached | Restart container, check skill content |

## Running in Docker

```bash
# On Docker host
docker exec telclaude telclaude integration-test --all -v

# Just voice test
docker exec telclaude telclaude integration-test --voice -v

# Check what skills are loaded
docker exec telclaude ls -la ~/.claude/skills/
```

## Debugging Tips

1. Run with `-v` to see streaming output from SDK
2. Check logs: `docker logs telclaude --tail 50`
3. Verify skills: `docker exec telclaude cat ~/.claude/skills/text-to-speech/SKILL.md | head -30`
4. Run doctor: `telclaude doctor --network --secrets`

## Files Involved

- `src/commands/integration-test.ts` - Test implementation
- `src/sdk/client.ts` - SDK query execution
- `.claude/skills/text-to-speech/SKILL.md` - TTS skill rules (voice test validates these)
- `.claude/skills/integration-test/SKILL.md` - This skill
