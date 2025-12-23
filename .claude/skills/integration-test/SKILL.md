---
name: integration-test
description: Full SDK integration test that runs actual queries through the Claude SDK. Use after making changes to SDK client code, session management, skill loading, or network integration.
---

# Integration Test Skill

Test the full SDK path without Telegram/auth overhead.

## When to Use

Run `telclaude integration-test` after modifying:
- `src/sdk/client.ts` (SDK options, permissions, hooks)
- `src/sdk/session-manager.ts` (session pooling, resume)
- Skill files in `.claude/skills/`
- OpenAI integration (image-generator, text-to-speech)
- Network configuration

## Quick Start

```bash
# Run all tests (echo + env + image)
telclaude integration-test --all

# Verbose output (shows SDK streaming)
telclaude integration-test --all -v

# Specific tests
telclaude integration-test --echo     # Just Bash/sandbox test
telclaude integration-test --env      # Just environment variable test
telclaude integration-test --image    # Just image generation

# Custom timeout (default 120s)
telclaude integration-test --timeout 180000
```

## What It Tests

### Echo Test (`--echo`)
- Runs a Bash command through SDK
- Verifies: SDK initialization, command execution
- Expected: Output contains `INTEGRATION_TEST_OK`

### Environment Test (`--env`)
- Verifies environment variables are passed to SDK
- Tests: OPENAI_API_KEY (if configured) or HOME
- Expected: Env var is present in environment

### Image Test (`--image`)
- Tests OpenAI API access through SDK
- Verifies: Network access, API key injection, file creation
- Expected: PNG file created
- Skips automatically if `OPENAI_API_KEY` not configured

## Interpreting Results

```
  Running echo test via SDK...
  ✓ Echo via SDK (3421ms)

  Running image generation test via SDK...
  ✓ Image generation via SDK (15234ms)
    Image: ./test-image.png (45.2 KB)
```

### Common Failures

| Failure | Cause | Fix |
|---------|-------|-----|
| Echo timed out | SDK not starting | Check `claude` CLI installed, `claude login` done |
| Marker not found | Bash command didn't run | Check sandbox mode and prerequisites |
| Image generation failed | OpenAI API issue | Verify OPENAI_API_KEY is configured |
| No image path | Skill not invoked | Verify skills exist in `.claude/skills/` |

## Debugging Tips

1. Run with `-v` to see streaming output from SDK
2. Check logs: `~/.telclaude/logs/telclaude.log`
3. For skill issues, verify skills exist in `.claude/skills/`
4. Run `telclaude doctor` to check overall system health
