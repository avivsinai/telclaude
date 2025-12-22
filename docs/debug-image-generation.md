# Telclaude Image Generation Debug Context

## Problem Statement

We're building **telclaude**, a secure Telegram-to-Claude bridge that runs Claude Agent SDK queries inside an OS-level sandbox (bubblewrap on Linux/Docker, Seatbelt on macOS). Image generation via OpenAI's GPT Image API consistently fails with connection errors, despite the domain being in our allowlist.

**Error from user**: "I'm sorry, there seems to be a connection issue with the image generation service right now. The OpenAI API isn't responding."

## Architecture Overview

```
User (Telegram)
     │
     ▼
┌─────────────────────────────────────────────┐
│ telclaude relay (Node.js)                   │
│ - Receives messages via Telegram Bot API    │
│ - Runs Claude Agent SDK query()             │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Claude Agent SDK                            │
│ - Processes query with tools                │
│ - Sees image-generator skill                │
│ - Calls Bash tool with command:             │
│   `telclaude generate-image "prompt"`       │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Sandbox Manager (wrapCommand)               │
│ 1. Builds env prefix with OPENAI_API_KEY    │
│ 2. Wraps with bubblewrap sandbox            │
│ 3. Executes command inside sandbox          │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ Bubblewrap Sandbox                          │
│ - Filesystem isolation                      │
│ - Network filtering via allowedDomains      │
│ - Env var allowlist (env -i KEY=VALUE...)   │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│ telclaude generate-image (CLI command)      │
│ - Spawned as subprocess inside sandbox      │
│ - Calls OpenAI API via openai npm package   │
│ - Needs to reach api.openai.com             │
└─────────────────────────────────────────────┘
```

## Key Files and Their Roles

### 1. Skill Definition (tells Claude how to generate images)
```markdown
# .claude/skills/image-generator/SKILL.md
---
name: image-generator
description: Generates images using GPT Image 1.5 API
---

To generate an image, use the Bash tool:
```bash
telclaude generate-image "your detailed prompt here"
```
```

### 2. CLI Command (what runs inside the sandbox)
```typescript
// src/commands/generate-image.ts
export function registerGenerateImageCommand(program: Command): void {
  program
    .command("generate-image")
    .argument("<prompt>", "Text description")
    .action(async (prompt: string, opts) => {
      // Initialize key from keychain/env
      await initializeOpenAIKey();

      if (!isImageGenerationAvailable()) {
        console.error("Error: Image generation not available.");
        process.exit(1);
      }

      const result = await generateImage(prompt, { size, quality });
      console.log(`Generated image saved to: ${result.path}`);
    });
}
```

### 3. Image Generation Service (makes the API call)
```typescript
// src/services/image-generation.ts
export async function generateImage(prompt: string, options?): Promise<GeneratedImage> {
  const client = await getOpenAIClient();

  const response = await client.images.generate({
    model: "gpt-image-1.5",
    prompt,
    size,
    quality,
    n: 1,
    output_format: "png",
  });

  // Process response, save image, return result
}
```

### 4. OpenAI Client (key management)
```typescript
// src/services/openai-client.ts
async function getApiKey(): Promise<string | null> {
  // 1. Try keychain first (via telclaude setup-openai)
  const keychainKey = await getSecret(SECRET_KEYS.OPENAI_API_KEY);
  if (keychainKey) return keychainKey;

  // 2. Try environment variable
  if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;

  // 3. Try config file
  const config = loadConfig();
  if (config.openai?.apiKey) return config.openai.apiKey;

  return null;
}

// Called fresh on each sandbox command (hot-loading support)
export async function getOpenAIKey(): Promise<string | null> {
  cachedApiKey = null;
  keySourceChecked = false;
  return getApiKey();
}
```

### 5. Sandbox Manager (wraps commands)
```typescript
// src/sandbox/manager.ts
async function buildEnvPrefixAsync(): Promise<string> {
  const envToApply: Record<string, string> = { ...sanitizedEnv };

  // Fetch API keys fresh from secure storage
  const openaiKey = await getOpenAIKey();
  if (openaiKey) {
    envToApply.OPENAI_API_KEY = openaiKey;
  }

  const envAssignments = Object.entries(envToApply)
    .map(([key, value]) => `${key}=${shellEscape(value)}`)
    .join(" ");

  return `env -i ${envAssignments} `;
}

export async function wrapCommand(command: string): Promise<string> {
  const sandboxWrapped = await SandboxManager.wrapWithSandbox(command);
  const envPrefix = await buildEnvPrefixAsync();
  return envPrefix + sandboxWrapped;
}
```

### 6. Domain Allowlist
```typescript
// src/sandbox/domains.ts
export const OPENAI_DOMAINS: DomainRule[] = [
  { domain: "api.openai.com", methods: ["GET", "HEAD", "POST"] },
];

export const DEFAULT_ALLOWED_DOMAINS: DomainRule[] = [
  ...PACKAGE_MANAGER_DOMAINS,  // npm, pypi, etc.
  ...DOC_DOMAINS,              // docs sites
  ...CODE_HOST_DOMAINS,        // github, gitlab
  ...CDN_DOMAINS,              // cdnjs, unpkg
  ...ANTHROPIC_DOMAINS,        // anthropic API
  ...OPENAI_DOMAINS,           // api.openai.com
];
```

## What We've Fixed So Far

### Issue 1: Skills not being found
- **Problem**: Skills were installed to `~/.claude/skills/` but SDK looks at `<cwd>/.claude/skills/`
- **Fix**: Entrypoint now symlinks `/workspace/.claude/skills` → `/home/node/.claude/skills`
- **Status**: ✅ Fixed - startup now shows "Skills: 4 available"

### Issue 2: API key not injected into sandbox
- **Problem**: `getCachedOpenAIKey()` returned null because key was lazily loaded
- **Fix**: Changed to async `getOpenAIKey()` that reads fresh from storage on each command
- **Status**: ✅ Fixed - keys now hot-load

## Current Issue

Despite api.openai.com being in the allowlist and the key being properly injected, the OpenAI API call fails. The error suggests a network connectivity issue.

## Questions for Analysis

1. **Sandbox Network Model**: The `@anthropic-ai/sandbox-runtime` uses `allowedDomains` to configure network access. How exactly does this work?
   - Does it use iptables?
   - Does it use a proxy?
   - Are there DNS resolution issues inside bubblewrap?

2. **Subprocess Inheritance**: When `telclaude generate-image` is spawned inside the sandbox:
   - Does it inherit the proxy configuration?
   - Does the OpenAI npm client respect HTTP_PROXY/HTTPS_PROXY env vars?
   - Are there any TLS/certificate issues in the sandbox?

3. **Docker + Bubblewrap**: We're running inside Docker with bubblewrap. Could there be:
   - Nested namespace issues?
   - Missing capabilities?
   - Network namespace conflicts?

4. **Alternative Approaches**: Should we consider:
   - Making the API call BEFORE entering the sandbox (in the relay process)?
   - Using a different sandboxing approach for network-heavy operations?
   - Exempting certain commands from sandbox network restrictions?

## How the Sandbox Network Works

From the code, the sandbox-runtime uses a proxy-based approach:

```typescript
// manager.ts - sandbox initialization
await SandboxManager.initialize(sandboxConfig, sandboxAskCallback);

// sandboxAskCallback is invoked for domains NOT in allowedDomains
const sandboxAskCallback = async ({ host }: { host: string; port?: number }) => {
  // Block private networks
  if (await isBlockedHost(host)) return false;

  // Check if in allowed domains
  return allowedDomains.some((pattern) => domainMatchesPattern(host, pattern));
};
```

Key observations:
1. The sandbox sets up HTTP_PROXY/HTTPS_PROXY environment variables
2. Network requests go through a local proxy (Unix socket)
3. The proxy checks requests against `allowedDomains`
4. We explicitly clear NO_PROXY to force all traffic through the proxy:
   ```typescript
   const noProxyOverride = "export NO_PROXY= no_proxy= && ";
   ```

**Potential issues:**
- Does the OpenAI npm client respect HTTP_PROXY/HTTPS_PROXY?
- Is DNS resolution happening inside or outside the sandbox?
- Are there TLS issues with the proxy?

## Environment

- **Platform**: Docker container on Raspberry Pi 4 (arm64)
- **Base image**: node:22-bookworm-slim
- **Sandbox**: bubblewrap (bwrap)
- **Network mode**: RESTRICTED (35 domains allowed)
- **SDK**: @anthropic-ai/claude-agent-sdk + @anthropic-ai/sandbox-runtime

## Desired Outcome

We want Claude to be able to generate images by running `telclaude generate-image` inside the sandbox, with the command successfully reaching api.openai.com.

## Key Constraints

1. Security is paramount - we can't just disable the sandbox
2. The solution must work in Docker + bubblewrap environment
3. Hot-loading of API keys must continue to work
4. We want to maintain the skill-based architecture (Claude learns capabilities from skills)

## Alternative Design Approaches to Consider

### Option A: Pre-sandbox API calls
Instead of having Claude run `telclaude generate-image` inside the sandbox, have Claude call a custom tool that makes the API call in the main relay process (outside sandbox).

```
Claude → ImageGenerateTool → relay process → OpenAI API
```

Pros: No sandbox network issues
Cons: Requires custom tool implementation, breaks skill pattern

### Option B: SDK hooks for image generation
Use the SDK's PreToolUse/PostToolUse hooks to intercept image generation requests and handle them in the relay.

### Option C: Sidecar service
Run a separate process outside the sandbox that handles API calls, communicate via IPC.

### Option D: Debug and fix sandbox networking
Figure out why the proxy isn't working for the OpenAI client and fix it.

## Specific Questions for GPT Pro

1. **Why might the OpenAI npm client fail to connect through an HTTP proxy?**
   - Does it use native fetch, axios, or something else?
   - Does it respect HTTP_PROXY environment variables?
   - Are there known issues with proxied HTTPS connections?

2. **What's the best architecture for a sandboxed agent that needs to call external APIs?**
   - Should API calls happen inside or outside the sandbox?
   - How do other sandboxed agent systems handle this?

3. **Is the "skill invokes CLI command" pattern fundamentally flawed for network-dependent operations?**
   - Would a custom tool be better than a Bash command?
   - How can we maintain the skill pattern while fixing network access?

4. **Docker + bubblewrap networking quirks:**
   - Are there known issues with bubblewrap networking inside Docker?
   - Do we need additional capabilities or configuration?

## Request

Please analyze this architecture and suggest the most robust solution that:
1. Maintains security (sandboxed execution)
2. Reliably enables network access to approved APIs (api.openai.com)
3. Keeps the skill-based architecture if possible
4. Works in Docker + bubblewrap environment
