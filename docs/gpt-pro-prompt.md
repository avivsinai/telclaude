<file_tree>
telclaude/
├── .claude/
│   └── skills/
│       └── image-generator/
│           └── SKILL.md
├── docs/
│   ├── architecture.md
│   └── debug-image-generation.md
└── src/
    ├── commands/
    │   └── generate-image.ts
    ├── sandbox/
    │   ├── config.ts
    │   ├── domains.ts
    │   └── manager.ts
    └── services/
        ├── image-generation.ts
        └── openai-client.ts</file_tree>

<files>
File: .claude/skills/image-generator/SKILL.md (562 tokens)
```
---
name: image-generator
description: Generates images using GPT Image 1.5 API. Use when users request image creation, illustration, or visual content.
---

# Image Generation Skill

You can generate images using the GPT Image 1.5 API when users request visual content.

## When to Use

Use this skill when users:
- Ask to "create", "generate", "draw", or "make" an image
- Request illustrations, artwork, diagrams, or visual content
- Want to visualize concepts, ideas, or descriptions

## How to Generate Images

To generate an image, use the Bash tool to run the telclaude image generation command:

```bash
telclaude generate-image "your detailed prompt here"
```

### Options

- `--size`: Image dimensions. Default: 1024x1024
  - `auto`: Let the model choose optimal size
  - `1024x1024`: Square (default)
  - `1536x1024`: Landscape
  - `1024x1536`: Portrait
- `--quality`: Quality tier (low, medium, high). Default: medium
  - low: ~$0.01/image, fastest
  - medium: ~$0.04/image, balanced
  - high: ~$0.17/image, best quality

### Example

```bash
telclaude generate-image "A serene mountain landscape at sunset with a lake reflection" --quality high --size 1536x1024
```

## Response Format

After generation, the command outputs:
- The local file path where the image was saved
- File size in KB
- Model used

**Important**: Tell the user the image has been generated and include the file path in your response. The image file is saved locally and the user can access it at that path.

## Best Practices

1. **Be Descriptive**: Include details about style, mood, colors, composition
2. **Specify Style**: Mention if you want photorealistic, illustration, cartoon, etc.
3. **Avoid Prohibited Content**: No copyrighted characters, real people, or inappropriate content
4. **Consider Cost**: Use "low" quality for quick drafts, "high" for final images

## Limitations

- Maximum 10 images per hour per user (configurable)
- Maximum 50 images per day per user (configurable)
- Some content may be blocked by OpenAI's safety filters
- Images are stored temporarily and cleaned up after 24 hours

## Cost Awareness

Inform users of approximate costs when generating multiple images:
- 1024x1024 medium quality: ~$0.04 each
- High quality or larger sizes cost more

```

File: docs/architecture.md (2259 tokens)
```
# Telclaude Architecture Deep Dive

Updated: 2025-12-06  
Scope: detailed design and security rationale for telclaude (Telegram ⇄ Claude Code relay).

## Runtime guardrail notes (dec 2025)
- **Network enforcement model**:
  - **Bash**: SDK sandbox `allowedDomains` (OS-level, strict allowlist always)
  - **WebFetch**: PreToolUse hook (PRIMARY) + `canUseTool` callback (fallback).
  - **WebSearch**: NOT filtered. Uses `query` parameter (not `url`); requests made server-side by Anthropic's search service, not by the local process.
- `TELCLAUDE_NETWORK_MODE=open|permissive` enables broad egress for **WebFetch only**. Private/metadata still blocked via PreToolUse hook.
- SDK permission rules for network are NOT used (SDK matcher doesn't support needed wildcards). WebFetch filtering is in PreToolUse hook + `canUseTool` fallback.
- **Settings isolation (disableAllHooks defense)**:
  - `settingSources: ["project"]` always set - user settings (~/.claude/settings.json) are never loaded.
  - Writes to `.claude/settings.json` and `.claude/settings.local.json` are blocked via sensitive paths.
  - This two-layer defense prevents both: (1) user settings with `disableAllHooks: true`, (2) prompt injection writing `disableAllHooks` to project settings.
  - NOTE: This means user-level model overrides, plugins, etc. won't load in telclaude. This is intentional.
- Read model is deny-list based: files outside the sensitive path list are readable if the user/agent asks. Seatbelt/bubblewrap plus the sensitive denyRead set provide defense-in-depth, but absolute allow-list reads are not supported by the runtime. For stricter isolation, run inside Docker/WSL with a minimal bind-mounted workspace.

## System Overview

```
Telegram Bot API
      │
      ▼
┌────────────────────────────────────────────┐
│ Security Layer                             │
│ • Fast-path regex (part of observer)       │
│ • Security observer (security-gate skill)  │
│ • Permission tiers & approvals             │
│ • Rate limits & audit                      │
│ • Identity linking                         │
└────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────┐
│ OS Sandbox (mandatory)                     │
│ • Seatbelt (macOS) / bubblewrap (Linux)    │
│ • Tier-aligned write rules + private /tmp  │
│ • Network filtering                        │
└────────────────────────────────────────────┘
      │
      ▼
Claude Agent SDK (allowedTools per tier)
      │
      ▼
TOTP daemon (separate process, keychain-backed)
```

## Security Profiles
- **simple (default)**: sandbox + secret filter + rate limits + audit. No observer/approvals.
- **strict (opt-in)**: adds Haiku observer, approvals, and tier enforcement.
- **test**: disables all enforcement; gated by `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Five Security Pillars
1) Filesystem isolation (deny sensitive paths; private `/tmp`; host `/tmp`/`/var/tmp`/`/run/user` denied).
2) Environment isolation (allowlist env vars).
3) Network isolation (strict default allowlist for Bash; metadata + RFC1918 always blocked for WebFetch; `TELCLAUDE_NETWORK_MODE=open|permissive` enables broad egress for WebFetch only; WebSearch is NOT filtered - server-side by Anthropic).
4) Secret output filtering (CORE patterns + entropy, streaming; infrastructure secrets are non-overridable blockers).
5) Auth/rate limits/audit (identity links, TOTP auth gate for periodic identity verification, SQLite-backed).

## Design notes
- Sandbox is mandatory; relay exits if sandbox-runtime prerequisites are missing.  
- Enforcement vs policy: sandbox + secret filter + rate limits + auth are always enforced; tiers/observer/approvals are policy layers.  
- WRITE_LOCAL is for accidental safety; sandbox still enforces filesystem/network limits.  
- Profiles:  
  - simple (default): sandbox + secret filter + rate limits + audit + tiers; observer/approvals off.  
  - strict: adds security observer (fast-path + LLM) and approval workflow.  
  - test: disables enforcement; requires `TELCLAUDE_ENABLE_TEST_PROFILE=1`.

## Permission Tiers

| Tier | Tools | Extra safeguards | Notes |
| --- | --- | --- | --- |
| READ_ONLY | Read, Glob, Grep, WebFetch, WebSearch | No writes allowed | Sandbox blocks writes; SDK default write paths mitigated via denyWrite |
| WRITE_LOCAL | READ_ONLY + Write, Edit, Bash | Blocks destructive/bash & dangerous patterns (rm/rmdir/mv/chmod/chown/kill, curl\|sh, netcat, git hooks, path redirects, etc.); denyWrite patterns for secrets | Prevents accidents, not malicious intent |
| FULL_ACCESS | All tools | Approval required unless user is claimed admin | Same sandbox as WRITE_LOCAL; `bypassPermissions` gated by approval/identity |

## OS-Level Sandbox
- **macOS**: Seatbelt via `sandbox-exec`.
- **Linux**: bubblewrap + socat proxy; glob patterns expanded once at startup (newly created matching files after init are not auto-blocked).
- Tier-aligned write rules: READ_ONLY (no writes), WRITE_LOCAL/FULL_ACCESS (cwd + `~/.telclaude/sandbox-tmp`).
- Deny-read includes `~/.ssh`, `~/.aws`, `~/.telclaude`, shell histories, host `/tmp`/`/var/tmp`/`/run/user`, etc.; private temp at `~/.telclaude/sandbox-tmp`.
- **Network for Bash**: SDK sandbox `allowedDomains` (OS-level, strict allowlist always). Bash cannot reach arbitrary domains even in permissive mode.
- **Network for WebFetch**: PreToolUse hook (PRIMARY) + `canUseTool` fallback. In permissive mode, allows all public domains while blocking private/metadata.
- **Network for WebSearch**: NOT filtered. Uses `query` parameter (not `url`); requests made server-side by Anthropic's search service.
- SDK sandbox is the primary enforcement layer for Bash. WebFetch uses PreToolUse hook + `canUseTool` for network filtering.
- **Settings files**: `.claude/settings.json` and `.claude/settings.local.json` are blocked as sensitive paths (prevents prompt injection from writing `disableAllHooks`).

## Session & Conversation Model
- Uses stable `query()` API with resume support; 30‑minute cache.  
- Per-chat session IDs; idle timeout configurable.  
- Implemented in `src/sdk/session-manager.ts`.

## Control Plane & Auth
- **Identity linking**: `/link` codes generated via CLI; stored in SQLite.
- **First-time admin claim**: private chat only, short-lived approval code.
- **TOTP auth gate (identity verification)**: Periodic identity check when session expires (default: 4 hours). Runs BEFORE any message processing. Separate daemon process, Unix socket IPC, secrets in OS keychain (native) or encrypted file backend in Docker.
- **Approvals (intent confirmation)**: Nonce-based confirmation for dangerous operations. Required for FULL_ACCESS (except claimed admin), all BLOCK classifications, WARN with WRITE_LOCAL, and low-confidence WARN; TTL 5 minutes.
- **Emergency controls**: CLI-only `ban`/`unban` (prevents attacker with Telegram+TOTP from unbanning themselves), `force-reauth`, `list-bans`. Telegram `/force-reauth [chat-id]` available for admins.

## Observer & Fast Path
- Fast-path regex handles obvious safe/unsafe patterns and structural issues (zero-width chars, mixed scripts, repetition).  
- Observer uses the security-gate skill via Claude Agent SDK (`query` with allowedTools: Skill); dangerThreshold downgrades BLOCK→WARN and WARN→ALLOW when confidence is low; circuit breaker + timeout fallback (`fallbackOnTimeout` default: block).  
- WARN/BLOCK may trigger approvals per tier rules above.

## Persistence
- SQLite at `~/.telclaude/telclaude.db` stores approvals, rate limits, identity links, sessions, and audit metadata.  
- Config path resolution in `src/config/path.ts`; schema in `src/config/config.ts`.

## Message Flow (strict profile)
1) Telegram message received.
2) Ban check — blocked users silently rejected.
3) Admin claim flow (if no admin configured yet).
4) TOTP auth gate — if session expired, challenge and save message; on valid code, create session and replay.
5) Control-plane commands handled (`/link`, `/approve`, `/deny`, `/whoami`, `/force-reauth`, etc.).
6) Infrastructure secret block (non-overridable).
7) Rate-limit check.
8) Observer: structural checks + fast path, then LLM if needed.
9) Approval gate (nonce-based, per tier/classification).
10) Session lookup/resume.
11) Tier lookup (identity links/admin claim).
12) SDK query with tiered allowedTools inside sandbox.
13) Streaming reply to Telegram; audit logged.

## Deployment Notes
- **Production**: Docker/WSL Compose adds container boundary, read-only root FS, dropped caps, optional outbound firewall; TOTP sidecar uses encrypted file backend.  
- **Native**: macOS 14+ or Linux with bubblewrap, socat, ripgrep on PATH; sandbox mandatory (relay refuses to start otherwise).  
- Keep `~/.telclaude/telclaude.json` chmod 600; `defaultTier=FULL_ACCESS` rejected at startup.

## Troubleshooting Pointers
- Bot silent: ensure `allowedChats` set and rate limits not exceeded.  
- Sandbox unavailable: install seatbelt/bubblewrap deps; see `pnpm dev doctor --network --secrets`.  
- TOTP issues: daemon running; device time synced.  
- SDK/observer errors: Claude CLI installed and `claude login` done.

## File Map (high-touch)
- `src/security/*` — pipeline, permissions, observer, approvals, rate limits.  
- `src/sandbox/*` — OS sandbox config.  
- `src/sdk/*` — Claude SDK integration and session manager.  
- `src/telegram/*` — inbound/outbound bot wiring.  
- `src/commands/*` — CLI commands.  
- `.claude/skills/*` — skills auto-loaded by SDK.

```

File: docs/debug-image-generation.md (2634 tokens)
```
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

```

File: src/commands/generate-image.ts (765 tokens)
```
/**
 * CLI command for generating images.
 * Used by Claude via the image-generator skill.
 */

import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import {
	generateImage,
	getEstimatedCost,
	isImageGenerationAvailable,
} from "../services/image-generation.js";
import { initializeOpenAIKey } from "../services/openai-client.js";

const logger = getChildLogger({ module: "cmd-generate-image" });

type ImageSize = "auto" | "1024x1024" | "1536x1024" | "1024x1536";

export type GenerateImageOptions = {
	size?: ImageSize;
	quality?: "low" | "medium" | "high";
	verbose?: boolean;
};

export function registerGenerateImageCommand(program: Command): void {
	program
		.command("generate-image")
		.description("Generate an image using GPT Image 1.5")
		.argument("<prompt>", "Text description of the image to generate")
		.option("-s, --size <size>", "Image size: auto, 1024x1024, 1536x1024, 1024x1536", "1024x1024")
		.option("-q, --quality <quality>", "Quality tier: low, medium, high", "medium")
		.action(async (prompt: string, opts: GenerateImageOptions) => {
			const verbose = program.opts().verbose || opts.verbose;

			try {
				// Initialize keychain lookup so isImageGenerationAvailable() works correctly
				await initializeOpenAIKey();

				if (!isImageGenerationAvailable()) {
					console.error(
						"Error: Image generation not available.\n" +
							"Run: telclaude setup-openai\n" +
							"Or set OPENAI_API_KEY environment variable.",
					);
					process.exit(1);
				}

				const size = validateSize(opts.size);
				const quality = validateQuality(opts.quality);

				if (verbose) {
					const cost = getEstimatedCost(size, quality);
					console.log(`Generating image with ${quality} quality at ${size}...`);
					console.log(`Estimated cost: $${cost.toFixed(2)}`);
				}

				const result = await generateImage(prompt, {
					size,
					quality,
				});

				// Output in a format that's easy to parse
				console.log(`Generated image saved to: ${result.path}`);
				console.log(`Size: ${(result.sizeBytes / 1024).toFixed(1)} KB`);
				console.log(`Model: ${result.model}`);

				if (result.revisedPrompt && verbose) {
					console.log(`Revised prompt: ${result.revisedPrompt}`);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "generate-image command failed");
				console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
				process.exit(1);
			}
		});
}

function validateSize(size?: string): ImageSize {
	const valid: ImageSize[] = ["auto", "1024x1024", "1536x1024", "1024x1536"];
	if (size && valid.includes(size as ImageSize)) {
		return size as ImageSize;
	}
	return "1024x1024";
}

function validateQuality(quality?: string): "low" | "medium" | "high" {
	const valid = ["low", "medium", "high"];
	if (quality && valid.includes(quality)) {
		return quality as "low" | "medium" | "high";
	}
	return "medium";
}

```

File: src/sandbox/config.ts (4332 tokens)
```
/**
 * Sandbox configuration for telclaude.
 *
 * SECURITY ARCHITECTURE:
 * Uses @anthropic-ai/sandbox-runtime to isolate Claude's execution environment.
 * This provides OS-level sandboxing (Seatbelt on macOS, bubblewrap on Linux).
 *
 * Security model:
 * - Filesystem: Deny ~ broadly, allow only workspace
 * - Environment: Allowlist-only model (see src/sandbox/env.ts)
 * - Network: Domain + method restrictions via proxy
 * - Private temp: Writes go to ~/.telclaude/sandbox-tmp and host /tmp is denyRead.
 *   On Linux, we set TMPDIR to the private temp before sandbox init so network sockets
 *   are created there, allowing host /tmp to be safely blocked.
 *
 * Tier-aligned configs:
 * - READ_ONLY: No writes allowed
 * - WRITE_LOCAL/FULL_ACCESS: Writes to workspace + private temp
 *
 * LINUX GLOB WORKAROUND:
 * The @anthropic-ai/sandbox-runtime library silently drops glob patterns on Linux
 * (bubblewrap doesn't support them). We work around this by expanding globs to
 * literal paths before passing to the sandbox. See glob-expansion.ts for details.
 */

import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { DEFAULT_ALLOWED_DOMAIN_NAMES } from "./domains.js";
import { expandGlobsForLinux, getGlobPatterns, isLinux } from "./glob-expansion.js";

const IS_PROD = process.env.TELCLAUDE_ENV === "prod" || process.env.NODE_ENV === "production";

/**
 * Sensitive paths that should never be readable by sandboxed processes.
 * These include telclaude's own data and common credential stores.
 *
 * LINUX LIMITATION: On Linux, glob patterns like ".env" and "secrets.*" are
 * expanded to literal paths at sandbox initialization time. Two caveats:
 * 1. Files matching these patterns CREATED AFTER init will NOT be protected
 * 2. Expansion runs from cwd AND home directory to cover sensitive files outside cwd
 *
 * This is a fundamental limitation of bubblewrap (Linux sandbox).
 * See glob-expansion.ts for details.
 *
 * On macOS (Seatbelt), glob patterns work natively and these limitations do not apply.
 */
export const SENSITIVE_READ_PATHS = [
	// === Telclaude data ===
	"~/.telclaude", // Block entire dir - media saved to workspace instead

	// === Environment files (secrets!) ===
	// These patterns block .env files anywhere in readable paths
	"**/.env",
	"**/.env.*", // .env.local, .env.production, etc.
	"**/.envrc", // direnv files
	"**/secrets.json",
	"**/secrets.yaml",
	"**/secrets.yml",

	// NOTE: ~/.claude is NOT blocked because Claude CLI needs it for authentication.
	// The srt sandbox wraps the entire Claude process, so blocking ~/.claude would
	// prevent Claude from reading its own OAuth tokens and settings.

	// === Claude desktop app data ===
	"~/Library/Application Support/Claude", // macOS app data

	// === Shell configuration files (can inject startup malware) ===
	"~/.bashrc",
	"~/.bash_profile",
	"~/.bash_login",
	"~/.zshrc",
	"~/.zprofile",
	"~/.zlogin",
	"~/.zshenv",
	"~/.profile",
	"~/.login",
	"~/.cshrc",
	"~/.tcshrc",
	"~/.config/fish/config.fish",

	// === Shell history (may contain typed secrets) ===
	"~/.bash_history",
	"~/.zsh_history",
	"~/.zsh_sessions",
	"~/.sh_history",
	"~/.history",
	"~/.lesshst",
	"~/.node_repl_history",
	"~/.python_history",
	"~/.psql_history",
	"~/.mysql_history",
	"~/.sqlite_history",
	"~/.rediscli_history",

	// === SSH/GPG keys ===
	"~/.ssh", // SSH keys
	"~/.gnupg", // GPG keys

	// === Cloud credentials ===
	"~/.aws", // AWS credentials
	"~/.azure", // Azure credentials
	"~/.config/gcloud", // GCP credentials
	"~/.kube", // Kubernetes configs
	"~/.docker/config.json", // Docker registry auth

	// === Package manager auth ===
	"~/.npmrc", // npm auth tokens
	"~/.pypirc", // PyPI credentials
	"~/.gem/credentials", // RubyGems
	"~/.cargo/credentials", // Cargo/crates.io

	// === Git credentials ===
	"~/.netrc", // Various service credentials
	"~/.git-credentials", // Git credentials

	// === Browser profiles (localStorage may have tokens) ===
	"~/Library/Application Support/Google/Chrome",
	"~/Library/Application Support/Firefox",
	"~/Library/Application Support/Arc",
	"~/.config/chromium",
	"~/.config/google-chrome",
	"~/.mozilla",

	// NOTE: ~/Library/Keychains is NOT blocked to allow Claude CLI subscription auth.
	// Claude uses macOS Keychain to store OAuth tokens from `claude login`.
	// Blocking Keychain would require ANTHROPIC_API_KEY which triggers API billing.
	// Trade-off: Keychain access grants potential access to OTHER stored secrets.
	// Mitigations:
	// - Claude's Seatbelt profile restricts Keychain access to its own items
	// - Network isolation prevents exfiltration
	// - Output filter catches leaked secrets

	// === Linux proc filesystem ===
	"/proc/self/environ", // Environment variables
	"/proc/self/cmdline", // Command line args

	// === Temp directories ===
	// Host temp directories contain secrets: SSH agent sockets, keyring sockets,
	// D-Bus sockets, credential files, etc.
	//
	// IMPORTANT: We set TMPDIR to our private temp (~/.telclaude/sandbox-tmp) BEFORE
	// calling SandboxManager.initialize() in manager.ts. This makes sandbox-runtime
	// create its network bridge sockets there instead of /tmp, allowing us to safely
	// block host /tmp and /var/tmp without breaking network functionality.
	"/tmp",
	"/var/tmp",

	// systemd user runtime directories (contains keyring, gpg-agent, ssh-agent, etc.)
	"/run/user",
];

/**
 * Private temporary directory for sandboxed processes.
 * This is used instead of host /tmp to prevent reading secrets.
 */
export const PRIVATE_TMP_PATH = "~/.telclaude/sandbox-tmp";

/**
 * Default write-allowed paths (excluding cwd which must be passed dynamically).
 * Sandboxed processes can only write to these locations plus their cwd.
 *
 * Note: We use PRIVATE_TMP_PATH instead of /tmp to prevent
 * reading secrets from host /tmp (keyring sockets, dbus secrets, etc.)
 */
export const DEFAULT_WRITE_PATHS = [
	PRIVATE_TMP_PATH, // Private temp dir (host /tmp is blocked)
	// Claude CLI config + atomic temp files
	"~/.claude.json",
	"~/.claude.json.*",
	// Claude CLI workspace data (sessions, history, logs)
	"~/.claude",
	"~/.claude/**",
];

/**
 * @deprecated Use PRIVATE_TMP_PATH instead. This is kept for backward compatibility.
 * The SDK doesn't support bind mounts, so we block host /tmp via denyRead
 * and allow writes to PRIVATE_TMP_PATH instead.
 */
export const PRIVATE_TMP_CONFIG = {
	hostPath: PRIVATE_TMP_PATH,
	sandboxPath: PRIVATE_TMP_PATH, // No actual mounting, just the write-allowed path
};

// NOTE: Symlink protection is NOT implemented. The @anthropic-ai/sandbox-runtime
// SDK does not support symlink policies. The underlying sandbox (Seatbelt/bubblewrap)
// may provide some protection, but it's not configurable via the SDK.
// DO NOT claim symlink protection in documentation.

/**
 * Cloud metadata endpoints that should be blocked to prevent SSRF attacks.
 * These are used by cloud providers for instance metadata and credentials.
 */
export const BLOCKED_METADATA_DOMAINS = [
	// Cloud instance metadata service IP (used by multiple providers: AWS/GCP/Azure/OCI/DO)
	"169.254.169.254",
	// AWS ECS container metadata
	"169.254.170.2",
	// GCP metadata hostnames (resolve to 169.254.169.254)
	"metadata.google.internal",
	"metadata.goog",
	// Kubernetes service DNS (often internal IPs / service account token endpoints)
	"kubernetes.default.svc",
	// Alibaba Cloud metadata
	"100.100.100.200",
];

/**
 * RFC1918 private networks - always blocked.
 * Prevents accessing internal services, routers, etc.
 */
export const BLOCKED_PRIVATE_NETWORKS = [
	// Localhost
	"127.0.0.0/8",
	"::1",
	"localhost",
	// RFC1918 private ranges
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	// Link-local
	"169.254.0.0/16",
	// IPv6 private/link-local ranges
	"fc00::/7",
	"fe80::/10",
];

/**
 * Paths that should never be writable, even if in an allowed write path.
 * This is a safety net for sensitive files that might be in cwd.
 *
 * IMPORTANT: sandbox-runtime adds default write paths internally (e.g., /tmp/claude,
 * ~/.claude/debug) that we cannot disable. These denyWrite patterns are applied
 * to ALL writable paths, providing defense-in-depth against writing sensitive
 * file patterns to sandbox-runtime's internal paths.
 *
 * LINUX LIMITATION: On Linux, glob patterns (*.pem, *.key, .env.*, etc.) are
 * expanded to literal paths at sandbox initialization time. Files matching these
 * patterns that are CREATED AFTER init will NOT be protected by denyWrite.
 * This is a fundamental limitation of bubblewrap (Linux sandbox).
 *
 * Mitigations:
 * - Output filter (CORE patterns) catches secrets in output regardless of filesystem
 * - Most sensitive files (SSH keys, credentials) pre-exist before the sandbox runs
 * - The sandbox is defense-in-depth, not the primary security mechanism
 *
 * On macOS (Seatbelt), glob patterns work natively and this limitation does not apply.
 */
export const DENY_WRITE_PATHS = [
	// === Environment secrets ===
	".env",
	".env.local",
	".env.production",
	".env.development",
	".env.*", // Catch all .env variants
	".envrc", // direnv
	"secrets.json",
	"secrets.yaml",
	"secrets.yml",

	// === SSH keys ===
	"id_rsa",
	"id_rsa.pub",
	"id_ed25519",
	"id_ed25519.pub",
	"id_ecdsa",
	"id_ecdsa.pub",
	"id_dsa",
	"id_dsa.pub",
	"authorized_keys",
	"known_hosts",
	"*.pem",
	"*.key",
	"*.ppk", // PuTTY private keys

	// === SSL/TLS certificates and keys ===
	"*.crt",
	"*.cer",
	"*.p12",
	"*.pfx",
	"*.jks", // Java keystore

	// === Cloud provider credentials ===
	"credentials.json", // GCP service account
	"service-account.json",
	"credentials", // AWS credentials file
	"config", // AWS config (when writing to ~/.aws/)

	// === Package manager auth ===
	".npmrc",
	".pypirc",
	".netrc",
	".git-credentials",
	".gitconfig",

	// === Shell configuration (prevent injection) ===
	".bashrc",
	".bash_profile",
	".zshrc",
	".zprofile",
	".profile",
	"config.fish",

	// === GPG keys ===
	"*.gpg",
	"*.asc",
	"pubring.kbx",
	"trustdb.gpg",

	// === Kubernetes/Docker ===
	"kubeconfig",
	"config.json", // Docker config

	// === Generic secret patterns ===
	"*_secret*",
	"*_private*",
	"*_token*",
	"*_credential*",
];

const logger = getChildLogger({ module: "sandbox-config" });

function hashString(value: string): string {
	let hash = 2166136261;
	for (let i = 0; i < value.length; i++) {
		hash ^= value.charCodeAt(i);
		hash = (hash * 16777619) >>> 0;
	}
	return hash.toString(16);
}

function domainsCacheKey(domains?: string[]): string {
	if (!domains || domains.length === 0) return "default";
	const normalized = domains.map((domain) => domain.toLowerCase()).sort();
	return hashString(normalized.join("|"));
}

/**
 * Build sandbox configuration.
 *
 * On Linux, glob patterns are expanded to literal paths since bubblewrap
 * doesn't support globs. This is a point-in-time expansion.
 *
 * @param options - Configuration overrides
 * @returns SandboxRuntimeConfig for the sandbox manager
 */
export function buildSandboxConfig(options: {
	/** Additional paths to deny reading */
	additionalDenyRead?: string[];
	/** Additional paths to allow writing */
	additionalAllowWrite?: string[];
	/** Allowed network domains (default: strict allowlist) */
	allowedDomains?: string[];
	/** Denied network domains (takes precedence over allowed) */
	deniedDomains?: string[];
	/** Allow Unix socket access (e.g., for Docker) */
	allowUnixSockets?: string[];
	/** Working directory for glob expansion (default: process.cwd()) */
	cwd?: string;
}): SandboxRuntimeConfig {
	const cwd = options.cwd ?? process.cwd();
	const envNetworkMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();

	const resolvedDefaultAllowed = DEFAULT_ALLOWED_DOMAIN_NAMES;
	if (envNetworkMode === "open" || envNetworkMode === "permissive") {
		logger.warn(
			{ mode: envNetworkMode },
			"TELCLAUDE_NETWORK_MODE enabled: broad egress will be allowed (private/metadata still blocked)",
		);
	}

	// Collect all deny/allow paths
	let denyRead = [...SENSITIVE_READ_PATHS, ...(options.additionalDenyRead ?? [])];
	let denyWrite = [...DENY_WRITE_PATHS];
	let allowWrite = [...DEFAULT_WRITE_PATHS, ...(options.additionalAllowWrite ?? [])];

	// LINUX GLOB WORKAROUND: Expand globs to literal paths
	// The sandbox-runtime silently drops glob patterns on Linux
	if (isLinux()) {
		const denyReadGlobs = getGlobPatterns(denyRead);
		const denyWriteGlobs = getGlobPatterns(denyWrite);

		const allowWriteGlobs = getGlobPatterns(allowWrite);

		if (denyReadGlobs.length > 0 || denyWriteGlobs.length > 0 || allowWriteGlobs.length > 0) {
			logger.warn(
				{
					denyReadGlobs: denyReadGlobs.length,
					denyWriteGlobs: denyWriteGlobs.length,
					allowWriteGlobs: allowWriteGlobs.length,
					patterns: [...denyReadGlobs, ...denyWriteGlobs, ...allowWriteGlobs].slice(0, 10),
				},
				"Linux sandbox: expanding glob patterns to literal paths (bubblewrap limitation)",
			);
		}

		denyRead = expandGlobsForLinux(denyRead, cwd);
		denyWrite = expandGlobsForLinux(denyWrite, cwd);
		allowWrite = expandGlobsForLinux(allowWrite, cwd);
	}

	return {
		filesystem: {
			denyRead,
			allowWrite,
			denyWrite,
		},
		network: {
			// Default to strict allowlist using well-known developer domains.
			// Users can opt into broader access via options.allowedDomains (config).
			allowedDomains: options.allowedDomains ?? resolvedDefaultAllowed,
			// SECURITY: Always block cloud metadata endpoints to prevent SSRF
			deniedDomains: [...BLOCKED_METADATA_DOMAINS, ...(options.deniedDomains ?? [])],
			allowUnixSockets: options.allowUnixSockets ?? [],
			// In dev we allow local binding/Unix sockets to avoid host-seatbelt friction.
			allowLocalBinding: !IS_PROD,
			// SECURITY: Disable arbitrary Unix socket creation in prod; relax in dev to reduce failures.
			allowAllUnixSockets: !IS_PROD,
		},
	};
}

/**
 * Default sandbox configuration.
 * Uses a strict network allowlist and restricts filesystem access to sensitive paths.
 */
export const DEFAULT_SANDBOX_CONFIG = buildSandboxConfig({});

// ═══════════════════════════════════════════════════════════════════════════════
// Tier-Aligned Sandbox Configs
// ═══════════════════════════════════════════════════════════════════════════════

// Cache tier configs to avoid repeated Linux glob expansion per query.
// Keyed by `${tier}:${cwd}`; env-based tweaks (e.g., TELCLAUDE_NETWORK_MODE) are assumed stable per process.
const sandboxTierConfigCache = new Map<string, SandboxRuntimeConfig>();

/**
 * Get sandbox configuration for a specific permission tier.
 *
 * The sandbox enforces what Claude CAN do (enforcement),
 * while the tier controls what Claude SHOULD do (policy).
 * The sandbox matches the tier, not more restrictive.
 *
 * @param tier - Permission tier
 * @param cwd - Working directory to allow writes to (for WRITE_LOCAL/FULL_ACCESS) and for glob expansion
 * @returns SandboxRuntimeConfig with tier-appropriate permissions
 *
 * - READ_ONLY: No writes allowed
 * - WRITE_LOCAL: Writes to cwd + private temp
 * - FULL_ACCESS: Same as WRITE_LOCAL (sandbox is safety net, not policy)
 */
export function getSandboxConfigForTier(
	tier: PermissionTier,
	cwd?: string,
	options: { allowedDomains?: string[] } = {},
): SandboxRuntimeConfig {
	const workingDir = cwd ?? process.cwd();
	const cacheKey = `${tier}:${workingDir}:${domainsCacheKey(options.allowedDomains)}`;
	const cached = sandboxTierConfigCache.get(cacheKey);
	if (cached) {
		return cached;
	}

	if (tier === "READ_ONLY") {
		// No writes allowed for read-only tier
		// Still pass cwd for glob expansion on Linux
		const baseConfig = buildSandboxConfig({
			cwd: workingDir,
			allowedDomains: options.allowedDomains,
		});
		const ro: SandboxRuntimeConfig = {
			...baseConfig,
			filesystem: {
				...baseConfig.filesystem,
				allowWrite: [], // No writes for READ_ONLY
			},
		};
		sandboxTierConfigCache.set(cacheKey, ro);
		return ro;
	}

	// WRITE_LOCAL and FULL_ACCESS: allow writes to cwd and private temp
	const rw = buildSandboxConfig({
		additionalAllowWrite: cwd ? [cwd] : [],
		cwd: workingDir,
		allowedDomains: options.allowedDomains,
	});
	sandboxTierConfigCache.set(cacheKey, rw);
	return rw;
}

/**
 * Pre-warm the sandbox tier config cache for a given cwd.
 * Call this at startup to avoid slow glob expansion on first message.
 *
 * @param cwd - Working directory to pre-warm configs for
 */
export function prewarmSandboxConfigCache(cwd: string, allowedDomains?: string[]): void {
	const tiers: PermissionTier[] = ["READ_ONLY", "WRITE_LOCAL", "FULL_ACCESS"];
	for (const tier of tiers) {
		getSandboxConfigForTier(tier, cwd, { allowedDomains });
	}
	logger.info({ cwd, tiers: tiers.length }, "pre-warmed sandbox tier config cache");
}

```

File: src/sandbox/domains.ts (1436 tokens)
```
/**
 * Network domain allowlist for sandboxed network access.
 *
 * Simplified: Single allowlist with all developer-friendly domains.
 * OpenAI is always included (harmless without key exposure via env var).
 */

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export interface DomainRule {
	domain: string;
	methods: HttpMethod[];
}

/**
 * Common package registry domains (read-only).
 */
export const PACKAGE_MANAGER_DOMAINS: DomainRule[] = [
	{ domain: "registry.npmjs.org", methods: ["GET", "HEAD"] },
	{ domain: "registry.yarnpkg.com", methods: ["GET", "HEAD"] },
	{ domain: "pypi.org", methods: ["GET", "HEAD"] },
	{ domain: "files.pythonhosted.org", methods: ["GET", "HEAD"] },
	{ domain: "crates.io", methods: ["GET", "HEAD"] },
	{ domain: "static.crates.io", methods: ["GET", "HEAD"] },
	{ domain: "index.crates.io", methods: ["GET", "HEAD"] },
	{ domain: "rubygems.org", methods: ["GET", "HEAD"] },
	{ domain: "repo.maven.apache.org", methods: ["GET", "HEAD"] },
	{ domain: "repo1.maven.org", methods: ["GET", "HEAD"] },
	{ domain: "api.nuget.org", methods: ["GET", "HEAD"] },
	{ domain: "proxy.golang.org", methods: ["GET", "HEAD"] },
	{ domain: "sum.golang.org", methods: ["GET", "HEAD"] },
	{ domain: "repo.packagist.org", methods: ["GET", "HEAD"] },
];

/**
 * Documentation domains (read-only).
 */
export const DOC_DOMAINS: DomainRule[] = [
	{ domain: "docs.python.org", methods: ["GET", "HEAD"] },
	{ domain: "docs.rs", methods: ["GET", "HEAD"] },
	{ domain: "developer.mozilla.org", methods: ["GET", "HEAD"] },
	{ domain: "stackoverflow.com", methods: ["GET", "HEAD"] },
	{ domain: "*.stackexchange.com", methods: ["GET", "HEAD"] },
];

/**
 * Code hosting domains (read-only by default).
 * POST requires explicit config - prevents pushing secrets to repos.
 */
export const CODE_HOST_DOMAINS: DomainRule[] = [
	{ domain: "github.com", methods: ["GET", "HEAD"] },
	{ domain: "api.github.com", methods: ["GET", "HEAD"] },
	{ domain: "codeload.github.com", methods: ["GET", "HEAD"] },
	{ domain: "objects.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gitlab.com", methods: ["GET", "HEAD"] },
	{ domain: "bitbucket.org", methods: ["GET", "HEAD"] },
	{ domain: "raw.githubusercontent.com", methods: ["GET", "HEAD"] },
	{ domain: "gist.githubusercontent.com", methods: ["GET", "HEAD"] },
];

/**
 * CDN domains used by package ecosystems (read-only).
 */
export const CDN_DOMAINS: DomainRule[] = [
	{ domain: "unpkg.com", methods: ["GET", "HEAD"] },
	{ domain: "cdn.jsdelivr.net", methods: ["GET", "HEAD"] },
];

/**
 * Anthropic API + Claude Code endpoints.
 */
export const ANTHROPIC_DOMAINS: DomainRule[] = [
	{ domain: "api.anthropic.com", methods: ["GET", "HEAD", "POST"] },
	{ domain: "claude.ai", methods: ["GET", "HEAD", "POST"] },
	{ domain: "*.claude.ai", methods: ["GET", "HEAD", "POST"] },
	{ domain: "code.anthropic.com", methods: ["GET", "HEAD", "POST"] },
	{ domain: "*.code.anthropic.com", methods: ["GET", "HEAD", "POST"] },
];

/**
 * OpenAI API domains.
 * Always included in allowlist - harmless without TELCLAUDE_OPENAI_SANDBOX_EXPOSE=1.
 */
export const OPENAI_DOMAINS: DomainRule[] = [
	{ domain: "api.openai.com", methods: ["GET", "HEAD", "POST"] },
];

/**
 * Default domain allowlist with all developer-friendly domains.
 */
export const DEFAULT_ALLOWED_DOMAINS: DomainRule[] = [
	...PACKAGE_MANAGER_DOMAINS,
	...DOC_DOMAINS,
	...CODE_HOST_DOMAINS,
	...CDN_DOMAINS,
	...ANTHROPIC_DOMAINS,
	...OPENAI_DOMAINS,
];

/**
 * Build the allowed domains list with optional additional domains.
 *
 * @param additionalDomains - Extra domains to allow (GET/HEAD only)
 */
export function buildAllowedDomains(additionalDomains: string[] = []): DomainRule[] {
	const extraRules = additionalDomains.map((domain) => ({
		domain,
		methods: ["GET", "HEAD"] as HttpMethod[],
	}));

	const combined = [...DEFAULT_ALLOWED_DOMAINS, ...extraRules];

	// Merge duplicate domains
	const merged = new Map<string, Set<HttpMethod>>();
	for (const rule of combined) {
		const key = rule.domain.toLowerCase();
		const set = merged.get(key) ?? new Set<HttpMethod>();
		for (const method of rule.methods) {
			set.add(method);
		}
		merged.set(key, set);
	}

	return Array.from(merged.entries()).map(([domain, methods]) => ({
		domain,
		methods: Array.from(methods),
	}));
}

/**
 * Build the allowed domain names (strings only).
 */
export function buildAllowedDomainNames(additionalDomains: string[] = []): string[] {
	return buildAllowedDomains(additionalDomains).map((rule) => rule.domain);
}

/**
 * Default domain patterns for sandbox-runtime config.
 */
export const DEFAULT_ALLOWED_DOMAIN_NAMES = DEFAULT_ALLOWED_DOMAINS.map((rule) => rule.domain);

/**
 * Check if a domain matches a pattern.
 * Supports:
 * - Exact matches: "example.com"
 * - Wildcard subdomain prefixes: "*.example.com"
 */
export function domainMatchesPattern(domain: string, pattern: string): boolean {
	const normalizedDomain = domain.toLowerCase();
	const normalizedPattern = pattern.toLowerCase();

	if (normalizedPattern.startsWith("*.")) {
		// Match subdomains only (align with @anthropic-ai/sandbox-runtime behavior)
		const baseDomain = normalizedPattern.slice(2); // "example.com"
		return normalizedDomain.endsWith(`.${baseDomain}`);
	}

	return normalizedDomain === normalizedPattern;
}

```

File: src/sandbox/manager.ts (3169 tokens)
```
/**
 * Sandbox manager for telclaude.
 *
 * Provides a high-level interface for sandboxing commands with
 * telclaude-specific configuration and lifecycle management.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getChildLogger } from "../logging.js";
import { getGitCredentials } from "../services/git-credentials.js";
import { getOpenAIKey } from "../services/openai-client.js";
import { DEFAULT_SANDBOX_CONFIG, PRIVATE_TMP_PATH, buildSandboxConfig } from "./config.js";
import { domainMatchesPattern } from "./domains.js";
import { buildSandboxEnv } from "./env.js";
import { isBlockedHost } from "./network-proxy.js";
import {
	MIN_SANDBOX_RUNTIME_VERSION,
	getSandboxRuntimeVersion,
	isSandboxRuntimeAtLeast,
} from "./version.js";
const logger = getChildLogger({ module: "sandbox" });

// ═══════════════════════════════════════════════════════════════════════════════
// Sandbox State
// ═══════════════════════════════════════════════════════════════════════════════

let initialized = false;
let currentConfig: SandboxRuntimeConfig | null = null;
let sanitizedEnv: Record<string, string> | null = null;
let originalTmpdir: string | undefined;

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/** Result of sandbox initialization */
export type SandboxInitResult = {
	/** Whether core sandbox (Bash isolation) initialized successfully */
	initialized: boolean;
};

/**
 * Initialize the sandbox manager with the given configuration.
 * Must be called before any sandboxed commands can be executed.
 *
 * Initializes two sandbox layers:
 * 1. Wrapper: Sandboxes entire Claude CLI subprocess (via pathToClaudeCodeExecutable)
 * 2. SandboxManager: Additional sandboxing for Bash commands (defense-in-depth)
 *
 * @param config - Optional configuration override (defaults to DEFAULT_SANDBOX_CONFIG)
 * @returns Status of sandbox initialization
 */
export async function initializeSandbox(config?: SandboxRuntimeConfig): Promise<SandboxInitResult> {
	if (initialized) {
		logger.debug("sandbox already initialized, skipping");
		return { initialized: true };
	}

	const runtimeVersion = getSandboxRuntimeVersion();
	if (runtimeVersion && !isSandboxRuntimeAtLeast()) {
		logger.warn(
			{ runtimeVersion, minimum: MIN_SANDBOX_RUNTIME_VERSION },
			"sandbox-runtime below patched version; upgrade recommended to fix network allowlist bug (CVE-2025-66479)",
		);
	} else if (!runtimeVersion) {
		logger.warn(
			"sandbox-runtime package not found; ensure dependencies are installed for network isolation",
		);
	}

	const sandboxConfig = config ?? DEFAULT_SANDBOX_CONFIG;
	try {
		// SECURITY: Create private temp directory before initializing sandbox
		// This ensures commands have a writable temp dir (host /tmp is blocked)
		const resolvedTmpPath = PRIVATE_TMP_PATH.startsWith("~")
			? path.join(os.homedir(), PRIVATE_TMP_PATH.slice(2))
			: PRIVATE_TMP_PATH;
		if (!fs.existsSync(resolvedTmpPath)) {
			fs.mkdirSync(resolvedTmpPath, { recursive: true, mode: 0o700 });
			logger.info({ path: resolvedTmpPath }, "created private temp directory");
		}

		// CRITICAL: Set TMPDIR BEFORE SandboxManager.initialize() on Linux
		// The sandbox-runtime creates network bridge sockets at tmpdir()/claude-*.sock
		// By pointing TMPDIR to our private temp, sockets land there instead of host /tmp.
		// This allows us to safely block host /tmp in denyRead without breaking network.
		originalTmpdir = process.env.TMPDIR;
		process.env.TMPDIR = resolvedTmpPath;
		logger.debug(
			{ tmpdir: resolvedTmpPath, originalTmpdir },
			"set TMPDIR for sandbox bridge sockets",
		);

		// Initialize SandboxManager for Bash commands (defense-in-depth)
		// NETWORK NOTES:
		// - We avoid a catch-all allowedDomains entry because it would bypass sandboxAskCallback,
		//   which we use to block private networks (including DNS rebinding) even in permissive mode.
		// - sandboxAskCallback is only invoked for domains NOT matched by allowedDomains/deniedDomains rules.
		// We use sandboxAskCallback to:
		// 1. Block private networks (RFC1918, localhost) - always enforced
		// 2. Allow broad egress when TELCLAUDE_NETWORK_MODE=open|permissive is set
		// NOTE: Callback reads currentConfig dynamically so updateSandboxConfig takes effect
		const sandboxAskCallback = async ({ host }: { host: string; port?: number }) => {
			// Always block private/internal networks (security critical)
			if (await isBlockedHost(host)) {
				logger.debug({ host }, "blocked private network access via sandboxAskCallback");
				return false;
			}
			const envMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
			if (envMode === "open" || envMode === "permissive") {
				return true;
			}
			// SECURITY: Check currentConfig dynamically (not captured at init time)
			// This ensures updateSandboxConfig() changes take effect immediately
			const allowedDomains = currentConfig?.network?.allowedDomains ?? [];
			if (allowedDomains.includes("*")) {
				return true;
			}
			if (allowedDomains.length === 0) {
				return false;
			}
			return allowedDomains.some((pattern) => domainMatchesPattern(host, pattern));
		};
		await SandboxManager.initialize(sandboxConfig, sandboxAskCallback);
		initialized = true;
		currentConfig = sandboxConfig;

		// SECURITY: Build sanitized environment for commands
		sanitizedEnv = buildSandboxEnv(process.env);

		logger.info(
			{
				denyRead: sandboxConfig.filesystem?.denyRead?.length ?? 0,
				allowWrite: sandboxConfig.filesystem?.allowWrite?.length ?? 0,
				allowedDomains: sandboxConfig.network?.allowedDomains?.length ?? 0,
				envVarsAllowed: Object.keys(sanitizedEnv).length,
			},
			"sandbox initialized",
		);

		return {
			initialized: true,
		};
	} catch (err) {
		logger.error({ error: String(err) }, "failed to initialize sandbox");
		throw new Error(`Sandbox initialization failed: ${String(err)}`);
	}
}

/**
 * Reset the sandbox manager.
 * Should be called during shutdown or when reconfiguring.
 */
export async function resetSandbox(): Promise<void> {
	if (!initialized) {
		return;
	}

	try {
		await SandboxManager.reset();
		initialized = false;
		currentConfig = null;
		sanitizedEnv = null;
		logger.info("sandbox reset");
	} catch (err) {
		logger.warn({ error: String(err) }, "error resetting sandbox");
	} finally {
		// Restore TMPDIR to its original value to avoid leaking global state.
		if (originalTmpdir === undefined) {
			Reflect.deleteProperty(process.env, "TMPDIR");
		} else {
			process.env.TMPDIR = originalTmpdir;
		}
		originalTmpdir = undefined;
	}
}

/**
 * Check if the sandbox is initialized.
 */
export function isSandboxInitialized(): boolean {
	return initialized;
}

/**
 * Get the current sandbox configuration.
 */
export function getSandboxConfig(): SandboxRuntimeConfig | null {
	return currentConfig;
}

/**
 * Update the sandbox configuration without restarting.
 *
 * Updates SandboxManager config (for Bash commands).
 */
export function updateSandboxConfig(config: SandboxRuntimeConfig): void {
	if (!initialized) {
		logger.warn("cannot update config: sandbox not initialized");
		return;
	}

	try {
		// Update SandboxManager config (for Bash commands)
		SandboxManager.updateConfig(config);
		currentConfig = config;
		logger.debug(
			{
				denyRead: config.filesystem?.denyRead?.length ?? 0,
				allowWrite: config.filesystem?.allowWrite?.length ?? 0,
			},
			"sandbox config updated",
		);
	} catch (err) {
		logger.error({ error: String(err) }, "failed to update sandbox config");
	}
}

/**
 * Escape a string for use in shell command (single-quote escaping).
 */
function shellEscape(value: string): string {
	// Replace single quotes with '\'' (end quote, escaped quote, start quote)
	return `'${value.replace(/'/g, "'\\''")}'`;
}

/**
 * Build environment prefix for commands.
 * Uses `env -i KEY=VALUE...` to ensure only allowed vars reach the command.
 *
 * Reads API keys fresh from secure storage on each call for hot-loading support.
 * If keys are updated via `telclaude setup-openai` or `telclaude setup-git`,
 * subsequent commands will pick up the new values without restart.
 */
async function buildEnvPrefixAsync(): Promise<string> {
	if (!sanitizedEnv) {
		return "";
	}

	// Start with the sanitized base env
	const envToApply: Record<string, string> = { ...sanitizedEnv };

	// Fetch API keys fresh from secure storage (supports hot-loading)
	const openaiKey = await getOpenAIKey();
	if (openaiKey) {
		envToApply.OPENAI_API_KEY = openaiKey;
	}

	const gitCreds = await getGitCredentials();
	const githubToken = gitCreds?.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
	if (githubToken) {
		envToApply.GITHUB_TOKEN = githubToken;
		envToApply.GH_TOKEN = githubToken;
	}

	const envAssignments = Object.entries(envToApply)
		.map(([key, value]) => `${key}=${shellEscape(value)}`)
		.join(" ");

	return `env -i ${envAssignments} `;
}

/**
 * Wrap a command with sandbox isolation.
 *
 * Returns the command string prefixed with:
 * 1. Environment isolation (env -i KEY=VALUE...)
 * 2. Sandbox (filesystem + network restrictions)
 *
 * The sandbox enforces filesystem and network restrictions at the OS level.
 * Environment isolation ensures only allowlisted env vars reach the command.
 *
 * @param command - The command to sandbox
 * @returns The sandboxed command string
 * @throws If sandbox is not initialized
 */
export async function wrapCommand(command: string): Promise<string> {
	if (!initialized) {
		throw new Error("Sandbox not initialized. Call initializeSandbox() first.");
	}

	try {
		// SECURITY: Override NO_PROXY to force RFC1918 traffic through the proxy.
		// The sandbox-runtime hardcodes NO_PROXY to bypass private networks (10.0.0.0/8, etc.)
		// for developer convenience. We reset it so all traffic goes through the proxy
		// where sandboxAskCallback can block RFC1918 addresses.
		const noProxyOverride = "export NO_PROXY= no_proxy= && ";
		const commandWithOverride = noProxyOverride + command;

		// First wrap with sandbox (filesystem + network isolation)
		const sandboxWrapped = await SandboxManager.wrapWithSandbox(commandWithOverride);

		// Then wrap with environment isolation
		// SECURITY: Apply allowlist-only environment
		// Uses async to fetch fresh API keys (supports hot-loading)
		const envPrefix = await buildEnvPrefixAsync();
		const fullyWrapped = envPrefix + sandboxWrapped;

		logger.debug(
			{
				original: command,
				wrapped: fullyWrapped.substring(0, 150),
				envVarsApplied: sanitizedEnv ? Object.keys(sanitizedEnv).length : 0,
			},
			"command wrapped with env isolation",
		);

		return fullyWrapped;
	} catch (err) {
		logger.error({ error: String(err), command }, "failed to wrap command");
		throw new Error(`Failed to sandbox command: ${String(err)}`);
	}
}

// Cache for sandbox availability (computed once at startup)
let sandboxAvailabilityChecked = false;
let sandboxAvailable = false;

/**
 * Check if sandboxing is available on this platform.
 *
 * Returns false on unsupported platforms (e.g., Windows) or if
 * required dependencies are missing (e.g., bubblewrap on Linux).
 *
 * This function is safe to call multiple times - it caches the result
 * and short-circuits if sandbox is already initialized.
 */
export async function isSandboxAvailable(): Promise<boolean> {
	// If already initialized in production, it's definitely available
	if (initialized) {
		return true;
	}

	// Return cached result if we've already checked
	if (sandboxAvailabilityChecked) {
		return sandboxAvailable;
	}

	// Perform the availability check once
	const resolvedTmpPath = PRIVATE_TMP_PATH.startsWith("~")
		? path.join(os.homedir(), PRIVATE_TMP_PATH.slice(2))
		: PRIVATE_TMP_PATH;
	const originalEnvTmpdir = process.env.TMPDIR;

	try {
		// Mirror initializeSandbox(): ensure private temp exists + use it for sandbox-runtime sockets.
		if (!fs.existsSync(resolvedTmpPath)) {
			fs.mkdirSync(resolvedTmpPath, { recursive: true, mode: 0o700 });
		}
		process.env.TMPDIR = resolvedTmpPath;

		const testConfig = buildSandboxConfig({});
		// Use same callback pattern for consistency with initializeSandbox
		const allowedDomains = testConfig.network?.allowedDomains ?? [];
		const sandboxAskCallback = async ({ host }: { host: string; port?: number }) => {
			if (await isBlockedHost(host)) return false;
			const envMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
			if (envMode === "open" || envMode === "permissive") return true;
			if (allowedDomains.includes("*")) return true;
			if (allowedDomains.length === 0) return false;
			return allowedDomains.some((pattern) => domainMatchesPattern(host, pattern));
		};
		await SandboxManager.initialize(testConfig, sandboxAskCallback);
		await SandboxManager.reset();
		sandboxAvailable = true;
	} catch {
		sandboxAvailable = false;
	} finally {
		// Restore TMPDIR to avoid leaking global state during a best-effort check.
		if (originalEnvTmpdir === undefined) {
			Reflect.deleteProperty(process.env, "TMPDIR");
		} else {
			process.env.TMPDIR = originalEnvTmpdir;
		}
	}

	sandboxAvailabilityChecked = true;
	return sandboxAvailable;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Config Helpers
// ═══════════════════════════════════════════════════════════════════════════════

export { buildSandboxConfig } from "./config.js";

```

File: src/services/image-generation.ts (1694 tokens)
```
/**
 * Image generation service using OpenAI GPT Image API.
 * Uses GPT Image 1.5 (December 2025).
 */

import fs from "node:fs";

import { type ImageGenerationConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { saveMediaBuffer } from "../media/store.js";
import { getMultimediaRateLimiter } from "./multimedia-rate-limit.js";
import { getOpenAIClient, isOpenAIConfigured, isOpenAIConfiguredSync } from "./openai-client.js";

const logger = getChildLogger({ module: "image-generation" });

/** Supported image sizes for GPT Image 1.5 */
type ImageSize = "auto" | "1024x1024" | "1536x1024" | "1024x1536";

/**
 * Image generation options.
 */
export type ImageGenerationOptions = {
	/** Image size. Default: 1024x1024 */
	size?: ImageSize;
	/** Quality tier: low, medium, high. Default: medium */
	quality?: "low" | "medium" | "high";
	/** User ID for rate limiting (chat_id or local_user_id) */
	userId?: string;
};

/**
 * Generated image result.
 */
export type GeneratedImage = {
	/** Local file path to the saved image */
	path: string;
	/** Revised prompt (if the model modified it) */
	revisedPrompt?: string;
	/** Image size in bytes */
	sizeBytes: number;
	/** Model used */
	model: string;
	/** Quality setting used */
	quality: string;
};

/**
 * Default image generation config.
 */
const DEFAULT_CONFIG: ImageGenerationConfig = {
	provider: "gpt-image",
	model: "gpt-image-1.5",
	size: "1024x1024",
	quality: "medium",
	maxPerHourPerUser: 10,
	maxPerDayPerUser: 50,
};

const SUPPORTED_SIZES: ImageSize[] = ["auto", "1024x1024", "1536x1024", "1024x1536"];

/**
 * Generate an image from a text prompt.
 *
 * @param prompt - Text description of the image to generate
 * @param options - Generation options (include userId for rate limiting)
 * @returns Generated image with local path and metadata
 * @throws Error if rate limited or generation fails
 */
export async function generateImage(
	prompt: string,
	options?: ImageGenerationOptions,
): Promise<GeneratedImage> {
	if (!(await isOpenAIConfigured())) {
		throw new Error("OpenAI API key not configured for image generation");
	}

	const config = loadConfig();
	const imageConfig = {
		...DEFAULT_CONFIG,
		...config.imageGeneration,
		...options,
	};

	if (imageConfig.provider === "disabled") {
		throw new Error("Image generation is disabled in config");
	}

	// Rate limiting check (if userId provided)
	const userId = options?.userId;
	if (userId) {
		const rateLimiter = getMultimediaRateLimiter();
		const rateLimitConfig = {
			maxPerHourPerUser: imageConfig.maxPerHourPerUser,
			maxPerDayPerUser: imageConfig.maxPerDayPerUser,
		};
		const limitResult = rateLimiter.checkLimit("image_generation", userId, rateLimitConfig);

		if (!limitResult.allowed) {
			logger.warn({ userId, remaining: limitResult.remaining }, "image generation rate limited");
			throw new Error(limitResult.reason ?? "Image generation rate limit exceeded");
		}
	}

	const client = await getOpenAIClient();
	const model = imageConfig.model ?? "gpt-image-1.5";
	const size = (imageConfig.size ?? "1024x1024") as ImageSize;
	const quality = imageConfig.quality ?? "medium";

	// Validate size
	if (!SUPPORTED_SIZES.includes(size)) {
		throw new Error(
			`Image size "${size}" is not supported. Use one of: ${SUPPORTED_SIZES.join(", ")}.`,
		);
	}

	logger.info({ prompt: prompt.slice(0, 100), model, size, quality }, "generating image");

	const startTime = Date.now();

	try {
		// GPT image models use output_format (png/jpeg/webp) and always return base64
		const response = await client.images.generate({
			model,
			prompt,
			size,
			quality,
			n: 1,
			output_format: "png",
		});

		const durationMs = Date.now() - startTime;

		// Handle response - SDK may return Stream or ImagesResponse
		if (!("data" in response) || !response.data?.[0]) {
			throw new Error("No image data in response");
		}

		const imageData = response.data[0];
		const base64 = imageData.b64_json;

		if (!base64) {
			throw new Error("No base64 image data in response");
		}

		// Save using centralized media store
		const buffer = Buffer.from(base64, "base64");
		const saved = await saveMediaBuffer(buffer, {
			mimeType: "image/png",
			category: "generated",
			extension: ".png",
		});

		const stat = await fs.promises.stat(saved.path);

		logger.info(
			{
				model,
				size,
				quality,
				durationMs,
				sizeBytes: stat.size,
				revisedPrompt: imageData.revised_prompt?.slice(0, 50),
			},
			"image generated successfully",
		);

		// Consume rate limit point after successful generation
		if (userId) {
			const rateLimiter = getMultimediaRateLimiter();
			rateLimiter.consume("image_generation", userId);
		}

		return {
			path: saved.path,
			revisedPrompt: imageData.revised_prompt,
			sizeBytes: stat.size,
			model,
			quality,
		};
	} catch (error) {
		logger.error({ prompt: prompt.slice(0, 100), error }, "image generation failed");
		throw error;
	}
}

/**
 * Generate multiple images from a prompt.
 */
export async function generateImages(
	prompt: string,
	count: number,
	options?: ImageGenerationOptions,
): Promise<GeneratedImage[]> {
	const results: GeneratedImage[] = [];

	// Generate one at a time to handle failures gracefully
	for (let i = 0; i < count; i++) {
		try {
			const image = await generateImage(prompt, options);
			results.push(image);
		} catch (error) {
			logger.error({ index: i, error }, "failed to generate image in batch");
			// Continue with remaining images
		}
	}

	return results;
}

/**
 * Check if image generation is available.
 * Uses sync check for env/config; keychain key will be found at runtime.
 */
export function isImageGenerationAvailable(): boolean {
	const config = loadConfig();

	if (config.imageGeneration?.provider === "disabled") {
		return false;
	}

	return isOpenAIConfiguredSync();
}

/**
 * Get estimated cost for image generation.
 * Based on December 2025 pricing for GPT Image 1.5.
 */
export function getEstimatedCost(size: ImageSize, quality: "low" | "medium" | "high"): number {
	const pricing: Record<string, Record<string, number>> = {
		auto: { low: 0.01, medium: 0.04, high: 0.17 },
		"1024x1024": { low: 0.01, medium: 0.04, high: 0.17 },
		"1536x1024": { low: 0.02, medium: 0.08, high: 0.25 },
		"1024x1536": { low: 0.02, medium: 0.08, high: 0.25 },
	};

	return pricing[size]?.[quality] ?? 0.04;
}

```

File: src/services/openai-client.ts (1129 tokens)
```
/**
 * OpenAI API client configuration.
 * Used for Whisper transcription, GPT Image generation, and TTS.
 *
 * API key resolution order:
 * 1. Keychain (via `telclaude setup-openai`)
 * 2. OPENAI_API_KEY environment variable
 * 3. openai.apiKey in config file
 */

import OpenAI from "openai";

import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { SECRET_KEYS, getSecret } from "../secrets/index.js";

const logger = getChildLogger({ module: "openai-client" });

let client: OpenAI | null = null;
let cachedApiKey: string | null = null;
let keySourceChecked = false;

/**
 * Get the OpenAI API key from keychain, env, or config.
 * Caches the result for performance.
 */
async function getApiKey(): Promise<string | null> {
	if (cachedApiKey) return cachedApiKey;

	// 1. Try keychain first
	try {
		const keychainKey = await getSecret(SECRET_KEYS.OPENAI_API_KEY);
		if (keychainKey) {
			cachedApiKey = keychainKey;
			keySourceChecked = true;
			logger.debug("using OpenAI API key from keychain");
			return keychainKey;
		}
	} catch (err) {
		logger.debug({ error: String(err) }, "keychain not available for OpenAI key");
	}

	// 2. Try environment variable
	if (process.env.OPENAI_API_KEY) {
		cachedApiKey = process.env.OPENAI_API_KEY;
		keySourceChecked = true;
		logger.debug("using OpenAI API key from environment variable");
		return cachedApiKey;
	}

	// 3. Try config file
	const config = loadConfig();
	if (config.openai?.apiKey) {
		cachedApiKey = config.openai.apiKey;
		keySourceChecked = true;
		logger.debug("using OpenAI API key from config file");
		return cachedApiKey;
	}

	keySourceChecked = true;
	return null;
}

/**
 * Get or create the OpenAI client.
 * Checks keychain first, then env var, then config file.
 */
export async function getOpenAIClient(): Promise<OpenAI> {
	if (client) return client;

	const apiKey = await getApiKey();

	if (!apiKey) {
		throw new Error(
			"OpenAI API key not configured.\n" +
				"Run: telclaude setup-openai\n" +
				"Or set OPENAI_API_KEY environment variable.",
		);
	}

	const config = loadConfig();
	const baseURL = config.openai?.baseUrl;

	client = new OpenAI({
		apiKey,
		baseURL,
		timeout: 120_000, // 2 minute timeout for large files
		maxRetries: 3,
	});

	logger.debug({ hasCustomBaseUrl: !!baseURL }, "OpenAI client initialized");

	return client;
}

/**
 * Check if OpenAI is configured.
 * Note: This is async due to keychain check.
 */
export async function isOpenAIConfigured(): Promise<boolean> {
	const apiKey = await getApiKey();
	return !!apiKey;
}

/**
 * Initialize OpenAI key lookup (call at startup).
 * This populates the cache so isOpenAIConfiguredSync() works correctly.
 */
export async function initializeOpenAIKey(): Promise<boolean> {
	const apiKey = await getApiKey();
	return !!apiKey;
}

/**
 * Synchronous check if OpenAI is configured.
 * Returns accurate result if initializeOpenAIKey() was called at startup,
 * otherwise falls back to env/config check only.
 */
export function isOpenAIConfiguredSync(): boolean {
	// If we've already checked all sources (including keychain), use cached result
	if (keySourceChecked) {
		return !!cachedApiKey;
	}

	// Fallback: check env and config only (keychain not yet checked)
	const config = loadConfig();
	return !!(process.env.OPENAI_API_KEY ?? config.openai?.apiKey);
}

/**
 * Clear cached API key and client.
 * Call this after key rotation or deletion.
 */
export function clearOpenAICache(): void {
	cachedApiKey = null;
	keySourceChecked = false;
	client = null;
	logger.debug("OpenAI cache cleared");
}

/**
 * Get cached OpenAI key if we've already checked all sources.
 * Returns null if the key hasn't been initialized yet.
 */
export function getCachedOpenAIKey(): string | null {
	return keySourceChecked ? cachedApiKey : null;
}

/**
 * Pre-warm the OpenAI key cache.
 * Call this at startup so getCachedOpenAIKey() works for sandbox env injection.
 */
export async function prewarmOpenAIKey(): Promise<boolean> {
	const key = await getApiKey();
	return key !== null;
}

/**
 * Get OpenAI API key fresh from storage (async).
 * Use this for hot-loading support - always reads from keychain/env/config.
 * Returns null if not configured.
 */
export async function getOpenAIKey(): Promise<string | null> {
	// Clear cache to force fresh read
	cachedApiKey = null;
	keySourceChecked = false;
	return getApiKey();
}

/**
 * Reset the client (for testing).
 */
export function resetOpenAIClient(): void {
	client = null;
}

```

</files>

