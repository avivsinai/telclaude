/**
 * Claude Agent SDK layer for telclaude.
 *
 * Provides a typed interface to the Claude Agent SDK with:
 * - Session pooling with resume for multi-turn conversations
 * - Tier-aligned sandbox configurations
 * - Security enforcement via canUseTool callback
 */

import fs from "node:fs";
import {
	type HookCallback,
	type HookCallbackMatcher,
	type HookInput,
	type PermissionMode,
	type Options as SDKOptions,
	type SdkBeta,
	query,
} from "@anthropic-ai/claude-agent-sdk";
import { type PermissionTier, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { buildAllowedDomainNames, domainMatchesPattern } from "../sandbox/domains.js";
import { buildSandboxEnv } from "../sandbox/env.js";
import { buildSdkPermissionsForTier } from "../sandbox/index.js";
import { isBlockedHost } from "../sandbox/network-proxy.js";
import { TIER_TOOLS, containsBlockedCommand, isSensitivePath } from "../security/permissions.js";
import { getCachedGitToken } from "../services/git-credentials.js";
import { getCachedOpenAIKey } from "../services/openai-client.js";
import {
	isAssistantMessage,
	isBashInput,
	isContentBlockStopEvent,
	isGlobInput,
	isGrepInput,
	isInputJsonDeltaEvent,
	isReadInput,
	isResultMessage,
	isStreamEvent,
	isTextDeltaEvent,
	isToolResultMessage,
	isToolUseStartEvent,
	isWriteInput,
} from "./message-guards.js";
import { executeWithSession, getSessionManager } from "./session-manager.js";

const logger = getChildLogger({ module: "sdk-client" });
let keysExposedLogged = false;

// ═══════════════════════════════════════════════════════════════════════════════
// Tier-Based Key Exposure
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if keys should be exposed to sandbox based on tier.
 * WRITE_LOCAL and FULL_ACCESS tiers get configured keys exposed.
 * READ_ONLY tier never gets keys (no Bash access anyway).
 */
function shouldExposeKeys(tier: PermissionTier): boolean {
	return tier === "FULL_ACCESS" || tier === "WRITE_LOCAL";
}

// ═══════════════════════════════════════════════════════════════════════════════
// Security Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Resolve symlinks to get the real path.
 * Returns the original path if the file doesn't exist or resolution fails.
 */
function resolveRealPath(inputPath: string): string {
	try {
		return fs.realpathSync(inputPath);
	} catch {
		// File doesn't exist yet or other error - return original
		return inputPath;
	}
}

/**
 * Recursively scan an input payload for any string that hits isSensitivePath().
 * This is a belt-and-suspenders guard when the tool schema isn't path-specific.
 */
function inputContainsSensitivePath(payload: unknown): boolean {
	if (payload == null) {
		return false;
	}

	if (typeof payload === "string") {
		return isSensitivePath(payload);
	}

	if (Array.isArray(payload)) {
		return payload.some((v) => inputContainsSensitivePath(v));
	}

	if (typeof payload === "object") {
		return Object.values(payload).some((v) => inputContainsSensitivePath(v));
	}

	return false;
}

/**
 * Check if a path (after symlink resolution) is sensitive.
 * Defends against symlink attacks where attacker creates a symlink
 * to bypass path checks.
 */
function isPathSensitive(inputPath: string): boolean {
	// Check original path
	if (isSensitivePath(inputPath)) {
		return true;
	}
	// Resolve symlinks and check real path
	const realPath = resolveRealPath(inputPath);
	if (realPath !== inputPath && isSensitivePath(realPath)) {
		logger.warn({ inputPath, realPath }, "symlink to sensitive path detected");
		return true;
	}
	return false;
}

/**
 * Options for SDK queries.
 */
export type TelclaudeQueryOptions = {
	/** Working directory for the query. Tools operate relative to this path. */
	cwd: string;

	/** Permission tier controlling which tools are available. */
	tier: PermissionTier;

	/** Resume a previous session by ID for conversation continuity. */
	resumeSessionId?: string;

	/** Custom system prompt to append to the default claude_code preset. */
	systemPromptAppend?: string;

	/** Override the model (defaults to SDK's default model). */
	model?: string;

	/** Maximum conversation turns before stopping. */
	maxTurns?: number;

	/** Include streaming partial messages for real-time text updates. */
	includePartialMessages?: boolean;

	/** Permission mode override. */
	permissionMode?: PermissionMode;

	/** Enable skills loading from project's .claude/skills directory. */
	enableSkills?: boolean;

	/** Abort controller for external cancellation. */
	abortController?: AbortController;

	/** Timeout in milliseconds. Query aborts if exceeded. */
	timeoutMs?: number;

	/** Optional beta features to enable (e.g., 1M context window). */
	betas?: SdkBeta[];
};

/**
 * Result of a completed query.
 */
export type QueryResult = {
	response: string;
	success: boolean;
	error?: string;
	costUsd: number;
	numTurns: number;
	durationMs: number;
};

/**
 * Streaming chunk from the SDK.
 */
export type StreamChunk =
	| { type: "text"; content: string }
	| { type: "tool_use"; toolName: string; input: unknown }
	| { type: "tool_result"; toolName: string; output: unknown }
	| { type: "done"; result: QueryResult };

// ═══════════════════════════════════════════════════════════════════════════════
// PreToolUse Hook for Network Security
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a PreToolUse hook that blocks WebFetch to private networks and metadata endpoints.
 *
 * CRITICAL: This hook runs UNCONDITIONALLY before every tool use, regardless of SDK permission decisions.
 * This is necessary because the SDK's canUseTool callback is only called when the SDK's permission
 * resolver returns "ask" - if settings pre-approve a domain, canUseTool is bypassed.
 *
 * NOTE: WebSearch is NOT filtered here because:
 * - WebSearch uses a `query` parameter, not a `url` parameter
 * - Search requests are made server-side by Anthropic, not by the local process
 * - We cannot control which domains Anthropic's search accesses
 *
 * This hook ensures WebFetch private/metadata blocking cannot be bypassed by project settings.
 * User settings are already excluded via settingSources: ["project"].
 */
function createNetworkSecurityHook(
	isPermissiveMode: boolean,
	allowedDomains: string[],
): HookCallbackMatcher {
	const hookCallback: HookCallback = async (input: HookInput) => {
		// Only handle PreToolUse events for WebFetch
		if (input.hook_event_name !== "PreToolUse") {
			return { continue: true };
		}

		const toolName = input.tool_name;

		// Only filter WebFetch - WebSearch uses server-side requests we can't control
		if (toolName !== "WebFetch") {
			return { continue: true };
		}

		const toolInput = input.tool_input as { url?: string };
		if (!toolInput.url) {
			return { continue: true };
		}

		try {
			const url = new URL(toolInput.url);

			// Block non-HTTP protocols
			if (!["http:", "https:"].includes(url.protocol)) {
				logger.warn({ url: toolInput.url, tool: toolName }, "[hook] blocked non-HTTP protocol");
				return {
					decision: "block",
					reason: "Only HTTP/HTTPS protocols are allowed.",
				};
			}

			// Block private networks and metadata endpoints (ALWAYS enforced, cannot be bypassed)
			if (await isBlockedHost(url.hostname)) {
				logger.warn(
					{ host: url.hostname, tool: toolName },
					"[hook] blocked private/metadata access",
				);
				return {
					decision: "block",
					reason: "Access to private networks, localhost, or metadata endpoints is forbidden.",
				};
			}

			// In strict mode, also check domain allowlist
			if (!isPermissiveMode) {
				if (!allowedDomains.some((pattern) => domainMatchesPattern(url.hostname, pattern))) {
					logger.warn(
						{ host: url.hostname, tool: toolName },
						"[hook] blocked non-allowlisted domain",
					);
					return {
						decision: "block",
						reason: `Domain not in allowlist: ${url.hostname}`,
					};
				}
			}

			return { continue: true };
		} catch {
			logger.warn({ url: toolInput.url, tool: toolName }, "[hook] invalid URL");
			return {
				decision: "block",
				reason: "Invalid URL format.",
			};
		}
	};

	return {
		matcher: "WebFetch",
		hooks: [hookCallback],
		timeout: 5, // 5 second timeout for DNS resolution in isBlockedHost
	};
}

/**
 * Build SDK options based on tier and configuration.
 */
export function buildSdkOptions(opts: TelclaudeQueryOptions): SDKOptions {
	// Create abort controller with timeout if specified
	let abortController = opts.abortController;
	if (opts.timeoutMs && !abortController) {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), opts.timeoutMs);
		controller.signal.addEventListener(
			"abort",
			() => {
				clearTimeout(timeoutId);
			},
			{ once: true },
		);
		abortController = controller;
	}

	const sandboxEnv = buildSandboxEnv(process.env);
	const config = loadConfig();

	// Tier-based key exposure: WRITE_LOCAL+ gets configured keys
	if (shouldExposeKeys(opts.tier)) {
		const exposedKeys: string[] = [];

		// OpenAI key
		const openaiKey = getCachedOpenAIKey();
		if (openaiKey) {
			sandboxEnv.OPENAI_API_KEY = openaiKey;
			exposedKeys.push("OPENAI_API_KEY");
		}

		// GitHub token - from setup-git cache or env vars
		const githubToken = getCachedGitToken() || process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
		if (githubToken) {
			sandboxEnv.GITHUB_TOKEN = githubToken;
			sandboxEnv.GH_TOKEN = githubToken; // gh CLI uses this
			exposedKeys.push("GITHUB_TOKEN");
		}

		if (exposedKeys.length > 0 && !keysExposedLogged) {
			keysExposedLogged = true;
			logger.info({ tier: opts.tier, keys: exposedKeys }, "API keys exposed to sandbox");
		}
	}

	const sdkOpts: SDKOptions = {
		cwd: opts.cwd,
		model: opts.model,
		maxTurns: opts.maxTurns,
		includePartialMessages: opts.includePartialMessages,
		abortController,
		resume: opts.resumeSessionId,
		env: sandboxEnv,
	};

	// Check if permissive network mode is enabled (affects WebFetch/WebSearch via canUseTool)
	const envNetworkMode = process.env.TELCLAUDE_NETWORK_MODE?.toLowerCase();
	const isPermissiveMode = envNetworkMode === "open" || envNetworkMode === "permissive";

	// Build permissions (filesystem only - network handled by canUseTool and SDK sandbox)
	const additionalDomains = config.security?.network?.additionalDomains ?? [];
	const permissions = buildSdkPermissionsForTier(opts.tier);
	sdkOpts.extraArgs = {
		...sdkOpts.extraArgs,
		settings: JSON.stringify({ permissions }),
	};

	// SDK sandbox provides OS-level network enforcement for Bash (strict allowlist always).
	// WebFetch/WebSearch network filtering is done in canUseTool below (respects permissive mode).
	const allowedDomains = buildAllowedDomainNames(additionalDomains);

	sdkOpts.sandbox = {
		enabled: true,
		// SECURITY: Prevent dangerouslyDisableSandbox from bypassing OS-level isolation
		allowUnsandboxedCommands: false,
		network: {
			allowedDomains,
		},
	};

	// CRITICAL: Add PreToolUse hook for network security.
	// This hook runs UNCONDITIONALLY before every tool use, even if SDK permissions pre-approve.
	// This ensures private/metadata blocking cannot be bypassed by user/project settings.
	sdkOpts.hooks = {
		PreToolUse: [createNetworkSecurityHook(isPermissiveMode, allowedDomains)],
	};

	// Configure tools based on tier
	if (opts.tier === "FULL_ACCESS") {
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
		sdkOpts.allowDangerouslySkipPermissions = false;
	} else {
		const tierTools = TIER_TOOLS[opts.tier];
		sdkOpts.tools = tierTools;
		sdkOpts.allowedTools = opts.enableSkills ? [...tierTools, "Skill"] : tierTools;
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
	}

	// Opt-in beta headers
	if (opts.betas?.length) {
		sdkOpts.betas = opts.betas;
	}

	// Add canUseTool for ALL tiers to protect sensitive paths
	sdkOpts.canUseTool = async (toolName, input) => {
		logger.debug(
			{ toolName, input: JSON.stringify(input).substring(0, 200) },
			"canUseTool invoked",
		);

		// Generic guard: block any input that references sensitive paths
		if (inputContainsSensitivePath(input)) {
			logger.warn({ toolName, input }, "blocked tool input containing sensitive path");
			return {
				behavior: "deny",
				message: "Access to sensitive paths is not permitted for security reasons.",
			};
		}

		// Block access to sensitive paths
		if (toolName === "Read" && isReadInput(input)) {
			if (isPathSensitive(input.file_path)) {
				logger.warn({ path: input.file_path }, "blocked read of sensitive path");
				return {
					behavior: "deny",
					message: "Access to this file is not permitted for security reasons.",
				};
			}
		}

		if (toolName === "Write" && isWriteInput(input)) {
			if (isPathSensitive(input.file_path)) {
				logger.warn({ path: input.file_path }, "blocked write to sensitive path");
				return {
					behavior: "deny",
					message: "Writing to this location is not permitted for security reasons.",
				};
			}
		}

		if (toolName === "Glob" && isGlobInput(input)) {
			const searchPath = input.path ?? input.pattern;
			if (isPathSensitive(searchPath)) {
				logger.warn({ path: searchPath }, "blocked glob of sensitive path");
				return {
					behavior: "deny",
					message: "Searching this location is not permitted for security reasons.",
				};
			}
		}

		if (toolName === "Grep" && isGrepInput(input)) {
			const searchPath = input.path ?? "";
			if (isPathSensitive(searchPath)) {
				logger.warn({ path: searchPath }, "blocked grep of sensitive path");
				return {
					behavior: "deny",
					message: "Searching this location is not permitted for security reasons.",
				};
			}
		}

		if (toolName === "Bash" && isBashInput(input)) {
			// Block access to sensitive paths via shell (policy layer)
			if (isSensitivePath(input.command)) {
				logger.warn({ command: input.command }, "blocked bash access to sensitive path");
				return {
					behavior: "deny",
					message: "Access to sensitive paths via shell is not permitted.",
				};
			}

			// For WRITE_LOCAL, check for blocked commands (policy layer)
			if (opts.tier === "WRITE_LOCAL") {
				const blocked = containsBlockedCommand(input.command);
				if (blocked) {
					logger.warn({ command: input.command, blocked }, "blocked dangerous bash command");
					return {
						behavior: "deny",
						message: `Command contains blocked operation: ${blocked}`,
					};
				}
			}

			// SDK sandbox handles OS-level sandboxing (filesystem + network isolation)
			// No need to call wrapCommand() - that would cause double-sandboxing
		}

		// Belt-and-suspenders: Application-layer network check for WebFetch/WebSearch
		// PRIMARY enforcement is via PreToolUse hook (runs unconditionally).
		// This canUseTool check is a FALLBACK for cases where the hook might not run.
		if (toolName === "WebFetch") {
			const webInput = input as { url?: string };
			if (webInput.url) {
				try {
					const url = new URL(webInput.url);

					// Block non-HTTP protocols (prevent file:// access)
					if (!["http:", "https:"].includes(url.protocol)) {
						logger.warn({ url: webInput.url }, "blocked non-HTTP protocol in WebFetch");
						return {
							behavior: "deny",
							message: "Only HTTP/HTTPS protocols are allowed.",
						};
					}

					// Block private networks and metadata endpoints
					if (await isBlockedHost(url.hostname)) {
						logger.warn({ host: url.hostname }, "blocked private network access in WebFetch");
						return {
							behavior: "deny",
							message: "Access to private networks, localhost, or metadata endpoints is forbidden.",
						};
					}

					// Check domain allowlist (belt-and-suspenders with SDK sandbox)
					// In permissive mode, skip allowlist check - only block private/metadata above
					if (
						!isPermissiveMode &&
						!allowedDomains.some((pattern) => domainMatchesPattern(url.hostname, pattern))
					) {
						logger.warn({ host: url.hostname }, "blocked non-allowlisted domain in WebFetch");
						return {
							behavior: "deny",
							message: `Domain not in allowlist: ${url.hostname}`,
						};
					}
				} catch {
					logger.warn({ url: webInput.url }, "invalid URL in WebFetch");
					return {
						behavior: "deny",
						message: "Invalid URL format.",
					};
				}
			}
		}

		// NOTE: WebSearch is NOT filtered because:
		// - WebSearch uses `query` parameter, not `url` - our URL checks would never match
		// - Search requests are made server-side by Anthropic, not by the local process
		// - We cannot control which domains Anthropic's search service accesses

		return { behavior: "allow", updatedInput: input };
	};

	// SECURITY: Always load only "project" settings (not "user") to prevent settings bypass.
	// This blocks attacks where:
	// - User has disableAllHooks: true in ~/.claude/settings.json (bypasses PreToolUse hook)
	// - User has permissive WebFetch rules that allow SSRF to private networks
	// Project settings are controlled by the deployment and can be trusted.
	// Combined with blocking writes to .claude/settings*.json (via isSensitivePath),
	// this prevents prompt injection from writing disableAllHooks to project settings.
	// NOTE: This means user-level model overrides, plugins, etc. won't load in telclaude.
	// This is intentional - security takes precedence over customization.
	sdkOpts.settingSources = ["project"];

	// System prompt configuration
	if (opts.systemPromptAppend) {
		sdkOpts.systemPrompt = {
			type: "preset",
			preset: "claude_code",
			append: opts.systemPromptAppend,
		};
	}

	return sdkOpts;
}

// NOTE: applyTierSandboxConfig() was removed - SDK sandbox handles all sandboxing now
// We pass allowedDomains to SDK via sdkOpts.sandbox.network.allowedDomains in buildSdkOptions()

/**
 * Execute a query with streaming, yielding chunks as they arrive.
 */
export async function* executeQueryStream(
	prompt: string,
	inputOpts: TelclaudeQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const startTime = Date.now();

	// SDK sandbox config (including allowedDomains) is set in buildSdkOptions()
	const sdkOpts = buildSdkOptions({
		...inputOpts,
		includePartialMessages: true,
	});

	logger.debug(
		{
			tier: inputOpts.tier,
			cwd: inputOpts.cwd,
			allowedTools: sdkOpts.allowedTools,
		},
		"executing streaming SDK query",
	);

	const q = query({ prompt, options: sdkOpts });

	let response = "";
	let assistantMessageFallback = "";
	let costUsd = 0;
	let numTurns = 0;
	let durationMs = 0;
	let currentToolUse: { name: string; input: unknown; inputJson: string } | null = null;
	let lastToolUseName: string | null = null;

	try {
		for await (const msg of q) {
			if (isStreamEvent(msg)) {
				const event = msg.event;
				if (isTextDeltaEvent(event)) {
					yield { type: "text", content: event.delta.text };
					response += event.delta.text;
				} else if (isToolUseStartEvent(event)) {
					const cb = (event as unknown as { content_block: { name: string; input?: unknown } })
						.content_block;
					currentToolUse = {
						name: cb.name,
						input: cb.input ?? {},
						inputJson: "",
					};
				} else if (isInputJsonDeltaEvent(event) && currentToolUse) {
					currentToolUse.inputJson += event.delta.partial_json;
				} else if (isContentBlockStopEvent(event) && currentToolUse) {
					let input = currentToolUse.input;
					if (currentToolUse.inputJson) {
						try {
							input = JSON.parse(currentToolUse.inputJson);
						} catch {
							input = currentToolUse.inputJson;
						}
					}
					lastToolUseName = currentToolUse.name;
					yield { type: "tool_use", toolName: currentToolUse.name, input };
					currentToolUse = null;
				}
			} else if (isAssistantMessage(msg)) {
				for (const block of msg.message.content) {
					if (block.type === "text") {
						assistantMessageFallback += block.text;
					}
				}
			} else if (isToolResultMessage(msg)) {
				yield {
					type: "tool_result",
					toolName: lastToolUseName ?? "unknown",
					output: msg.tool_use_result,
				};
				lastToolUseName = null;
			} else if (isResultMessage(msg)) {
				costUsd = msg.total_cost_usd;
				numTurns = msg.num_turns;
				durationMs = msg.duration_ms;

				const success = msg.subtype === "success";
				const error = !success && "errors" in msg ? msg.errors.join("; ") : undefined;

				const finalResponse = response || assistantMessageFallback;
				if (!response && assistantMessageFallback) {
					logger.debug(
						{ streamedLength: response.length, fallbackLength: assistantMessageFallback.length },
						"using assistant message fallback",
					);
					yield { type: "text", content: assistantMessageFallback };
				}

				yield {
					type: "done",
					result: { response: finalResponse, success, error, costUsd, numTurns, durationMs },
				};
			}
		}
	} catch (err) {
		const isAborted = err instanceof Error && err.name === "AbortError";

		if (isAborted) {
			logger.warn({ durationMs: Date.now() - startTime }, "SDK query aborted");
		} else {
			logger.error({ error: String(err) }, "SDK streaming query error");
		}

		const finalResponse = response || assistantMessageFallback;

		yield {
			type: "done",
			result: {
				response: finalResponse,
				success: false,
				error: isAborted ? "Request was aborted" : String(err),
				costUsd,
				numTurns,
				durationMs: Date.now() - startTime,
			},
		};
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session Pool API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Options for pooled queries.
 */
export type PooledQueryOptions = TelclaudeQueryOptions & {
	poolKey: string;
};

/**
 * Execute a query using the session pool with resume support.
 */
export async function* executePooledQuery(
	prompt: string,
	inputOpts: PooledQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const startTime = Date.now();

	const opts = inputOpts;

	// SDK sandbox config (including allowedDomains) is set in buildSdkOptions()
	const sdkOpts = buildSdkOptions({
		...opts,
		includePartialMessages: true,
	});

	logger.debug(
		{
			tier: opts.tier,
			poolKey: opts.poolKey,
			cwd: opts.cwd,
		},
		"executing pooled SDK query",
	);

	const sessionManager = getSessionManager();
	let response = "";
	let assistantMessageFallback = "";
	let costUsd = 0;
	let numTurns = 0;
	let durationMs = 0;
	let currentToolUse: { name: string; input: unknown; inputJson: string } | null = null;
	let lastToolUseName: string | null = null;

	try {
		for await (const msg of executeWithSession(sessionManager, opts.poolKey, prompt, sdkOpts)) {
			if (isStreamEvent(msg)) {
				const event = msg.event;
				if (isTextDeltaEvent(event)) {
					yield { type: "text", content: event.delta.text };
					response += event.delta.text;
				} else if (isToolUseStartEvent(event)) {
					const cb = (event as unknown as { content_block: { name: string; input?: unknown } })
						.content_block;
					currentToolUse = {
						name: cb.name,
						input: cb.input ?? {},
						inputJson: "",
					};
				} else if (isInputJsonDeltaEvent(event) && currentToolUse) {
					currentToolUse.inputJson += event.delta.partial_json;
				} else if (isContentBlockStopEvent(event) && currentToolUse) {
					let input = currentToolUse.input;
					if (currentToolUse.inputJson) {
						try {
							input = JSON.parse(currentToolUse.inputJson);
						} catch {
							input = currentToolUse.inputJson;
						}
					}
					lastToolUseName = currentToolUse.name;
					yield { type: "tool_use", toolName: currentToolUse.name, input };
					currentToolUse = null;
				}
			} else if (isAssistantMessage(msg)) {
				for (const block of msg.message.content) {
					if (block.type === "tool_use") {
						lastToolUseName = block.name;
						yield { type: "tool_use", toolName: block.name, input: block.input };
					} else if (block.type === "text") {
						assistantMessageFallback += block.text;
					}
				}
			} else if (isToolResultMessage(msg)) {
				yield {
					type: "tool_result",
					toolName: lastToolUseName ?? "unknown",
					output: msg.tool_use_result,
				};
				lastToolUseName = null;
			} else if (isResultMessage(msg)) {
				costUsd = msg.total_cost_usd;
				numTurns = msg.num_turns;
				durationMs = msg.duration_ms;

				const success = msg.subtype === "success";
				const error = !success && "errors" in msg ? msg.errors.join("; ") : undefined;

				if (!success) {
					logger.error(
						{
							requestError: error,
							costUsd,
							numTurns,
							durationMs,
							poolKey: opts.poolKey,
						},
						"SDK result message reported failure",
					);
				}

				const finalResponse = response || assistantMessageFallback;
				if (!response && assistantMessageFallback) {
					logger.debug(
						{ streamedLength: response.length, fallbackLength: assistantMessageFallback.length },
						"using assistant message fallback",
					);
					yield { type: "text", content: assistantMessageFallback };
				}

				yield {
					type: "done",
					result: { response: finalResponse, success, error, costUsd, numTurns, durationMs },
				};
			}
		}
	} catch (err) {
		const isAborted = err instanceof Error && err.name === "AbortError";

		if (isAborted) {
			logger.warn({ durationMs: Date.now() - startTime }, "pooled query aborted");
		} else {
			logger.error({ error: String(err) }, "pooled query error");
		}

		const finalResponse = response || assistantMessageFallback;

		yield {
			type: "done",
			result: {
				response: finalResponse,
				success: false,
				error: isAborted ? "Request was aborted" : String(err),
				costUsd,
				numTurns,
				durationMs: Date.now() - startTime,
			},
		};
	}
}
