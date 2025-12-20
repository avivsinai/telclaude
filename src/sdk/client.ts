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
	type PermissionMode,
	type Options as SDKOptions,
	type SdkBeta,
	query,
} from "@anthropic-ai/claude-agent-sdk";
import { type PermissionTier, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { buildSandboxEnv } from "../sandbox/env.js";
import {
	buildSdkPermissionsForTier,
	getSandboxConfigForTier,
	isSandboxInitialized,
	updateSandboxConfig,
	wrapCommand,
} from "../sandbox/index.js";
import { TIER_TOOLS, containsBlockedCommand, isSensitivePath } from "../security/permissions.js";
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
let openaiSandboxKeyLogState: "none" | "exposed" | "missing" | "disabled" = "none";
const IS_PROD = process.env.TELCLAUDE_ENV === "prod" || process.env.NODE_ENV === "production";

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
 *
 * Controls permission tiers, session handling, streaming, and timeouts.
 *
 * @example
 * // Basic read-only query with timeout
 * const chunks = executeQueryStream("What files are in this directory?", {
 *   cwd: process.cwd(),
 *   tier: "READ_ONLY",
 *   timeoutMs: 30000,
 * });
 *
 * @example
 * // Write-safe query with session resumption
 * const chunks = executeQueryStream("Create a new file called test.ts", {
 *   cwd: process.cwd(),
 *   tier: "WRITE_LOCAL",
 *   resumeSessionId: "session-123",
 *   enableSkills: true,
 * });
 *
 * @example
 * // Full-access query with custom timeout and abort controller
 * const controller = new AbortController();
 * setTimeout(() => controller.abort(), 60000);
 *
 * const chunks = executeQueryStream("Run the build script", {
 *   cwd: "/path/to/project",
 *   tier: "FULL_ACCESS",
 *   abortController: controller,
 *   systemPromptAppend: "Be extra careful with destructive operations.",
 * });
 */
export type TelclaudeQueryOptions = {
	/** Working directory for the query. Tools operate relative to this path. */
	cwd: string;

	/** Permission tier controlling which tools are available.
	 * - READ_ONLY: Read, Glob, Grep, WebFetch, WebSearch
	 * - WRITE_LOCAL: Above + Write, Edit, Bash (with restrictions)
	 * - FULL_ACCESS: All tools (requires sandbox); still subject to canUseTool and approvals
	 */
	tier: PermissionTier;

	/** Resume a previous session by ID for conversation continuity.
	 * Omit for new sessions; the SDK will create a fresh conversation.
	 */
	resumeSessionId?: string;

	/** Custom system prompt to append to the default claude_code preset. */
	systemPromptAppend?: string;

	/** Override the model (defaults to SDK's default model). */
	model?: string;

	/** Maximum conversation turns before stopping (default: SDK default). */
	maxTurns?: number;

	/** Include streaming partial messages for real-time text updates. */
	includePartialMessages?: boolean;

	/** Permission mode override (bypassPermissions for FULL_ACCESS). */
	permissionMode?: PermissionMode;

	/** Enable skills loading from project's .claude/skills directory. */
	enableSkills?: boolean;

	/** Abort controller for external cancellation (e.g., user interrupt). */
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
	/** Final text response */
	response: string;
	/** Whether the query succeeded */
	success: boolean;
	/** Error message if failed */
	error?: string;
	/** Total cost in USD */
	costUsd: number;
	/** Number of turns taken */
	numTurns: number;
	/** Duration in milliseconds */
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

	// OpenAI sandbox key exposure precedence:
	// 1. Env var explicit disable (0/false/no) => disabled, ignores config
	// 2. Env var explicit enable (any other value) => enabled
	// 3. Config value (openai.exposeKeyToSandbox) => fallback if env not set
	const envExposeRaw = process.env.TELCLAUDE_OPENAI_SANDBOX_EXPOSE;
	const envExpose = envExposeRaw?.toLowerCase();
	const envExposeDisabled = envExpose === "0" || envExpose === "false" || envExpose === "no";
	const envExposeEnabled =
		envExposeRaw !== undefined && !envExposeDisabled && envExposeRaw.trim() !== "";
	const configEnables = config.openai?.exposeKeyToSandbox ?? false;
	const exposeOpenAIKey = envExposeEnabled || (!envExposeDisabled && configEnables);

	// Log when env var explicitly overrides config
	if (envExposeDisabled && configEnables) {
		if (openaiSandboxKeyLogState !== "disabled") {
			openaiSandboxKeyLogState = "disabled";
			logger.debug("OpenAI sandbox key exposure disabled by env var (overrides config)");
		}
	}

	const bashAllowed = opts.tier === "FULL_ACCESS" || TIER_TOOLS[opts.tier]?.includes("Bash");

	if (exposeOpenAIKey && bashAllowed) {
		const overrideKey = process.env.TELCLAUDE_SANDBOX_OPENAI_KEY;
		const cachedKey = getCachedOpenAIKey();
		const keyToExpose = overrideKey ?? cachedKey;

		if (keyToExpose) {
			sandboxEnv.OPENAI_API_KEY = keyToExpose;
			if (openaiSandboxKeyLogState !== "exposed") {
				openaiSandboxKeyLogState = "exposed";
				logger.warn(
					{
						source: overrideKey ? "TELCLAUDE_SANDBOX_OPENAI_KEY" : "cached",
					},
					"OpenAI key exposed to tool sandbox (use a restricted key)",
				);
			}
		} else {
			if (openaiSandboxKeyLogState !== "missing") {
				openaiSandboxKeyLogState = "missing";
				logger.warn(
					"OpenAI sandbox key exposure enabled but no key is available (set key or run setup-openai)",
				);
			}
		}
	}

	const sdkOpts: SDKOptions = {
		cwd: opts.cwd,
		model: opts.model,
		maxTurns: opts.maxTurns,
		includePartialMessages: opts.includePartialMessages,
		abortController,
		resume: opts.resumeSessionId,
		// SECURITY: Sanitize environment to prevent leaking secrets like TELEGRAM_BOT_TOKEN
		// Only allowlisted env vars pass through to the Claude subprocess
		env: sandboxEnv,
	};

	// Enforce Claude Code sandbox + permission policy per invocation (no writes to ~/.claude).
	// Sandbox settings are merged into `--settings` by the Agent SDK.
	// SECURITY: Only include OpenAI domains in sandbox allowlist if exposeKeyToSandbox is enabled.
	// This minimizes egress surface when the agent doesn't need direct OpenAI access.
	const permissions = buildSdkPermissionsForTier(opts.tier, {
		includeOpenAI: exposeOpenAIKey && bashAllowed,
	});
	sdkOpts.extraArgs = {
		...sdkOpts.extraArgs,
		settings: JSON.stringify({ permissions }),
	};
	sdkOpts.sandbox = {
		enabled: true,
		network: {
			allowLocalBinding: !IS_PROD,
			allowAllUnixSockets: !IS_PROD,
		},
	};

	// Configure tools based on tier
	if (opts.tier === "FULL_ACCESS") {
		// Full access, but keep canUseTool enforcement for sensitive paths.
		// Leave allowedTools undefined => all tools allowed.
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
		sdkOpts.allowDangerouslySkipPermissions = false;
	} else {
		// Restricted tiers - specify allowed tools
		const tierTools = TIER_TOOLS[opts.tier];
		// `tools` constrains built-in tool surface; allowedTools also gates optional Skill.
		sdkOpts.tools = tierTools;
		sdkOpts.allowedTools = opts.enableSkills ? [...tierTools, "Skill"] : tierTools;
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
	}

	// Opt-in beta headers (e.g., 1M context)
	if (opts.betas?.length) {
		sdkOpts.betas = opts.betas;
	}

	// Add canUseTool for ALL tiers to protect sensitive paths
	// This prevents the agent from accessing TOTP secrets, database, credentials, etc.
	// Uses symlink resolution to prevent bypass attacks
	sdkOpts.canUseTool = async (toolName, input) => {
		// Log every tool invocation for debugging
		logger.debug(
			{ toolName, input: JSON.stringify(input).substring(0, 200) },
			"canUseTool invoked",
		);

		// Generic guard: block any input that references sensitive paths, even if the tool schema is unknown.
		if (inputContainsSensitivePath(input)) {
			logger.warn({ toolName, input }, "blocked tool input containing sensitive path");
			return {
				behavior: "deny",
				message: "Access to sensitive paths is not permitted for security reasons.",
			};
		}

		// Block access to sensitive paths (telclaude internals + credentials like ~/.ssh)
		if (toolName === "Read" && isReadInput(input)) {
			const sensitive = isPathSensitive(input.file_path);
			logger.debug({ path: input.file_path, sensitive }, "checking Read path sensitivity");
			if (sensitive) {
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
			// Block access to sensitive paths via shell
			if (isSensitivePath(input.command)) {
				logger.warn({ command: input.command }, "blocked bash access to sensitive path");
				return {
					behavior: "deny",
					message: "Access to sensitive paths via shell is not permitted.",
				};
			}

			// For WRITE_LOCAL, also check for blocked commands
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

			// Wrap command with sandbox if available
			if (isSandboxInitialized()) {
				try {
					const sandboxedCommand = await wrapCommand(input.command);
					logger.debug(
						{ original: input.command, sandboxed: sandboxedCommand.substring(0, 100) },
						"sandboxing bash command",
					);
					return {
						behavior: "allow",
						updatedInput: { ...input, command: sandboxedCommand },
					};
				} catch (err) {
					logger.error({ error: String(err), command: input.command }, "sandbox wrap failed");
					return {
						behavior: "deny",
						message: "Failed to sandbox command. Execution blocked for security.",
					};
				}
			}
		}

		return { behavior: "allow", updatedInput: input };
	};

	// Load skills from both user (~/.claude) and project (cwd/.claude) locations
	// User location contains bundled telclaude skills; project may have additional skills
	if (opts.enableSkills) {
		sdkOpts.settingSources = ["user", "project"];
	}

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

/**
 * Apply tier-aligned sandbox configuration.
 * Updates the sandbox config to match the permission tier.
 *
 * @param tier - Permission tier
 * @param cwd - Working directory to allow writes to
 */
function applyTierSandboxConfig(tier: PermissionTier, cwd: string): void {
	if (!isSandboxInitialized()) {
		return;
	}

	const tierConfig = getSandboxConfigForTier(tier, cwd);
	updateSandboxConfig(tierConfig);
	logger.debug(
		{ tier, cwd, allowWrite: tierConfig.filesystem?.allowWrite },
		"applied tier-aligned sandbox config",
	);
}

/**
 * Execute a query with streaming, yielding chunks as they arrive.
 *
 * Applies tier-aligned sandbox configuration before execution.
 */
export async function* executeQueryStream(
	prompt: string,
	inputOpts: TelclaudeQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const startTime = Date.now();

	// Apply tier-aligned sandbox config with cwd
	applyTierSandboxConfig(inputOpts.tier, inputOpts.cwd);

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
	let assistantMessageFallback = ""; // Track assistant message text as fallback
	let costUsd = 0;
	let numTurns = 0;
	let durationMs = 0;
	let currentToolUse: { name: string; input: unknown; inputJson: string } | null = null;

	try {
		for await (const msg of q) {
			if (isStreamEvent(msg)) {
				// Handle streaming events for partial text using type guards
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
					yield { type: "tool_use", toolName: currentToolUse.name, input };
					currentToolUse = null;
				}
			} else if (isAssistantMessage(msg)) {
				// Track assistant message text as fallback in case streaming events weren't delivered
				for (const block of msg.message.content) {
					if (block.type === "text") {
						assistantMessageFallback += block.text;
					}
				}
			} else if (isToolResultMessage(msg)) {
				// Tool result from a tool use
				yield { type: "tool_result", toolName: "unknown", output: msg.tool_use_result };
			} else if (isResultMessage(msg)) {
				// Use type guard for result message
				costUsd = msg.total_cost_usd;
				numTurns = msg.num_turns;
				durationMs = msg.duration_ms;

				const success = msg.subtype === "success";
				const error = !success && "errors" in msg ? msg.errors.join("; ") : undefined;

				// Use assistant message fallback if streaming didn't deliver text
				const finalResponse = response || assistantMessageFallback;
				if (!response && assistantMessageFallback) {
					logger.debug(
						{ streamedLength: response.length, fallbackLength: assistantMessageFallback.length },
						"using assistant message fallback (streaming events not delivered)",
					);
					// Yield the fallback text now since it wasn't streamed
					yield { type: "text", content: assistantMessageFallback };
				}

				yield {
					type: "done",
					result: { response: finalResponse, success, error, costUsd, numTurns, durationMs },
				};
			}
		}
	} catch (err) {
		// Distinguish between abort (timeout/cancellation) and other errors
		const isAborted = err instanceof Error && err.name === "AbortError";

		const errorInfo =
			err instanceof Error
				? {
						name: err.name,
						message: err.message,
						stack: err.stack,
						// spread after capturing name/message/stack to avoid TS overwrite warnings
						...(err as unknown as Record<string, unknown>),
					}
				: { value: err };

		if (isAborted) {
			logger.warn({ durationMs: Date.now() - startTime, error: errorInfo }, "SDK query aborted");
		} else {
			logger.error({ error: errorInfo }, "SDK streaming query error");
		}

		// Use fallback if we didn't get streaming events but did get assistant messages
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
	/** Session pool key (typically derived from chat/user ID) */
	poolKey: string;
};

/**
 * Execute a query using the session pool with resume support.
 *
 * Uses the stable query() API with session ID tracking for multi-turn conversations.
 * Session IDs are automatically captured and reused via the resume option.
 */
export async function* executePooledQuery(
	prompt: string,
	inputOpts: PooledQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const startTime = Date.now();

	// SECURITY: FULL_ACCESS requires the sandbox layer. Relay startup fails if the
	// layer is unavailable; this check is a safety net in case initialization
	// state drifts, ensuring we never run without sandbox alignment.
	const opts = inputOpts;
	// Apply tier-aligned sandbox config with cwd
	applyTierSandboxConfig(opts.tier, opts.cwd);

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
	let assistantMessageFallback = ""; // Track assistant message text as fallback
	let costUsd = 0;
	let numTurns = 0;
	let durationMs = 0;
	let currentToolUse: { name: string; input: unknown; inputJson: string } | null = null;

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
					yield { type: "tool_use", toolName: currentToolUse.name, input };
					currentToolUse = null;
				}
			} else if (isAssistantMessage(msg)) {
				// NOTE: We do NOT yield text from assistant messages because we already
				// get it via streaming events (isTextDeltaEvent). However, we track it
				// as a fallback in case streaming events weren't delivered.
				for (const block of msg.message.content) {
					if (block.type === "tool_use") {
						yield { type: "tool_use", toolName: block.name, input: block.input };
					} else if (block.type === "text") {
						// Track as fallback but don't yield (to avoid duplicates)
						assistantMessageFallback += block.text;
					}
				}
			} else if (isToolResultMessage(msg)) {
				yield { type: "tool_result", toolName: "unknown", output: msg.tool_use_result };
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
							resultMessage: msg,
							costUsd,
							numTurns,
							durationMs,
							poolKey: opts.poolKey,
							cwd: opts.cwd,
							tier: opts.tier,
						},
						"SDK result message reported failure",
					);
				}

				// Use assistant message fallback if streaming didn't deliver text
				const finalResponse = response || assistantMessageFallback;
				if (!response && assistantMessageFallback) {
					logger.debug(
						{ streamedLength: response.length, fallbackLength: assistantMessageFallback.length },
						"using assistant message fallback (streaming events not delivered)",
					);
					// Yield the fallback text now since it wasn't streamed
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

		// Use fallback if we didn't get streaming events but did get assistant messages
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
