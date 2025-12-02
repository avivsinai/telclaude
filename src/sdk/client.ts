/**
 * Claude Agent SDK wrapper for telclaude.
 *
 * Provides a typed interface to the Claude Agent SDK with
 * telclaude-specific configuration and streaming support.
 */

import {
	type PermissionMode,
	type SDKMessage,
	type Options as SDKOptions,
	type SDKPartialAssistantMessage,
	type SDKResultMessage,
	query,
} from "@anthropic-ai/claude-agent-sdk";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { isSandboxInitialized, wrapCommand } from "../sandbox/index.js";
import { TIER_TOOLS, containsBlockedCommand, isSensitivePath } from "../security/permissions.js";

const logger = getChildLogger({ module: "sdk-client" });

// ═══════════════════════════════════════════════════════════════════════════════
// Type Guards for SDK Messages
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Type guard for SDK result messages.
 */
function isResultMessage(msg: SDKMessage): msg is SDKResultMessage {
	return (
		msg.type === "result" && "total_cost_usd" in msg && "num_turns" in msg && "duration_ms" in msg
	);
}

/**
 * Type guard for Bash tool input.
 */
function isBashInput(input: unknown): input is { command: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"command" in input &&
		typeof (input as { command: unknown }).command === "string"
	);
}

/**
 * Type guard for Read tool input.
 */
function isReadInput(input: unknown): input is { file_path: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"file_path" in input &&
		typeof (input as { file_path: unknown }).file_path === "string"
	);
}

/**
 * Type guard for Glob tool input.
 */
function isGlobInput(input: unknown): input is { pattern: string; path?: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"pattern" in input &&
		typeof (input as { pattern: unknown }).pattern === "string"
	);
}

/**
 * Type guard for Grep tool input.
 */
function isGrepInput(input: unknown): input is { pattern: string; path?: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"pattern" in input &&
		typeof (input as { pattern: unknown }).pattern === "string"
	);
}

/**
 * Type guard for stream_event messages.
 */
function isStreamEvent(msg: SDKMessage): msg is SDKPartialAssistantMessage {
	return msg.type === "stream_event" && "event" in msg;
}

/**
 * Type guard for content_block_delta with text_delta.
 */
function isTextDeltaEvent(
	event: unknown,
): event is { type: "content_block_delta"; delta: { type: "text_delta"; text: string } } {
	if (typeof event !== "object" || event === null) return false;
	const e = event as { type?: string; delta?: { type?: string; text?: unknown } };
	return (
		e.type === "content_block_delta" &&
		typeof e.delta === "object" &&
		e.delta !== null &&
		e.delta.type === "text_delta" &&
		typeof e.delta.text === "string"
	);
}

/**
 * Type guard for content_block_start with tool_use.
 */
function isToolUseStartEvent(
	event: unknown,
): event is { type: "content_block_start"; content_block: { type: "tool_use"; name: string } } {
	if (typeof event !== "object" || event === null) return false;
	const e = event as { type?: string; content_block?: { type?: string; name?: unknown } };
	return (
		e.type === "content_block_start" &&
		typeof e.content_block === "object" &&
		e.content_block !== null &&
		e.content_block.type === "tool_use" &&
		typeof e.content_block.name === "string"
	);
}

/**
 * Type guard for content_block_stop.
 */
function isContentBlockStopEvent(event: unknown): event is { type: "content_block_stop" } {
	if (typeof event !== "object" || event === null) return false;
	return (event as { type?: string }).type === "content_block_stop";
}

/**
 * Type guard for user message with tool_use_result.
 */
function isToolResultMessage(msg: SDKMessage): msg is SDKMessage & { tool_use_result: unknown } {
	return msg.type === "user" && "tool_use_result" in msg;
}

/**
 * Options for SDK queries.
 */
export type TelclaudeQueryOptions = {
	/** Working directory for the query */
	cwd: string;
	/** Permission tier for this query */
	tier: PermissionTier;
	/** Resume a previous session by ID (for conversation continuity) */
	resumeSessionId?: string;
	/** Custom system prompt to append */
	systemPromptAppend?: string;
	/** Override the model */
	model?: string;
	/** Maximum turns for the conversation */
	maxTurns?: number;
	/** Include streaming partial messages */
	includePartialMessages?: boolean;
	/** Permission mode override */
	permissionMode?: PermissionMode;
	/** Enable skills (loads from project/user) */
	enableSkills?: boolean;
	/** Abort controller for cancellation */
	abortController?: AbortController;
	/** Timeout in milliseconds */
	timeoutMs?: number;
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
		abortController = new AbortController();
		setTimeout(() => abortController?.abort(), opts.timeoutMs);
	}

	const sdkOpts: SDKOptions = {
		cwd: opts.cwd,
		model: opts.model,
		maxTurns: opts.maxTurns,
		includePartialMessages: opts.includePartialMessages,
		abortController,
		resume: opts.resumeSessionId,
	};

	// Configure tools based on tier
	if (opts.tier === "FULL_ACCESS") {
		// Full access - use bypassPermissions mode
		sdkOpts.permissionMode = opts.permissionMode ?? "bypassPermissions";
		sdkOpts.allowDangerouslySkipPermissions = true;
	} else {
		// Restricted tiers - specify allowed tools
		const tierTools = TIER_TOOLS[opts.tier];
		sdkOpts.allowedTools = opts.enableSkills ? [...tierTools, "Skill"] : tierTools;
		sdkOpts.permissionMode = opts.permissionMode ?? "acceptEdits";
	}

	// Add canUseTool for ALL tiers to protect sensitive paths
	// This prevents the agent from accessing TOTP secrets, database, etc.
	sdkOpts.canUseTool = async (toolName, input) => {
		// Block access to sensitive telclaude paths (TOTP secrets, etc.)
		if (toolName === "Read" && isReadInput(input)) {
			if (isSensitivePath(input.file_path)) {
				logger.warn({ path: input.file_path }, "blocked read of sensitive path");
				return {
					behavior: "deny",
					message: "Access to telclaude configuration files is not permitted.",
				};
			}
		}

		if (toolName === "Glob" && isGlobInput(input)) {
			const searchPath = input.path ?? input.pattern;
			if (isSensitivePath(searchPath)) {
				logger.warn({ path: searchPath }, "blocked glob of sensitive path");
				return {
					behavior: "deny",
					message: "Searching telclaude configuration directories is not permitted.",
				};
			}
		}

		if (toolName === "Grep" && isGrepInput(input)) {
			const searchPath = input.path ?? "";
			const searchPattern = input.pattern;
			if (isSensitivePath(searchPath) || isSensitivePath(searchPattern)) {
				logger.warn({ path: searchPath, pattern: searchPattern }, "blocked grep of sensitive path");
				return {
					behavior: "deny",
					message: "Searching telclaude configuration is not permitted.",
				};
			}
		}

		if (toolName === "Bash" && isBashInput(input)) {
			// Block access to sensitive paths via shell
			if (isSensitivePath(input.command)) {
				logger.warn({ command: input.command }, "blocked bash access to sensitive path");
				return {
					behavior: "deny",
					message: "Access to telclaude configuration via shell is not permitted.",
				};
			}

			// For WRITE_SAFE, also check for blocked commands
			if (opts.tier === "WRITE_SAFE") {
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

	// Load settings from project for skills
	if (opts.enableSkills) {
		sdkOpts.settingSources = ["project"];
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
 * Execute a query with streaming, yielding chunks as they arrive.
 */
export async function* executeQueryStream(
	prompt: string,
	opts: TelclaudeQueryOptions,
): AsyncGenerator<StreamChunk, void, unknown> {
	const sdkOpts = buildSdkOptions({
		...opts,
		includePartialMessages: true,
	});

	logger.debug(
		{
			tier: opts.tier,
			cwd: opts.cwd,
			allowedTools: sdkOpts.allowedTools,
		},
		"executing streaming SDK query",
	);

	const q = query({ prompt, options: sdkOpts });

	let response = "";
	let costUsd = 0;
	let numTurns = 0;
	let durationMs = 0;
	let currentToolUse: { name: string; input: unknown } | null = null;

	try {
		for await (const msg of q) {
			if (isStreamEvent(msg)) {
				// Handle streaming events for partial text using type guards
				const event = msg.event;
				if (isTextDeltaEvent(event)) {
					yield { type: "text", content: event.delta.text };
					response += event.delta.text;
				} else if (isToolUseStartEvent(event)) {
					currentToolUse = { name: event.content_block.name, input: {} };
				} else if (isContentBlockStopEvent(event) && currentToolUse) {
					yield { type: "tool_use", toolName: currentToolUse.name, input: currentToolUse.input };
					currentToolUse = null;
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

				yield {
					type: "done",
					result: { response, success, error, costUsd, numTurns, durationMs },
				};
			}
		}
	} catch (err) {
		logger.error({ error: String(err) }, "SDK streaming query error");
		yield {
			type: "done",
			result: {
				response,
				success: false,
				error: String(err),
				costUsd,
				numTurns,
				durationMs,
			},
		};
	}
}
