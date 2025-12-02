/**
 * Shared type guards for Claude Agent SDK messages.
 *
 * These guards provide runtime type checking for SDK message types,
 * enabling safe handling of streaming responses and tool interactions.
 */

import type {
	SDKAssistantMessage,
	SDKMessage,
	SDKPartialAssistantMessage,
	SDKResultMessage,
} from "@anthropic-ai/claude-agent-sdk";

// ═══════════════════════════════════════════════════════════════════════════════
// SDK Message Type Guards
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Type guard for SDK result messages (query completion).
 *
 * @example
 * for await (const msg of query({...})) {
 *   if (isResultMessage(msg)) {
 *     console.log(`Cost: $${msg.total_cost_usd}`);
 *   }
 * }
 */
export function isResultMessage(msg: SDKMessage): msg is SDKResultMessage {
	return (
		msg.type === "result" && "total_cost_usd" in msg && "num_turns" in msg && "duration_ms" in msg
	);
}

/**
 * Type guard for SDK assistant messages (complete response).
 *
 * @example
 * for await (const msg of query({...})) {
 *   if (isAssistantMessage(msg)) {
 *     for (const block of msg.message.content) {
 *       if (block.type === 'text') console.log(block.text);
 *     }
 *   }
 * }
 */
export function isAssistantMessage(msg: SDKMessage): msg is SDKAssistantMessage {
	return (
		msg.type === "assistant" &&
		"message" in msg &&
		typeof msg.message === "object" &&
		msg.message !== null &&
		"content" in msg.message &&
		Array.isArray(msg.message.content)
	);
}

/**
 * Type guard for stream_event messages (partial streaming).
 */
export function isStreamEvent(msg: SDKMessage): msg is SDKPartialAssistantMessage {
	return msg.type === "stream_event" && "event" in msg;
}

/**
 * Type guard for user messages containing tool_use_result.
 * These are SDK messages where a tool has returned its output.
 */
export function isToolResultMessage(
	msg: SDKMessage,
): msg is SDKMessage & { tool_use_result: unknown } {
	return msg.type === "user" && "tool_use_result" in msg;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Streaming Event Type Guards
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Type guard for content_block_delta with text_delta.
 * Used to extract streaming text chunks.
 */
export function isTextDeltaEvent(
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
 * Indicates the start of a tool invocation.
 */
export function isToolUseStartEvent(
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
 * Type guard for content_block_stop events.
 * Indicates the end of a content block (text or tool use).
 */
export function isContentBlockStopEvent(event: unknown): event is { type: "content_block_stop" } {
	if (typeof event !== "object" || event === null) return false;
	return (event as { type?: string }).type === "content_block_stop";
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tool Input Type Guards
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Type guard for Bash tool input.
 */
export function isBashInput(input: unknown): input is { command: string } {
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
export function isReadInput(input: unknown): input is { file_path: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"file_path" in input &&
		typeof (input as { file_path: unknown }).file_path === "string"
	);
}

/**
 * Type guard for Write tool input.
 */
export function isWriteInput(input: unknown): input is { file_path: string; content: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"file_path" in input &&
		typeof (input as { file_path: unknown }).file_path === "string" &&
		"content" in input &&
		typeof (input as { content: unknown }).content === "string"
	);
}

/**
 * Type guard for Glob tool input.
 */
export function isGlobInput(input: unknown): input is { pattern: string; path?: string } {
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
export function isGrepInput(input: unknown): input is { pattern: string; path?: string } {
	return (
		typeof input === "object" &&
		input !== null &&
		"pattern" in input &&
		typeof (input as { pattern: unknown }).pattern === "string"
	);
}
