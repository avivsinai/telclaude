/**
 * Stream Output Size Guard.
 *
 * Caps oversized tool-result content before it exhausts the context window,
 * and detects context overflow errors for graceful recovery.
 *
 * Adapted from OpenClaw's tool-result-truncation.ts and session-tool-result-guard.ts.
 * Since telclaude doesn't own transcript storage (the SDK handles persistence),
 * this guard operates on the streaming layer only — truncating tool results as
 * they flow through processMessageStream().
 */

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "output-guard" });

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Default maximum characters for a single tool result.
 * ~200KB allows larger file reads and web fetches without premature truncation.
 * At ~4 chars/token, this is ~50K tokens — ~25% of a 200K-token context window.
 */
export const DEFAULT_MAX_TOOL_RESULT_CHARS = 200_000;

/**
 * Absolute minimum characters to keep when truncating.
 * Always preserve enough context for the model to understand the result.
 */
const MIN_KEEP_CHARS = 2_000;

/**
 * Characters to keep from the end of truncated content.
 * Tail content often contains summaries, error messages, or final output.
 */
const TAIL_KEEP_CHARS = 500;

/**
 * Marker inserted where content was removed.
 */
const TRUNCATION_MARKER = "\n\n[... truncated %SIZE% ...]\n\n";

/**
 * Error patterns that indicate context window overflow.
 * These are matched against SDK error messages.
 */
const CONTEXT_OVERFLOW_PATTERNS = [
	/context.*(window|length|limit).*exceed/i,
	/maximum.*context.*length/i,
	/token.*limit.*exceeded/i,
	/too.*many.*tokens/i,
	/prompt.*too.*long/i,
	/input.*too.*large/i,
	/request.*too.*large/i,
	/max_tokens_exceeded/i,
	/context_length_exceeded/i,
	/prompt_too_long/i,
];

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type TruncationResult = {
	/** The (possibly truncated) content. */
	content: string;
	/** Original size in characters. */
	originalSize: number;
	/** Whether truncation was applied. */
	wasTruncated: boolean;
};

export type OutputGuardConfig = {
	/** Maximum characters per tool result (default: DEFAULT_MAX_TOOL_RESULT_CHARS). */
	maxToolResultChars?: number;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Truncation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Format a byte/char count for human display.
 */
function formatSize(chars: number): string {
	if (chars >= 1_000_000) {
		return `${(chars / 1_000_000).toFixed(1)}M chars`;
	}
	if (chars >= 1_000) {
		return `${(chars / 1_000).toFixed(1)}K chars`;
	}
	return `${chars} chars`;
}

/**
 * Truncate a tool result string, keeping the beginning and end
 * with a marker in the middle showing what was removed.
 *
 * Strategy: keep first portion + last TAIL_KEEP_CHARS, insert marker in between.
 * The first portion gets the remaining budget after tail + marker.
 * Tries to break at newline boundaries to avoid cutting mid-line.
 */
export function truncateToolResult(
	content: string,
	maxSize: number = DEFAULT_MAX_TOOL_RESULT_CHARS,
): TruncationResult {
	const originalSize = content.length;

	if (originalSize <= maxSize) {
		return { content, originalSize, wasTruncated: false };
	}

	const effectiveMax = Math.max(MIN_KEEP_CHARS, maxSize);
	const removedSize = originalSize - effectiveMax;
	const marker = TRUNCATION_MARKER.replace("%SIZE%", formatSize(removedSize));

	// Budget for head = total budget - tail - marker
	const tailSize = Math.min(TAIL_KEEP_CHARS, Math.floor(effectiveMax * 0.1));
	const headBudget = effectiveMax - tailSize - marker.length;

	if (headBudget < MIN_KEEP_CHARS) {
		// Not enough room for head+tail split; just keep the head
		let cutPoint = effectiveMax - marker.length;
		const lastNewline = content.lastIndexOf("\n", cutPoint);
		if (lastNewline > cutPoint * 0.8) {
			cutPoint = lastNewline;
		}
		const truncated = content.slice(0, cutPoint) + marker;
		return { content: truncated, originalSize, wasTruncated: true };
	}

	// Find clean break points
	let headEnd = headBudget;
	const headNewline = content.lastIndexOf("\n", headBudget);
	if (headNewline > headBudget * 0.8) {
		headEnd = headNewline;
	}

	let tailStart = originalSize - tailSize;
	const tailNewline = content.indexOf("\n", tailStart);
	if (tailNewline !== -1 && tailNewline < tailStart + tailSize * 0.2) {
		tailStart = tailNewline + 1;
	}

	const truncated = content.slice(0, headEnd) + marker + content.slice(tailStart);
	return { content: truncated, originalSize, wasTruncated: true };
}

/**
 * Apply truncation to a tool result output value from the SDK stream.
 * Handles string outputs directly; for structured outputs, serializes and truncates.
 *
 * Returns the original output unchanged if under the limit.
 */
export function guardToolResultOutput(
	output: unknown,
	maxSize: number = DEFAULT_MAX_TOOL_RESULT_CHARS,
): { output: unknown; truncation?: TruncationResult } {
	let content: string;

	if (typeof output === "string") {
		content = output;
	} else if (output == null) {
		return { output };
	} else {
		try {
			content = JSON.stringify(output);
		} catch {
			content = String(output);
		}
	}

	const result = truncateToolResult(content, maxSize);

	if (!result.wasTruncated) {
		return { output };
	}

	logger.info(
		{
			originalSize: result.originalSize,
			truncatedSize: result.content.length,
			reduction: `${((1 - result.content.length / result.originalSize) * 100).toFixed(1)}%`,
		},
		"tool result truncated by output guard",
	);

	// Return as string (the model handles string tool results fine)
	return {
		output: result.content,
		truncation: result,
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Context Overflow Detection
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if an error message indicates a context window overflow.
 */
export function isContextOverflowError(error: string | Error | unknown): boolean {
	const message = error instanceof Error ? error.message : String(error ?? "");
	return CONTEXT_OVERFLOW_PATTERNS.some((pattern) => pattern.test(message));
}

/**
 * Build a recovery summary for context overflow.
 * This provides context to the user about what happened and the recovery action.
 */
export function buildOverflowRecoverySummary(opts: {
	poolKey?: string;
	error: string;
	numTurns: number;
}): string {
	return (
		`[Context overflow detected after ${opts.numTurns} turn(s). ` +
		`The conversation exceeded the model's context window. ` +
		`Session will be reset. Error: ${opts.error}]`
	);
}
