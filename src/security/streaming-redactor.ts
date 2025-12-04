/**
 * Streaming Redactor - V2 Security
 *
 * Handles secret redaction across chunk boundaries when streaming to Telegram.
 *
 * Problem: Secrets can straddle chunk boundaries:
 *   Chunk 1: "Here's the key: ghp_abc12345"
 *   Chunk 2: "6789abcdef..."
 *   Neither chunk individually matches the pattern.
 *
 * Solution: Keep an overlap buffer to catch split secrets.
 */

import { getChildLogger } from "../logging.js";
import {
	SECRET_PATTERNS,
	type SecretFilterConfig,
	filterOutput,
	filterOutputWithConfig,
	redactSecrets,
	redactSecretsWithConfig,
} from "./output-filter.js";

const logger = getChildLogger({ module: "streaming-redactor" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface RedactionStats {
	chunksProcessed: number;
	secretsRedacted: number;
	patternsMatched: string[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Streaming Redactor
// ═══════════════════════════════════════════════════════════════════════════════

export class StreamingRedactor {
	private buffer = "";
	private readonly OVERLAP_SIZE: number;
	private readonly secretFilterConfig?: SecretFilterConfig;
	private stats: RedactionStats = {
		chunksProcessed: 0,
		secretsRedacted: 0,
		patternsMatched: [],
	};

	/**
	 * Create a streaming redactor.
	 *
	 * @param overlapSize - Characters to keep in buffer for overlap detection.
	 *                      Should be >= longest expected secret pattern (~100 chars).
	 * @param secretFilterConfig - Optional config for additional patterns and entropy detection.
	 */
	constructor(overlapSize = 100, secretFilterConfig?: SecretFilterConfig) {
		this.OVERLAP_SIZE = overlapSize;
		this.secretFilterConfig = secretFilterConfig;
	}

	/**
	 * Process a chunk of text.
	 *
	 * @param chunk - New chunk to process
	 * @returns Safe text to emit (may be empty if buffering)
	 */
	processChunk(chunk: string): string {
		this.stats.chunksProcessed++;

		// Combine buffer with new chunk
		const combined = this.buffer + chunk;

		// Check for secrets in combined text (use config if provided)
		const filterResult = this.secretFilterConfig
			? filterOutputWithConfig(combined, this.secretFilterConfig)
			: filterOutput(combined);
		let processed = combined;

		if (filterResult.blocked) {
			// Redact secrets (use config if provided)
			processed = this.secretFilterConfig
				? redactSecretsWithConfig(combined, this.secretFilterConfig)
				: redactSecrets(combined);
			this.stats.secretsRedacted += filterResult.matches.length;
			for (const match of filterResult.matches) {
				if (!this.stats.patternsMatched.includes(match.pattern)) {
					this.stats.patternsMatched.push(match.pattern);
				}
			}
			logger.warn(
				{ patterns: filterResult.matches.map((m) => m.pattern) },
				"secrets redacted in stream",
			);
		}

		// Calculate safe emit point (everything except overlap buffer)
		const safeLength = Math.max(0, processed.length - this.OVERLAP_SIZE);

		if (safeLength === 0) {
			// Not enough content to emit safely, keep buffering
			this.buffer = processed;
			return "";
		}

		// Emit safe portion, keep overlap in buffer
		const toEmit = processed.slice(0, safeLength);
		this.buffer = processed.slice(safeLength);

		return toEmit;
	}

	/**
	 * Flush remaining buffer on stream end.
	 *
	 * @returns Final text to emit
	 */
	flush(): string {
		// Final scan of remaining buffer (use config if provided)
		const filterResult = this.secretFilterConfig
			? filterOutputWithConfig(this.buffer, this.secretFilterConfig)
			: filterOutput(this.buffer);
		let final = this.buffer;

		if (filterResult.blocked) {
			final = this.secretFilterConfig
				? redactSecretsWithConfig(this.buffer, this.secretFilterConfig)
				: redactSecrets(this.buffer);
			this.stats.secretsRedacted += filterResult.matches.length;
			for (const match of filterResult.matches) {
				if (!this.stats.patternsMatched.includes(match.pattern)) {
					this.stats.patternsMatched.push(match.pattern);
				}
			}
		}

		this.buffer = "";
		return final;
	}

	/**
	 * Reset the redactor state.
	 */
	reset(): void {
		this.buffer = "";
		this.stats = {
			chunksProcessed: 0,
			secretsRedacted: 0,
			patternsMatched: [],
		};
	}

	/**
	 * Get redaction statistics.
	 */
	getStats(): RedactionStats {
		return { ...this.stats };
	}

	/**
	 * Check if there's pending content in the buffer.
	 */
	hasPending(): boolean {
		return this.buffer.length > 0;
	}

	/**
	 * Get buffer size for monitoring.
	 */
	getBufferSize(): number {
		return this.buffer.length;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Convenience Functions
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a streaming redactor with default settings.
 *
 * @param overlapSize - Characters to keep in buffer for overlap detection.
 * @param secretFilterConfig - Optional config for additional patterns and entropy detection.
 */
export function createStreamingRedactor(
	overlapSize?: number,
	secretFilterConfig?: SecretFilterConfig,
): StreamingRedactor {
	return new StreamingRedactor(overlapSize, secretFilterConfig);
}

/**
 * Process an array of chunks through a redactor.
 * Useful for testing or batch processing.
 *
 * @param chunks - Array of text chunks
 * @returns Fully redacted text
 */
export function processChunks(chunks: string[]): string {
	const redactor = new StreamingRedactor();
	let result = "";

	for (const chunk of chunks) {
		result += redactor.processChunk(chunk);
	}

	result += redactor.flush();
	return result;
}

/**
 * Create an async generator that wraps another generator with redaction.
 *
 * @param source - Source async generator of text chunks
 * @returns Async generator yielding redacted chunks
 */
export async function* redactStream(
	source: AsyncGenerator<string, void, unknown>,
): AsyncGenerator<string, void, unknown> {
	const redactor = new StreamingRedactor();

	for await (const chunk of source) {
		const redacted = redactor.processChunk(chunk);
		if (redacted.length > 0) {
			yield redacted;
		}
	}

	const final = redactor.flush();
	if (final.length > 0) {
		yield final;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Pattern Info Export
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get the longest pattern length for sizing the overlap buffer.
 */
export function getLongestPatternLength(): number {
	// Estimate based on known patterns (GitHub PAT is ~40 chars, etc.)
	// Add buffer for context around the match
	return 100;
}

/**
 * Get pattern names for logging/debugging.
 */
export function getPatternNames(): string[] {
	return SECRET_PATTERNS.map((p) => p.name);
}

// Re-export SecretFilterConfig for convenience
export type { SecretFilterConfig } from "./output-filter.js";
