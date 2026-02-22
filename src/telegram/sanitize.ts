/**
 * Message sanitization for Telegram output.
 *
 * Prevents injection attacks through Claude responses or user-echoed content.
 * Output is converted to MarkdownV2 by outbound.ts after splitting.
 */

import { MAX_MESSAGE_CHUNK_LENGTH, MAX_TOTAL_RESPONSE_SIZE } from "./constants.js";

/** Truncation message appended when response exceeds size limit */
const TRUNCATION_WARNING = "\n\n⚠️ [Response truncated - exceeded 500KB limit]";

/**
 * Find the best split point in text, preferring natural boundaries.
 * Priority: paragraph break > line break > sentence end > word boundary > hard cut
 */
function findSplitPoint(text: string, maxLength: number): number {
	if (text.length <= maxLength) return text.length;

	// Look for natural break points within the last 20% of the allowed length
	const searchStart = Math.floor(maxLength * 0.8);
	const searchRegion = text.slice(searchStart, maxLength);

	// Priority 1: Paragraph break (double newline)
	const paragraphBreak = searchRegion.lastIndexOf("\n\n");
	if (paragraphBreak !== -1) {
		return searchStart + paragraphBreak + 2; // Include the newlines
	}

	// Priority 2: Single line break
	const lineBreak = searchRegion.lastIndexOf("\n");
	if (lineBreak !== -1) {
		return searchStart + lineBreak + 1;
	}

	// Priority 3: Sentence end (. ! ?)
	const sentenceMatch = searchRegion.match(/[.!?]\s+[A-Z]/g);
	if (sentenceMatch) {
		const lastSentence = searchRegion.lastIndexOf(sentenceMatch[sentenceMatch.length - 1]);
		if (lastSentence !== -1) {
			return searchStart + lastSentence + 2; // After punctuation and space
		}
	}

	// Priority 4: Word boundary (space)
	const wordBreak = searchRegion.lastIndexOf(" ");
	if (wordBreak !== -1) {
		return searchStart + wordBreak + 1;
	}

	// Priority 5: Hard cut at maxLength
	return maxLength;
}

/**
 * Split a long message into multiple chunks for Telegram.
 * Tries to split at natural boundaries (paragraphs, lines, sentences, words).
 *
 * @param text - Text to split
 * @param maxLength - Maximum length per chunk (default: 4000)
 * @returns Array of text chunks, each within maxLength
 */
export function splitMessage(text: string, maxLength: number = MAX_MESSAGE_CHUNK_LENGTH): string[] {
	if (text.length <= maxLength) {
		return [text];
	}

	const chunks: string[] = [];
	let remaining = text;

	while (remaining.length > 0) {
		if (remaining.length <= maxLength) {
			chunks.push(remaining);
			break;
		}

		const splitPoint = findSplitPoint(remaining, maxLength);
		chunks.push(remaining.slice(0, splitPoint).trimEnd());
		remaining = remaining.slice(splitPoint).trimStart();
	}

	return chunks;
}

/**
 * Remove dangerous characters from text.
 * Removes zero-width and RTL/LTR override characters that could hide content.
 */
function removeDangerousChars(text: string): string {
	// Remove zero-width characters that could hide content
	// Using alternation instead of character class due to ZWJ combining behavior
	let sanitized = text.replace(/\u200B|\u200C|\u200D|\uFEFF/g, "");

	// Remove RTL/LTR override characters (can be used to hide text)
	sanitized = sanitized.replace(/[\u202A-\u202E\u2066-\u2069]/g, "");

	return sanitized;
}

/**
 * Sanitize and split a long response into multiple Telegram-safe chunks.
 * Combines sanitization with intelligent splitting at natural boundaries.
 *
 * SECURITY: Enforces a maximum total response size to prevent DoS attacks
 * where an LLM generates extremely long responses that could block the event loop.
 *
 * @param text - Text to sanitize and split
 * @returns Array of sanitized chunks ready for Telegram
 */
export function sanitizeAndSplitResponse(text: string): string[] {
	let sanitized = removeDangerousChars(text);

	// Enforce maximum response size to prevent DoS
	if (sanitized.length > MAX_TOTAL_RESPONSE_SIZE) {
		// Truncate at a reasonable boundary (try to find last paragraph/line break)
		const truncateAt = MAX_TOTAL_RESPONSE_SIZE - TRUNCATION_WARNING.length;
		const lastParagraph = sanitized.lastIndexOf("\n\n", truncateAt);
		const lastLine = sanitized.lastIndexOf("\n", truncateAt);
		const cutPoint =
			lastParagraph > truncateAt * 0.8
				? lastParagraph
				: lastLine > truncateAt * 0.8
					? lastLine
					: truncateAt;

		sanitized = sanitized.slice(0, cutPoint) + TRUNCATION_WARNING;
	}

	return splitMessage(sanitized);
}
