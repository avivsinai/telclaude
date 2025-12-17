/**
 * Message sanitization for Telegram output.
 *
 * Prevents injection attacks through Claude responses or user-echoed content.
 * Uses plain text by default to avoid markdown injection.
 */

/** Telegram message length limit with safety margin */
const MAX_MESSAGE_LENGTH = 4000; // Telegram limit is 4096, leave margin for safety

/**
 * Escape special characters for Telegram MarkdownV2.
 * Only use this for trusted content that needs formatting.
 */
export function escapeMarkdownV2(text: string): string {
	// Characters that need escaping in MarkdownV2
	return text.replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, "\\$1");
}

/**
 * Escape special characters for legacy Telegram Markdown.
 * Only use this for trusted content that needs formatting.
 */
export function escapeMarkdown(text: string): string {
	// Characters that need escaping in legacy Markdown
	return text.replace(/([_*`\[])/g, "\\$1");
}

/**
 * Strip all markdown formatting from text.
 * Use this for untrusted content (like Claude responses).
 */
export function stripMarkdown(text: string): string {
	return (
		text
			// Remove code blocks
			.replace(/```[\s\S]*?```/g, (match) => match.replace(/```/g, ""))
			// Remove inline code
			.replace(/`([^`]+)`/g, "$1")
			// Remove bold/italic markers (but keep content)
			.replace(/\*\*([^*]+)\*\*/g, "$1")
			.replace(/\*([^*]+)\*/g, "$1")
			.replace(/__([^_]+)__/g, "$1")
			.replace(/_([^_]+)_/g, "$1")
			// Remove links but show URL
			.replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)")
			// Remove strikethrough
			.replace(/~~([^~]+)~~/g, "$1")
	);
}

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
export function splitMessage(text: string, maxLength: number = MAX_MESSAGE_LENGTH): string[] {
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
 * Sanitize Claude's response for safe display in Telegram.
 * Removes potentially dangerous formatting while preserving readability.
 *
 * NOTE: This function now returns a single sanitized string without truncation.
 * Use splitMessage() separately if you need to split for Telegram's length limit.
 */
export function sanitizeClaudeResponse(text: string): string {
	return removeDangerousChars(text);
}

/**
 * Sanitize and split a long response into multiple Telegram-safe chunks.
 * Combines sanitization with intelligent splitting at natural boundaries.
 *
 * @param text - Text to sanitize and split
 * @returns Array of sanitized chunks ready for Telegram
 */
export function sanitizeAndSplitResponse(text: string): string[] {
	const sanitized = removeDangerousChars(text);
	return splitMessage(sanitized);
}

/**
 * Format a system message with controlled markdown.
 * Only use for messages we fully control (not user/Claude content).
 */
export function formatSystemMessage(template: string, vars: Record<string, string> = {}): string {
	let result = template;
	for (const [key, value] of Object.entries(vars)) {
		// Escape the value to prevent injection
		const escaped = escapeMarkdown(value);
		result = result.replace(new RegExp(`\\{${key}\\}`, "g"), escaped);
	}
	return result;
}
