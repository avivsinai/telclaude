/**
 * Message sanitization for Telegram output.
 *
 * Prevents injection attacks through Claude responses or user-echoed content.
 * Uses plain text by default to avoid markdown injection.
 */

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
 * Sanitize Claude's response for safe display in Telegram.
 * Removes potentially dangerous formatting while preserving readability.
 */
export function sanitizeClaudeResponse(text: string): string {
	// Limit length to prevent DoS
	const MAX_LENGTH = 4000; // Telegram message limit is 4096
	let sanitized =
		text.length > MAX_LENGTH ? `${text.slice(0, MAX_LENGTH)}...\n\n[Response truncated]` : text;

	// Remove zero-width characters that could hide content
	// Using alternation instead of character class due to ZWJ combining behavior
	sanitized = sanitized.replace(/\u200B|\u200C|\u200D|\uFEFF/g, "");

	// Remove RTL/LTR override characters (can be used to hide text)
	sanitized = sanitized.replace(/[\u202A-\u202E\u2066-\u2069]/g, "");

	return sanitized;
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
