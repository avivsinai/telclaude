import { filterInfrastructureSecrets } from "./output-filter.js";
import type { SecurityClassification } from "./types.js";

/**
 * Patterns that are clearly safe and can skip LLM review.
 *
 * SECURITY NOTE: These patterns must be STRICTLY anchored (^ and $) to avoid
 * matching malicious requests that start with safe-looking text. For example,
 * "What are the contents of ~/.ssh/id_rsa?" should NOT match because generic
 * question starters can be used to request dangerous operations.
 *
 * Only include patterns where the ENTIRE message is known to be safe.
 */
export const SAFE_PATTERNS: RegExp[] = [
	// Strictly anchored safe commands (entire message must match)
	/^pwd$/i,
	/^whoami$/i,
	/^date$/i,
	/^uptime$/i,
	/^ls$/i,
	/^ls\s+-[lahR]+$/i, // ls with common flags only

	// Git read-only status commands (strictly anchored)
	/^git\s+status$/i,
	/^git\s+branch$/i,
	/^git\s+remote\s+-v$/i,
	/^git\s+log\s*$/i,
	/^git\s+log\s+--oneline(\s+-\d+)?$/i, // git log --oneline -10

	// Simple greetings (cannot trigger tools)
	/^(hi|hello|hey|thanks|thank you|ok|okay)!?$/i,
];

/**
 * Patterns that are clearly dangerous and should be blocked immediately.
 */
export const DANGEROUS_PATTERNS: RegExp[] = [
	// Destructive file operations
	/rm\s+-rf?\s*\//i,
	/rm\s+-rf?\s*~\//i,
	/>\s*\/etc\//i,
	/chmod\s+777/i,
	/chown\s+.*\s+\//i,

	// Shell injection attempts
	/curl.*\|\s*(ba)?sh/i,
	/wget.*\|\s*(ba)?sh/i,
	/\$\([^)]+\)/i, // Command substitution
	/`[^`]+`/, // Backtick execution
	/;\s*(rm|chmod|chown|sudo|su\s)/i, // Command chaining to dangerous

	// Dangerous flags
	/--dangerously/i,
	/--force/i,
	/--no-preserve-root/i,

	// Privilege escalation
	/sudo\s+/i,
	/su\s+-?\s*$/i,
	/pkexec/i,

	// Prompt injection attempts
	/ignore\s+(all\s+)?previous\s+instructions?/i,
	/disregard\s+(all\s+)?prior\s+instructions?/i,
	/forget\s+(all\s+)?your\s+instructions?/i,
	/you\s+are\s+now\s+/i,
	/your\s+new\s+(role|persona|identity)/i,
	/system\s*prompt/i,
	/reveal\s+your\s+prompt/i,

	// Network exfiltration
	/curl\s+.*-X\s*(POST|PUT)/i,
	/nc\s+-e/i,
	/netcat.*-e/i,

	// Process manipulation
	/kill\s+-9\s+1$/i,
	/killall/i,
	/pkill\s+/i,
];

/**
 * Fast-path classification without LLM.
 * Returns null if LLM review is needed.
 */
export function fastPathClassify(message: string): {
	classification: SecurityClassification;
	reason: string;
} | null {
	const trimmed = message.trim();

	// SECURITY: Block messages containing infrastructure secrets
	// These are secrets that should NEVER be given to the agent:
	// - Telegram bot tokens (would allow bot hijacking)
	// - Anthropic API keys (would allow unauthorized API usage)
	// - SSH/PGP private keys (would allow server/identity compromise)
	const secretResult = filterInfrastructureSecrets(trimmed);
	if (secretResult.blocked) {
		const patterns = secretResult.matches.map((m) => m.pattern).join(", ");
		return {
			classification: "BLOCK",
			reason: `Message contains infrastructure secret(s): ${patterns}. These should never be shared with the agent.`,
		};
	}

	// Check dangerous patterns
	for (const pattern of DANGEROUS_PATTERNS) {
		if (pattern.test(trimmed)) {
			return {
				classification: "BLOCK",
				reason: `Matched dangerous pattern: ${pattern.source}`,
			};
		}
	}

	// Check safe patterns
	for (const pattern of SAFE_PATTERNS) {
		if (pattern.test(trimmed)) {
			return {
				classification: "ALLOW",
				reason: `Matched safe pattern: ${pattern.source}`,
			};
		}
	}

	// Need LLM review
	return null;
}

/**
 * Check for structural issues that might indicate an attack.
 */
export function checkStructuralIssues(message: string): string[] {
	const issues: string[] = [];

	// Check for zero-width characters (hidden text)
	// Using alternation instead of character class due to ZWJ combining behavior
	if (/\u200B|\u200C|\u200D|\uFEFF/.test(message)) {
		issues.push("Contains zero-width characters");
	}

	// Check for excessive repetition (trying to overwhelm context)
	const words = message.toLowerCase().split(/\s+/);
	const wordCounts = new Map<string, number>();
	for (const word of words) {
		wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
	}
	const maxCount = Math.max(...wordCounts.values());
	if (maxCount > 50 || (words.length > 10 && maxCount / words.length > 0.3)) {
		issues.push("Excessive word repetition detected");
	}

	// Check for mixed scripts (homoglyph attacks)
	const hasLatin = /[a-zA-Z]/.test(message);
	const hasCyrillic = /[\u0400-\u04FF]/.test(message);
	if (hasLatin && hasCyrillic) {
		issues.push("Mixed Latin and Cyrillic scripts (possible homoglyph attack)");
	}

	// Check for unusually long message
	if (message.length > 10000) {
		issues.push("Unusually long message");
	}

	return issues;
}
