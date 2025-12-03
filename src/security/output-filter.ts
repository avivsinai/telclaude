/**
 * Output filter for detecting and blocking secret exfiltration.
 *
 * SECURITY PRINCIPLE:
 * - Claude CAN see secrets (needed to complete tasks)
 * - Claude CANNOT send secrets out (exfiltration prevention)
 *
 * This filter runs on ALL outbound channels:
 * 1. Telegram responses (primary exfiltration risk)
 * 2. Network request URLs/bodies (WebFetch, curl, etc.)
 *
 * Defense layers:
 * 1. Plain text pattern matching
 * 2. Base64 decode and scan
 * 3. Hex decode and scan
 * 4. URL decode and scan
 * 5. Rolling buffer for split-across-chunks detection
 */

export interface SecretPattern {
	name: string;
	pattern: RegExp;
	severity: "critical" | "high";
	description: string;
}

/**
 * Secret patterns to detect.
 *
 * CRITICAL: Infrastructure secrets that could compromise telclaude itself
 * HIGH: Secrets that could compromise user's external services
 */
export const SECRET_PATTERNS: SecretPattern[] = [
	// === CRITICAL: Telclaude infrastructure ===
	{
		name: "telegram_bot_token",
		pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/,
		severity: "critical",
		description: "Telegram bot token - would allow bot hijacking",
	},
	{
		name: "anthropic_api_key",
		pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
		severity: "critical",
		description: "Anthropic API key - would allow unauthorized API usage",
	},

	// === CRITICAL: Private keys ===
	{
		name: "ssh_private_key",
		pattern: /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----/,
		severity: "critical",
		description: "SSH private key - would allow server compromise",
	},
	{
		name: "pgp_private_key",
		pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/,
		severity: "critical",
		description: "PGP private key - would allow decryption/impersonation",
	},

	// === HIGH: Cloud provider credentials ===
	{
		name: "aws_access_key",
		pattern: /\bAKIA[0-9A-Z]{16}\b/,
		severity: "high",
		description: "AWS access key ID",
	},
	{
		name: "aws_secret_key",
		// AWS secret keys are 40 chars, base64-ish
		pattern: /\baws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
		severity: "high",
		description: "AWS secret access key",
	},
	{
		name: "gcp_service_account",
		pattern: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:/,
		severity: "high",
		description: "GCP service account key",
	},

	// === HIGH: API keys and tokens ===
	{
		name: "openai_api_key",
		pattern: /\bsk-[A-Za-z0-9]{48,}\b/,
		severity: "high",
		description: "OpenAI API key",
	},
	{
		name: "github_token",
		pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/,
		severity: "high",
		description: "GitHub personal access token",
	},
	{
		name: "github_oauth",
		pattern: /\bgho_[A-Za-z0-9]{36,}\b/,
		severity: "high",
		description: "GitHub OAuth token",
	},
	{
		name: "slack_token",
		pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
		severity: "high",
		description: "Slack API token",
	},
	{
		name: "stripe_key",
		pattern: /\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b/,
		severity: "high",
		description: "Stripe API key",
	},
	{
		name: "sendgrid_key",
		pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
		severity: "high",
		description: "SendGrid API key",
	},
	{
		name: "twilio_key",
		pattern: /\bSK[a-f0-9]{32}\b/,
		severity: "high",
		description: "Twilio API key",
	},

	// === HIGH: Database connection strings with passwords ===
	{
		name: "connection_string_password",
		pattern: /\b(mongodb|postgres|mysql|redis):\/\/[^:]+:([^@]+)@/,
		severity: "high",
		description: "Database connection string with password",
	},

	// === HIGH: JWT secrets ===
	{
		name: "jwt_secret",
		pattern: /\b(jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9_-]{16,})['"]?/i,
		severity: "high",
		description: "JWT secret key",
	},
];

export interface FilterMatch {
	pattern: string;
	severity: "critical" | "high";
	description: string;
	/** Redacted match for safe logging (first 4 + last 4 chars) */
	redactedMatch: string;
}

export interface FilterResult {
	blocked: boolean;
	matches: FilterMatch[];
}

/**
 * Redact a secret for safe logging.
 * Shows first 4 and last 4 characters only.
 */
function redact(secret: string): string {
	if (secret.length <= 12) {
		return `${"*".repeat(secret.length)}`;
	}
	return `${secret.slice(0, 4)}...[REDACTED]...${secret.slice(-4)}`;
}

/**
 * Scan text for secret patterns.
 * Returns all matches found.
 */
function scanPlainText(text: string): FilterMatch[] {
	const matches: FilterMatch[] = [];

	for (const { name, pattern, severity, description } of SECRET_PATTERNS) {
		// Create new regex instance to reset state
		const regex = new RegExp(pattern.source, pattern.flags || "g");

		for (let match = regex.exec(text); match !== null; match = regex.exec(text)) {
			matches.push({
				pattern: name,
				severity,
				description,
				redactedMatch: redact(match[0]),
			});

			// Prevent infinite loop for zero-length matches
			if (match[0].length === 0) {
				regex.lastIndex++;
			}
		}
	}

	return matches;
}

/**
 * Decode base64 strings and scan for secrets.
 * Handles both standard and URL-safe base64.
 */
function scanBase64(text: string): FilterMatch[] {
	const matches: FilterMatch[] = [];

	// Find potential base64 strings (at least 20 chars)
	const base64Pattern = /\b[A-Za-z0-9+/_-]{20,}={0,2}\b/g;

	for (
		let b64Match = base64Pattern.exec(text);
		b64Match !== null;
		b64Match = base64Pattern.exec(text)
	) {
		try {
			// Try standard base64
			const decoded = Buffer.from(b64Match[0], "base64").toString("utf-8");

			// Check if it decoded to mostly printable ASCII
			const printableRatio =
				decoded.split("").filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length /
				decoded.length;

			if (printableRatio > 0.8) {
				const innerMatches = scanPlainText(decoded);
				for (const m of innerMatches) {
					matches.push({
						...m,
						pattern: `base64(${m.pattern})`,
						redactedMatch: `base64(${m.redactedMatch})`,
					});
				}
			}
		} catch {
			// Not valid base64, ignore
		}
	}

	return matches;
}

/**
 * Decode hex strings and scan for secrets.
 */
function scanHex(text: string): FilterMatch[] {
	const matches: FilterMatch[] = [];

	// Find potential hex strings (at least 20 chars, even length)
	const hexPattern = /\b[0-9a-fA-F]{20,}\b/g;

	for (let hexMatch = hexPattern.exec(text); hexMatch !== null; hexMatch = hexPattern.exec(text)) {
		const hex = hexMatch[0];
		if (hex.length % 2 !== 0) continue; // Must be even length

		try {
			const decoded = Buffer.from(hex, "hex").toString("utf-8");

			// Check if it decoded to mostly printable ASCII
			const printableRatio =
				decoded.split("").filter((c) => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length /
				decoded.length;

			if (printableRatio > 0.8) {
				const innerMatches = scanPlainText(decoded);
				for (const m of innerMatches) {
					matches.push({
						...m,
						pattern: `hex(${m.pattern})`,
						redactedMatch: `hex(${m.redactedMatch})`,
					});
				}
			}
		} catch {
			// Not valid hex, ignore
		}
	}

	return matches;
}

/**
 * Decode URL-encoded strings and scan for secrets.
 */
function scanUrlEncoded(text: string): FilterMatch[] {
	const matches: FilterMatch[] = [];

	// Find URL-encoded sequences (at least 3 encoded chars)
	const urlPattern = /(%[0-9a-fA-F]{2}){3,}/g;

	for (let urlMatch = urlPattern.exec(text); urlMatch !== null; urlMatch = urlPattern.exec(text)) {
		try {
			const decoded = decodeURIComponent(urlMatch[0]);
			const innerMatches = scanPlainText(decoded);
			for (const m of innerMatches) {
				matches.push({
					...m,
					pattern: `urlencoded(${m.pattern})`,
					redactedMatch: `urlencoded(${m.redactedMatch})`,
				});
			}
		} catch {
			// Invalid URL encoding, ignore
		}
	}

	return matches;
}

/**
 * Main filter function: scan text for secrets using all detection methods.
 *
 * @param text - The text to scan (Telegram message, URL, request body, etc.)
 * @returns FilterResult with blocked status and all matches
 */
export function filterOutput(text: string): FilterResult {
	const allMatches: FilterMatch[] = [];

	// Layer 1: Plain text patterns
	allMatches.push(...scanPlainText(text));

	// Layer 2: Base64 encoded
	allMatches.push(...scanBase64(text));

	// Layer 3: Hex encoded
	allMatches.push(...scanHex(text));

	// Layer 4: URL encoded
	allMatches.push(...scanUrlEncoded(text));

	// Deduplicate by pattern + redactedMatch
	const seen = new Set<string>();
	const uniqueMatches = allMatches.filter((m) => {
		const key = `${m.pattern}:${m.redactedMatch}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});

	return {
		blocked: uniqueMatches.length > 0,
		matches: uniqueMatches,
	};
}

/**
 * Filter specifically for CRITICAL infrastructure secrets.
 * These are always blocked with no exceptions.
 */
export function filterInfrastructureSecrets(text: string): FilterResult {
	const result = filterOutput(text);
	const criticalMatches = result.matches.filter((m) => m.severity === "critical");

	return {
		blocked: criticalMatches.length > 0,
		matches: criticalMatches,
	};
}

/**
 * Rolling buffer for detecting secrets split across message chunks.
 *
 * Usage:
 * ```
 * const buffer = new ChunkBuffer();
 * for (const chunk of responseChunks) {
 *   buffer.add(chunk);
 *   const result = buffer.scan();
 *   if (result.blocked) {
 *     // Abort - secret detected
 *   }
 * }
 * ```
 */
export class ChunkBuffer {
	private buffer = "";
	// Keep enough context to detect split secrets (longest pattern ~100 chars)
	private readonly maxSize: number = 200;

	/**
	 * Add a chunk to the buffer.
	 */
	add(chunk: string): void {
		this.buffer += chunk;
		// Keep only the tail to limit memory usage
		if (this.buffer.length > this.maxSize * 2) {
			this.buffer = this.buffer.slice(-this.maxSize);
		}
	}

	/**
	 * Scan the buffer for secrets.
	 */
	scan(): FilterResult {
		return filterOutput(this.buffer);
	}

	/**
	 * Get the full accumulated text (for final scan).
	 */
	getText(): string {
		return this.buffer;
	}

	/**
	 * Reset the buffer.
	 */
	reset(): void {
		this.buffer = "";
	}
}
