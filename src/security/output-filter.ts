/**
 * Output filter for detecting and blocking secret exfiltration.
 *
 * SECURITY ARCHITECTURE:
 * - CORE patterns: NEVER configurable, NEVER removable
 * - Additive patterns: Users can ADD, never remove CORE
 * - Entropy detection: Catches encoded/obfuscated secrets
 *
 * SECURITY PRINCIPLE:
 * - Claude CAN see secrets (needed to complete tasks)
 * - Claude CANNOT send secrets out (exfiltration prevention)
 *
 * Surface area coverage (everything leaving the process):
 * - Telegram messages
 * - Tool results
 * - File contents when agent reads them back
 * - Error messages
 * - Audit logs
 * - Debug logs
 */

export interface SecretPattern {
	name: string;
	pattern: RegExp;
	severity: "critical" | "high";
	description: string;
	/** If true, this is a CORE pattern that cannot be removed */
	core?: boolean;
}

/**
 * CORE secret patterns - NEVER configurable, NEVER removable.
 * These are the foundational patterns that must always be enforced.
 */
export const CORE_SECRET_PATTERNS: SecretPattern[] = [
	// === CRITICAL: Telclaude infrastructure ===
	{
		name: "telegram_bot_token",
		// BotFather tokens are digits + ':' + 35-ish chars (can vary slightly). Loosen length to avoid false negatives.
		pattern: /\b\d{8,10}:[A-Za-z0-9_-]{32,64}\b/,
		severity: "critical",
		description: "Telegram bot token - would allow bot hijacking",
		core: true,
	},
	{
		name: "anthropic_api_key",
		// Real keys are long (~45 chars) but allow shorter in case format shifts; keep broad to avoid misses.
		pattern: /\bsk-ant-[A-Za-z0-9_-]{10,}\b/,
		severity: "critical",
		description: "Anthropic API key - would allow unauthorized API usage",
		core: true,
	},

	// === CRITICAL: Private keys ===
	{
		name: "ssh_private_key",
		pattern: /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----/,
		severity: "critical",
		description: "SSH private key - would allow server compromise",
		core: true,
	},
	{
		name: "pgp_private_key",
		pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/,
		severity: "critical",
		description: "PGP private key - would allow decryption/impersonation",
		core: true,
	},

	// === CRITICAL: TOTP seeds (base32) ===
	{
		name: "totp_seed",
		pattern: /\b[A-Z2-7]{32,}\b/,
		severity: "critical",
		description: "TOTP seed - would allow 2FA bypass",
		core: true,
	},

	// === HIGH: Cloud provider credentials ===
	{
		name: "aws_access_key",
		pattern: /\bAKIA[0-9A-Z]{16}\b/,
		severity: "high",
		description: "AWS access key ID",
		core: true,
	},
	{
		name: "aws_secret_key",
		pattern: /\baws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
		severity: "high",
		description: "AWS secret access key",
		core: true,
	},
	{
		name: "gcp_service_account",
		pattern: /"type"\s*:\s*"service_account"[\s\S]*?"private_key"\s*:/,
		severity: "high",
		description: "GCP service account key",
		core: true,
	},

	// === HIGH: API keys and tokens ===
	{
		name: "openai_api_key",
		pattern: /\bsk-[A-Za-z0-9]{48,}\b/,
		severity: "high",
		description: "OpenAI API key",
		core: true,
	},
	{
		name: "github_pat",
		pattern: /\bghp_[A-Za-z0-9]{36}\b/,
		severity: "high",
		description: "GitHub personal access token",
		core: true,
	},
	{
		name: "github_oauth",
		pattern: /\bgho_[A-Za-z0-9]{36}\b/,
		severity: "high",
		description: "GitHub OAuth token",
		core: true,
	},
	{
		name: "slack_token",
		pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
		severity: "high",
		description: "Slack API token",
		core: true,
	},
	{
		name: "stripe_key",
		pattern: /\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b/,
		severity: "high",
		description: "Stripe API key",
		core: true,
	},
	{
		name: "sendgrid_key",
		pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
		severity: "high",
		description: "SendGrid API key",
		core: true,
	},
	{
		name: "twilio_key",
		pattern: /\bSK[a-f0-9]{32}\b/,
		severity: "high",
		description: "Twilio API key",
		core: true,
	},

	// === HIGH: JWTs (can contain sensitive claims) ===
	{
		name: "jwt",
		pattern: /\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/,
		severity: "high",
		description: "JSON Web Token",
		core: true,
	},

	// === HIGH: Database connection strings with passwords ===
	{
		name: "connection_string_password",
		pattern: /\b(mongodb|postgres|mysql|redis):\/\/[^:]+:([^@]+)@/,
		severity: "high",
		description: "Database connection string with password",
		core: true,
	},

	// === HIGH: Generic env var patterns ===
	{
		name: "env_secret",
		pattern: /\b(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?/i,
		severity: "high",
		description: "Environment variable containing secret",
		core: true,
	},
];

/**
 * All secret patterns (CORE patterns).
 * This is the main export used by the filter.
 */
export const SECRET_PATTERNS: SecretPattern[] = CORE_SECRET_PATTERNS;

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
 * Redact all secrets from a text string.
 * Replaces detected secrets with [REDACTED:pattern_name].
 *
 * SECURITY: Use this for log sanitization to prevent secrets from
 * appearing in audit logs, error messages, or debug output.
 *
 * @param text - The text to sanitize
 * @returns Text with all detected secrets replaced
 */
export function redactSecrets(text: string): string {
	let result = text;

	for (const { name, pattern } of SECRET_PATTERNS) {
		// Create new regex instance, preserving original flags but ensuring global
		const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
		const regex = new RegExp(pattern.source, flags);
		if (name === "totp_seed") {
			// Avoid redacting low-entropy base32-looking text (reduces false positives)
			result = result.replace(regex, (m) =>
				calculateEntropy(m) >= TOTP_ENTROPY_THRESHOLD ? `[REDACTED:${name}]` : m,
			);
		} else {
			result = result.replace(regex, `[REDACTED:${name}]`);
		}
	}

	return result;
}

/**
 * Scan text for secret patterns.
 * Returns all matches found.
 */
function scanPlainText(text: string): FilterMatch[] {
	const matches: FilterMatch[] = [];

	for (const { name, pattern, severity, description } of SECRET_PATTERNS) {
		// Create new regex instance, preserving original flags but ensuring global
		// CRITICAL: Without 'g' flag, exec() never advances lastIndex → infinite loop
		const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
		const regex = new RegExp(pattern.source, flags);

		for (let match = regex.exec(text); match !== null; match = regex.exec(text)) {
			// Reduce false positives for base32-like TOTP seeds by checking entropy
			if (name === "totp_seed" && calculateEntropy(match[0]) < TOTP_ENTROPY_THRESHOLD) {
				continue;
			}
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

// ═══════════════════════════════════════════════════════════════════════════════
// Config-Aware Filtering
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Configuration for secret filtering.
 * Allows users to ADD patterns (never remove CORE patterns) and tune entropy detection.
 */
export interface SecretFilterConfig {
	additionalPatterns?: Array<{ id: string; pattern: string }>;
	entropyDetection?: { enabled?: boolean; threshold?: number; minLength?: number };
}

// Entropy threshold for treating base32 blobs as TOTP seeds.
const TOTP_ENTROPY_THRESHOLD = 4.0;

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy = more random = more likely to be a secret.
 */
export function calculateEntropy(str: string): number {
	const len = str.length;
	if (len === 0) return 0;

	const freq: Record<string, number> = {};
	for (const char of str) {
		freq[char] = (freq[char] || 0) + 1;
	}

	let entropy = 0;
	for (const count of Object.values(freq)) {
		const p = count / len;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

/**
 * Detect high-entropy blobs that might be encoded secrets.
 * Looks for base64-like or hex-like strings with high randomness.
 */
export function detectHighEntropyBlobs(
	text: string,
	threshold: number,
	minLength: number,
): string[] {
	const suspiciousBlobs: string[] = [];
	const blobPattern = /[=:]\s*['"]?([a-zA-Z0-9+/=]{32,}|[a-fA-F0-9]{32,})['"]?/g;
	for (const match of text.matchAll(blobPattern)) {
		const blob = match[1];
		if (blob && blob.length >= minLength) {
			const entropy = calculateEntropy(blob);
			if (entropy > threshold) {
				suspiciousBlobs.push(blob);
			}
		}
	}
	return suspiciousBlobs;
}

/**
 * Filter output with user configuration.
 * Applies CORE patterns + additional patterns + entropy detection.
 *
 * @param text - The text to scan
 * @param config - Optional secret filter configuration
 * @returns FilterResult with blocked status and all matches
 */
export function filterOutputWithConfig(text: string, config?: SecretFilterConfig): FilterResult {
	// Start with CORE pattern detection
	const result = filterOutput(text);
	const allMatches = [...result.matches];

	// Apply user-defined additional patterns
	if (config?.additionalPatterns) {
		for (const { id, pattern } of config.additionalPatterns) {
			try {
				const regex = new RegExp(pattern, "g");
				for (const match of text.matchAll(regex)) {
					allMatches.push({
						pattern: `user:${id}`,
						severity: "high",
						description: `User-defined pattern: ${id}`,
						redactedMatch: redact(match[0]),
					});
				}
			} catch {
				// Invalid regex pattern, skip
			}
		}
	}

	// Apply entropy detection (enabled by default)
	if (config?.entropyDetection?.enabled !== false) {
		const threshold = config?.entropyDetection?.threshold ?? 4.5;
		const minLength = config?.entropyDetection?.minLength ?? 32;
		const blobs = detectHighEntropyBlobs(text, threshold, minLength);
		for (const blob of blobs) {
			allMatches.push({
				pattern: "HIGH_ENTROPY",
				severity: "high",
				description: "High-entropy blob detected (possible encoded secret)",
				redactedMatch: redact(blob),
			});
		}
	}

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
 * Redact secrets from text using configuration.
 * Applies CORE patterns + additional patterns + entropy detection.
 *
 * @param text - The text to redact
 * @param config - Optional secret filter configuration
 * @returns Text with all detected secrets replaced
 */
export function redactSecretsWithConfig(text: string, config?: SecretFilterConfig): string {
	// Start with CORE pattern redaction
	let result = redactSecrets(text);

	// Apply user-defined additional patterns
	if (config?.additionalPatterns) {
		for (const { id, pattern } of config.additionalPatterns) {
			try {
				const regex = new RegExp(pattern, "g");
				result = result.replace(regex, `[REDACTED:user:${id}]`);
			} catch {
				// Invalid regex pattern, skip
			}
		}
	}

	// Apply entropy detection (enabled by default)
	if (config?.entropyDetection?.enabled !== false) {
		const threshold = config?.entropyDetection?.threshold ?? 4.5;
		const minLength = config?.entropyDetection?.minLength ?? 32;
		const blobs = detectHighEntropyBlobs(result, threshold, minLength);
		for (const blob of blobs) {
			result = result.replace(blob, "[REDACTED:HIGH_ENTROPY]");
		}
	}

	return result;
}
