import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export async function ensureDir(dir: string) {
	await fs.promises.mkdir(dir, { recursive: true });
}

export function normalizePath(p: string): string {
	if (!p.startsWith("/")) return `/${p}`;
	return p;
}

/**
 * Convert Telegram chat_id to a normalized string format.
 * Prefixed with "tg:" for clarity and to distinguish from phone numbers.
 */
export function chatIdToString(chatId: number | string): string {
	return `tg:${chatId}`;
}

/**
 * Extract numeric chat_id from our string format.
 * Returns NaN if the string is not a valid tg: formatted ID.
 */
export function stringToChatId(str: string): number {
	const withoutPrefix = str.replace(/^tg:/, "");
	// Validate that the remaining string is purely numeric (with optional leading minus for negative IDs)
	if (!/^-?\d+$/.test(withoutPrefix)) {
		return Number.NaN;
	}
	return Number.parseInt(withoutPrefix, 10);
}

/**
 * Normalize a Telegram identifier (could be chat_id or username).
 * Returns null if the input is invalid (e.g., tg: prefix with non-numeric value).
 */
export function normalizeTelegramId(id: string | number): string | null {
	if (typeof id === "number") {
		return chatIdToString(id);
	}
	// If already has prefix, validate that the rest is numeric
	if (id.startsWith("tg:")) {
		const numPart = id.slice(3);
		// Must be purely numeric (with optional leading minus for negative IDs like group chats)
		if (!/^-?\d+$/.test(numPart)) {
			return null;
		}
		return id;
	}
	// If it's a numeric string (with optional leading minus), add prefix
	if (/^-?\d+$/.test(id)) {
		return `tg:${id}`;
	}
	// If it's a username (starts with @), normalize it
	if (id.startsWith("@")) {
		return id.toLowerCase();
	}
	return id;
}

export function sleep(ms: number) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Validate and resolve TELCLAUDE_DATA_DIR.
 * Rejects: ~ paths (not expanded), relative paths, empty strings.
 * Returns normalized path (no trailing slash) or null if invalid.
 */
function resolveDataDir(): string | null {
	const dataDir = process.env.TELCLAUDE_DATA_DIR;
	if (!dataDir) return null;

	// Reject ~ paths (shell doesn't expand in env vars)
	if (dataDir.startsWith("~")) {
		console.error(
			`ERROR: TELCLAUDE_DATA_DIR contains ~ which won't expand. Use absolute path like /data or ${os.homedir()}/.telclaude`,
		);
		return null;
	}

	// Reject relative paths (security risk: could place files in workspace)
	if (!path.isAbsolute(dataDir)) {
		console.error(`ERROR: TELCLAUDE_DATA_DIR must be absolute path, got: ${dataDir}`);
		return null;
	}

	// Normalize: remove trailing slash for consistent matching
	return dataDir.replace(/\/+$/, "");
}

/**
 * Escape special regex characters in a string.
 */
export function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Validated TELCLAUDE_DATA_DIR (null if not set or invalid).
 * Use this for sensitive path checks instead of raw process.env.
 */
export const VALIDATED_DATA_DIR = resolveDataDir();

// Use TELCLAUDE_DATA_DIR if set and valid (Docker), otherwise ~/.telclaude (native)
export const CONFIG_DIR = VALIDATED_DATA_DIR || `${os.homedir()}/.telclaude`;

/**
 * Sanitize error messages to prevent credential leakage.
 * Redacts URLs which may contain tokens in query strings or reveal sensitive endpoints.
 *
 * @param err - The error to sanitize
 * @param preservePath - If true, keeps host/path but redacts query strings.
 *                       If false, redacts the entire URL.
 */
export function sanitizeError(err: unknown, preservePath = false): string {
	const message = String(err);

	if (preservePath) {
		// Replace URLs but keep host/path, only redact query parameters
		return message.replace(/https?:\/\/[^\s]+\?[^\s]*/g, (url) => {
			try {
				const parsed = new URL(url);
				return `${parsed.protocol}//${parsed.host}${parsed.pathname}?[REDACTED]`;
			} catch {
				return "[URL REDACTED]";
			}
		});
	}

	// Replace entire URLs (may contain tokens or reveal sensitive endpoints)
	return message.replace(/https?:\/\/[^\s]+/g, "[URL REDACTED]");
}
