import fs from "node:fs";
import os from "node:os";

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

export const CONFIG_DIR = `${os.homedir()}/.telclaude`;
