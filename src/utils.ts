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
 */
export function stringToChatId(str: string): number {
	const withoutPrefix = str.replace(/^tg:/, "");
	return Number.parseInt(withoutPrefix, 10);
}

/**
 * Normalize a Telegram identifier (could be chat_id or username).
 */
export function normalizeTelegramId(id: string | number): string {
	if (typeof id === "number") {
		return chatIdToString(id);
	}
	// If already has prefix, return as-is
	if (id.startsWith("tg:")) {
		return id;
	}
	// If it's a numeric string, add prefix
	if (/^\d+$/.test(id)) {
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
