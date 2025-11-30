import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import JSON5 from "json5";
import type { MsgContext } from "../auto-reply/templating.js";
import { CONFIG_DIR, normalizeTelegramId } from "../utils.js";

export type SessionScope = "per-sender" | "global";

export type SessionEntry = {
	sessionId: string;
	updatedAt: number;
	systemSent?: boolean;
};

export const SESSION_STORE_DEFAULT = path.join(CONFIG_DIR, "sessions.json");
export const DEFAULT_RESET_TRIGGER = "/new";
export const DEFAULT_IDLE_MINUTES = 60;

/**
 * Type guard for individual session entries.
 */
function isValidSessionEntry(entry: unknown): entry is SessionEntry {
	return (
		typeof entry === "object" &&
		entry !== null &&
		"sessionId" in entry &&
		typeof (entry as SessionEntry).sessionId === "string" &&
		"updatedAt" in entry &&
		typeof (entry as SessionEntry).updatedAt === "number"
	);
}

/**
 * Validate and filter session store entries.
 */
function validateSessionStore(parsed: unknown): Record<string, SessionEntry> {
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return {};
	}

	const result: Record<string, SessionEntry> = {};
	for (const [key, value] of Object.entries(parsed)) {
		if (isValidSessionEntry(value)) {
			result[key] = value;
		}
	}
	return result;
}

export function resolveStorePath(store?: string) {
	if (!store) return SESSION_STORE_DEFAULT;
	if (store.startsWith("~")) return path.resolve(store.replace("~", os.homedir()));
	return path.resolve(store);
}

export function loadSessionStore(storePath: string): Record<string, SessionEntry> {
	try {
		const raw = fs.readFileSync(storePath, "utf-8");
		const parsed = JSON5.parse(raw) as unknown;
		return validateSessionStore(parsed);
	} catch {
		// ignore missing/invalid store; we'll recreate it
	}
	return {};
}

export async function saveSessionStore(storePath: string, store: Record<string, SessionEntry>) {
	await fs.promises.mkdir(path.dirname(storePath), { recursive: true });
	await fs.promises.writeFile(storePath, JSON.stringify(store, null, 2), "utf-8");
}

// Decide which session bucket to use (per-sender vs global).
export function deriveSessionKey(scope: SessionScope, ctx: MsgContext) {
	if (scope === "global") return "global";
	const from = ctx.From ? normalizeTelegramId(ctx.From) : "";
	return from || "unknown";
}
