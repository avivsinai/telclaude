import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import JSON5 from "json5";
import { getChildLogger } from "../logging.js";
import { CONFIG_DIR } from "../utils.js";
import type { Result } from "./types.js";

const logger = getChildLogger({ module: "identity-linking" });

const LINKS_FILE = path.join(CONFIG_DIR, "links.json");
const CODE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

/**
 * A pending link code awaiting chat verification.
 */
export type PendingLinkCode = {
	code: string;
	localUserId: string;
	createdAt: number;
	expiresAt: number;
};

/**
 * A completed identity link between a Telegram chat and a local user.
 */
export type IdentityLink = {
	chatId: number;
	localUserId: string;
	linkedAt: number;
	linkedBy: string; // The username or chat identifier who linked
};

/**
 * Store for pending link codes and completed links.
 */
export type LinkStore = {
	pendingCodes: Record<string, PendingLinkCode>; // code -> entry
	links: Record<string, IdentityLink>; // chatId -> link
};

/**
 * Type guard for PendingLinkCode.
 */
function isValidPendingLinkCode(entry: unknown): entry is PendingLinkCode {
	return (
		typeof entry === "object" &&
		entry !== null &&
		"code" in entry &&
		typeof (entry as PendingLinkCode).code === "string" &&
		"localUserId" in entry &&
		typeof (entry as PendingLinkCode).localUserId === "string" &&
		"createdAt" in entry &&
		typeof (entry as PendingLinkCode).createdAt === "number" &&
		"expiresAt" in entry &&
		typeof (entry as PendingLinkCode).expiresAt === "number"
	);
}

/**
 * Type guard for IdentityLink.
 */
function isValidIdentityLink(entry: unknown): entry is IdentityLink {
	return (
		typeof entry === "object" &&
		entry !== null &&
		"chatId" in entry &&
		typeof (entry as IdentityLink).chatId === "number" &&
		"localUserId" in entry &&
		typeof (entry as IdentityLink).localUserId === "string" &&
		"linkedAt" in entry &&
		typeof (entry as IdentityLink).linkedAt === "number" &&
		"linkedBy" in entry &&
		typeof (entry as IdentityLink).linkedBy === "string"
	);
}

/**
 * Validate a parsed link store.
 */
function validateLinkStore(parsed: unknown): LinkStore {
	const result: LinkStore = { pendingCodes: {}, links: {} };

	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return result;
	}

	const obj = parsed as { pendingCodes?: unknown; links?: unknown };

	// Validate pending codes
	if (
		obj.pendingCodes &&
		typeof obj.pendingCodes === "object" &&
		!Array.isArray(obj.pendingCodes)
	) {
		for (const [code, entry] of Object.entries(obj.pendingCodes)) {
			if (isValidPendingLinkCode(entry)) {
				result.pendingCodes[code] = entry;
			}
		}
	}

	// Validate links
	if (obj.links && typeof obj.links === "object" && !Array.isArray(obj.links)) {
		for (const [chatId, link] of Object.entries(obj.links)) {
			if (isValidIdentityLink(link)) {
				result.links[chatId] = link;
			}
		}
	}

	return result;
}

/**
 * Load the link store from disk.
 */
export function loadLinkStore(): LinkStore {
	try {
		const content = fs.readFileSync(LINKS_FILE, "utf-8");
		const parsed = JSON5.parse(content) as unknown;
		const store = validateLinkStore(parsed);

		// Clean up expired codes
		const now = Date.now();
		for (const [code, entry] of Object.entries(store.pendingCodes)) {
			if (entry.expiresAt < now) {
				delete store.pendingCodes[code];
			}
		}

		return store;
	} catch {
		return { pendingCodes: {}, links: {} };
	}
}

/**
 * Save the link store to disk.
 */
export function saveLinkStore(store: LinkStore): void {
	fs.mkdirSync(path.dirname(LINKS_FILE), { recursive: true });
	fs.writeFileSync(LINKS_FILE, JSON.stringify(store, null, 2), "utf-8");
}

/**
 * Generate a new link code for a local user.
 * Returns the generated code.
 */
export function generateLinkCode(localUserId: string): string {
	const store = loadLinkStore();
	const now = Date.now();

	// Generate a random 8-character code (4 bytes = 8 hex chars)
	const code = crypto.randomBytes(4).toString("hex").toUpperCase();

	// Format as XXXX-XXXX for readability
	const formattedCode = `${code.slice(0, 4)}-${code.slice(4)}`;

	store.pendingCodes[formattedCode] = {
		code: formattedCode,
		localUserId,
		createdAt: now,
		expiresAt: now + CODE_EXPIRY_MS,
	};

	saveLinkStore(store);

	logger.info({ code: formattedCode, localUserId }, "generated link code");

	return formattedCode;
}

/**
 * Verify and consume a link code, creating an identity link.
 * Returns the local user ID if successful, or an error if invalid/expired.
 */
export function consumeLinkCode(
	code: string,
	chatId: number,
	linkedBy: string,
): Result<{ localUserId: string }> {
	const store = loadLinkStore();
	const now = Date.now();

	// Normalize code format (allow with or without dash)
	const normalizedCode = code.toUpperCase().replace(/[^A-F0-9]/g, "");
	const formattedCode =
		normalizedCode.length === 8
			? `${normalizedCode.slice(0, 4)}-${normalizedCode.slice(4)}`
			: code.toUpperCase();

	const entry = store.pendingCodes[formattedCode];

	if (!entry) {
		logger.warn({ code: formattedCode, chatId }, "invalid link code");
		return {
			success: false,
			error: "Invalid link code. Please generate a new one with `telclaude link`.",
		};
	}

	if (entry.expiresAt < now) {
		delete store.pendingCodes[formattedCode];
		saveLinkStore(store);
		logger.warn({ code: formattedCode, chatId }, "expired link code");
		return {
			success: false,
			error: "Link code has expired. Please generate a new one with `telclaude link`.",
		};
	}

	// Create the identity link
	const chatIdStr = String(chatId);
	store.links[chatIdStr] = {
		chatId,
		localUserId: entry.localUserId,
		linkedAt: now,
		linkedBy,
	};

	// Remove the consumed code
	delete store.pendingCodes[formattedCode];

	saveLinkStore(store);

	logger.info(
		{ code: formattedCode, chatId, localUserId: entry.localUserId, linkedBy },
		"identity link created",
	);

	return { success: true, data: { localUserId: entry.localUserId } };
}

/**
 * Get the identity link for a chat, if any.
 */
export function getIdentityLink(chatId: number): IdentityLink | null {
	const store = loadLinkStore();
	return store.links[String(chatId)] ?? null;
}

/**
 * Remove an identity link for a chat.
 */
export function removeIdentityLink(chatId: number): boolean {
	const store = loadLinkStore();
	const chatIdStr = String(chatId);

	if (store.links[chatIdStr]) {
		delete store.links[chatIdStr];
		saveLinkStore(store);
		logger.info({ chatId }, "identity link removed");
		return true;
	}

	return false;
}

/**
 * List all identity links.
 */
export function listIdentityLinks(): IdentityLink[] {
	const store = loadLinkStore();
	return Object.values(store.links);
}

/**
 * Check if a chat has a verified identity link.
 */
export function isLinked(chatId: number): boolean {
	return getIdentityLink(chatId) !== null;
}
