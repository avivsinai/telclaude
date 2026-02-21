import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { MemoryCategory, MemoryEntry, MemorySource, TrustLevel } from "./types.js";

const logger = getChildLogger({ module: "memory-store" });

export type MemoryEntryInput = {
	id: string;
	category: MemoryCategory;
	content: string;
	chatId?: string;
};

export type MemoryQuery = {
	categories?: MemoryCategory[];
	trust?: TrustLevel[];
	sources?: MemorySource[];
	limit?: number;
	order?: "asc" | "desc";
	/** Filter by promotion status */
	promoted?: boolean;
	/** Filter by posted status */
	posted?: boolean;
	/** Filter by chat ID (H3 multi-user scoping) */
	chatId?: string;
};

const DEFAULT_QUERY_LIMIT = 200;
const MAX_QUERY_LIMIT = 500;
const MAX_ENTRIES_PER_SOURCE_CHAT = 500;

function trustForSource(source: MemorySource): TrustLevel {
	return source === "telegram" ? "trusted" : "untrusted";
}

type MemoryEntryRow = {
	id: string;
	category: string;
	content: string;
	source: string;
	trust: string;
	created_at: number;
	promoted_at: number | null;
	promoted_by: string | null;
	posted_at: number | null;
	chat_id: string | null;
};

function rowToEntry(row: MemoryEntryRow): MemoryEntry {
	return {
		id: row.id,
		category: row.category as MemoryCategory,
		content: row.content,
		_provenance: {
			source: row.source as MemorySource,
			trust: row.trust as TrustLevel,
			createdAt: row.created_at,
			...(row.promoted_at ? { promotedAt: row.promoted_at } : {}),
			...(row.promoted_by ? { promotedBy: row.promoted_by } : {}),
			...(row.posted_at ? { postedAt: row.posted_at } : {}),
			...(row.chat_id ? { chatId: row.chat_id } : {}),
		},
	};
}

export function createEntries(
	entries: MemoryEntryInput[],
	source: MemorySource,
	createdAt = Date.now(),
): MemoryEntry[] {
	const db = getDb();
	const trust = trustForSource(source);

	const insert = db.prepare(
		`INSERT INTO memory_entries
			(id, category, content, source, trust, created_at, promoted_at, promoted_by, chat_id)
			VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)`,
	);
	const exists = db.prepare("SELECT 1 FROM memory_entries WHERE id = ?");

	const created: MemoryEntry[] = [];
	const txn = db.transaction(() => {
		for (const entry of entries) {
			const existing = exists.get(entry.id) as { 1: number } | undefined;
			if (existing) {
				throw new Error(`Memory entry already exists: ${entry.id}`);
			}
			insert.run(
				entry.id,
				entry.category,
				entry.content,
				source,
				trust,
				createdAt,
				entry.chatId ?? null,
			);
			created.push({
				id: entry.id,
				category: entry.category,
				content: entry.content,
				_provenance: {
					source,
					trust,
					createdAt,
					...(entry.chatId ? { chatId: entry.chatId } : {}),
				},
			});
		}
	});

	try {
		txn();
		logger.debug({ count: created.length, source }, "memory entries created");

		// M5: Enforce per-source-chat quota to prevent unbounded DB growth
		const chatId = entries[0]?.chatId;
		if (chatId) {
			const countRow = db
				.prepare("SELECT COUNT(*) as cnt FROM memory_entries WHERE source = ? AND chat_id = ?")
				.get(source, chatId) as { cnt: number };
			if (countRow.cnt > MAX_ENTRIES_PER_SOURCE_CHAT) {
				const excess = countRow.cnt - MAX_ENTRIES_PER_SOURCE_CHAT;
				db.prepare(
					`DELETE FROM memory_entries WHERE id IN (
						SELECT id FROM memory_entries
						WHERE source = ? AND chat_id = ?
						ORDER BY created_at ASC
						LIMIT ?
					)`,
				).run(source, chatId, excess);
				logger.info(
					{ source, chatId, deleted: excess },
					"quota enforcement: deleted oldest entries",
				);
			}
		}

		return created;
	} catch (err) {
		logger.warn({ error: String(err) }, "failed to create memory entries");
		throw err;
	}
}

export function getEntries(query: MemoryQuery = {}): MemoryEntry[] {
	const db = getDb();
	const where: string[] = [];
	const params: Array<string | number> = [];

	if (query.categories && query.categories.length > 0) {
		where.push(`category IN (${query.categories.map(() => "?").join(", ")})`);
		params.push(...query.categories);
	}
	if (query.trust && query.trust.length > 0) {
		where.push(`trust IN (${query.trust.map(() => "?").join(", ")})`);
		params.push(...query.trust);
	}
	if (query.sources && query.sources.length > 0) {
		where.push(`source IN (${query.sources.map(() => "?").join(", ")})`);
		params.push(...query.sources);
	}
	if (query.promoted === true) {
		where.push("promoted_at IS NOT NULL");
	} else if (query.promoted === false) {
		where.push("promoted_at IS NULL");
	}
	if (query.posted === true) {
		where.push("posted_at IS NOT NULL");
	} else if (query.posted === false) {
		where.push("posted_at IS NULL");
	}
	if (query.chatId) {
		where.push("chat_id = ?");
		params.push(query.chatId);
	}

	const order = query.order === "asc" ? "ASC" : "DESC";
	const limit = Math.min(Math.max(query.limit ?? DEFAULT_QUERY_LIMIT, 1), MAX_QUERY_LIMIT);

	const sql = `SELECT id, category, content, source, trust, created_at, promoted_at, promoted_by, posted_at, chat_id
		FROM memory_entries
		${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""}
		ORDER BY created_at ${order}
		LIMIT ?`;
	params.push(limit);

	const rows = db.prepare(sql).all(...params) as MemoryEntryRow[];

	return rows.map(rowToEntry);
}

export type PromoteEntryResult = { ok: true; entry: MemoryEntry } | { ok: false; reason: string };

/**
 * Promote a memory entry to trusted.
 *
 * Security constraints:
 * - Only allows category === "posts"
 * - Only allows source === "telegram" or "social"
 * - Telegram entries must be quarantined (consent-based workflow)
 * - Social entries must be untrusted (agent-written post ideas)
 * - Operator explicitly approves via /promote — consent is established
 */
export function promoteEntryTrust(id: string, promotedBy: string): PromoteEntryResult {
	const db = getDb();
	const existing = db
		.prepare(
			"SELECT id, category, content, source, trust, created_at, promoted_at, promoted_by, posted_at, chat_id FROM memory_entries WHERE id = ?",
		)
		.get(id) as
		| {
				id: string;
				category: string;
				content: string;
				source: string;
				trust: string;
				created_at: number;
				promoted_at: number | null;
				promoted_by: string | null;
				posted_at: number | null;
				chat_id: string | null;
		  }
		| undefined;

	if (!existing) {
		return { ok: false, reason: "Entry not found" };
	}

	// Security: Only allow posts category to be promoted
	if (existing.category !== "posts") {
		logger.warn(
			{ id, category: existing.category },
			"rejected promotion: only posts can be promoted",
		);
		return { ok: false, reason: "Only posts can be promoted" };
	}

	// Security: Only allow telegram or social source
	const allowedSources = ["telegram", "social"];
	if (!allowedSources.includes(existing.source)) {
		logger.warn({ id, source: existing.source }, "rejected promotion: invalid source");
		return { ok: false, reason: "Only telegram or social entries can be promoted" };
	}

	// Security: Enforce valid pre-promotion trust per source
	// - Telegram: must be quarantined (consent-based workflow)
	// - Social: must be untrusted (agent-written post ideas)
	const validTrust = existing.source === "telegram" ? "quarantined" : "untrusted";
	if (existing.trust !== validTrust) {
		return { ok: false, reason: `Only ${validTrust} ${existing.source} entries can be promoted` };
	}

	const now = Date.now();
	const result = db
		.prepare(
			`UPDATE memory_entries
			 SET trust = ?, promoted_at = ?, promoted_by = ?
			 WHERE id = ?`,
		)
		.run("trusted", now, promotedBy, id);

	if (result.changes === 0) {
		return { ok: false, reason: "Failed to update entry" };
	}

	logger.info({ id, promotedBy }, "memory entry promoted to trusted");

	return {
		ok: true,
		entry: {
			id: existing.id,
			category: existing.category as MemoryCategory,
			content: existing.content,
			_provenance: {
				source: existing.source as MemorySource,
				trust: "trusted",
				createdAt: existing.created_at,
				promotedAt: now,
				promotedBy,
			},
		},
	};
}

export function deleteEntry(id: string): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM memory_entries WHERE id = ?").run(id);
	return result.changes > 0;
}

/**
 * Mark a memory entry as posted (used for proactive social posting).
 * This prevents the same idea from being posted multiple times.
 */
export function markEntryPosted(id: string): boolean {
	const db = getDb();
	const result = db
		.prepare("UPDATE memory_entries SET posted_at = ? WHERE id = ? AND posted_at IS NULL")
		.run(Date.now(), id);

	if (result.changes > 0) {
		logger.info({ id }, "memory entry marked as posted");
	}

	return result.changes > 0;
}

/**
 * Create a quarantined memory entry (for consent-based idea bridge).
 *
 * Security constraints:
 * - Only creates entries with trust = "quarantined"
 * - Only allows category = "posts"
 * - Source must be "telegram"
 *
 * This is a dedicated function to avoid widening the attack surface
 * by adding a generic trust parameter to createEntries().
 */
export function createQuarantinedEntry(
	entry: MemoryEntryInput,
	createdAt = Date.now(),
): MemoryEntry {
	const db = getDb();

	// Security: Force category to posts and trust to quarantined
	if (entry.category !== "posts") {
		throw new Error("Only posts category is allowed for quarantined entries");
	}

	const insert = db.prepare(
		`INSERT INTO memory_entries
			(id, category, content, source, trust, created_at, promoted_at, promoted_by, posted_at, chat_id)
			VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)`,
	);
	const exists = db.prepare("SELECT 1 FROM memory_entries WHERE id = ?");

	const existing = exists.get(entry.id) as { 1: number } | undefined;
	if (existing) {
		throw new Error(`Memory entry already exists: ${entry.id}`);
	}

	insert.run(
		entry.id,
		"posts",
		entry.content,
		"telegram",
		"quarantined",
		createdAt,
		entry.chatId ?? null,
	);

	logger.debug({ id: entry.id, chatId: entry.chatId }, "quarantined memory entry created");

	return {
		id: entry.id,
		category: "posts",
		content: entry.content,
		_provenance: {
			source: "telegram",
			trust: "quarantined",
			createdAt,
			...(entry.chatId ? { chatId: entry.chatId } : {}),
		},
	};
}
