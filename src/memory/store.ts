import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { MemoryCategory, MemoryEntry, MemorySource, TrustLevel } from "./types.js";

const logger = getChildLogger({ module: "memory-store" });

export type MemoryEntryInput = {
	id: string;
	category: MemoryCategory;
	content: string;
};

export type MemoryQuery = {
	categories?: MemoryCategory[];
	trust?: TrustLevel[];
	sources?: MemorySource[];
	limit?: number;
	order?: "asc" | "desc";
};

const DEFAULT_QUERY_LIMIT = 200;
const MAX_QUERY_LIMIT = 500;

function trustForSource(source: MemorySource): TrustLevel {
	return source === "telegram" ? "trusted" : "untrusted";
}

function rowToEntry(row: {
	id: string;
	category: string;
	content: string;
	source: string;
	trust: string;
	created_at: number;
	promoted_at: number | null;
	promoted_by: string | null;
}): MemoryEntry {
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
			(id, category, content, source, trust, created_at, promoted_at, promoted_by)
			VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
	);
	const exists = db.prepare("SELECT 1 FROM memory_entries WHERE id = ?");

	const created: MemoryEntry[] = [];
	const txn = db.transaction(() => {
		for (const entry of entries) {
			const existing = exists.get(entry.id) as { 1: number } | undefined;
			if (existing) {
				throw new Error(`Memory entry already exists: ${entry.id}`);
			}
			insert.run(entry.id, entry.category, entry.content, source, trust, createdAt);
			created.push({
				id: entry.id,
				category: entry.category,
				content: entry.content,
				_provenance: {
					source,
					trust,
					createdAt,
				},
			});
		}
	});

	try {
		txn();
		logger.debug({ count: created.length, source }, "memory entries created");
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

	const order = query.order === "asc" ? "ASC" : "DESC";
	const limit = Math.min(Math.max(query.limit ?? DEFAULT_QUERY_LIMIT, 1), MAX_QUERY_LIMIT);

	const sql = `SELECT id, category, content, source, trust, created_at, promoted_at, promoted_by
		FROM memory_entries
		${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""}
		ORDER BY created_at ${order}
		LIMIT ?`;
	params.push(limit);

	const rows = db.prepare(sql).all(...params) as Array<{
		id: string;
		category: string;
		content: string;
		source: string;
		trust: string;
		created_at: number;
		promoted_at: number | null;
		promoted_by: string | null;
	}>;

	return rows.map(rowToEntry);
}

export function promoteEntryTrust(id: string, promotedBy: string): boolean {
	const db = getDb();
	const existing = db.prepare("SELECT trust FROM memory_entries WHERE id = ?").get(id) as
		| { trust: string }
		| undefined;
	if (!existing || existing.trust !== "untrusted") {
		return false;
	}

	const result = db
		.prepare(
			`UPDATE memory_entries
			 SET trust = ?, promoted_at = ?, promoted_by = ?
			 WHERE id = ?`,
		)
		.run("trusted", Date.now(), promotedBy, id);

	return result.changes > 0;
}

export function deleteEntry(id: string): boolean {
	const db = getDb();
	const result = db.prepare("DELETE FROM memory_entries WHERE id = ?").run(id);
	return result.changes > 0;
}
