import crypto from "node:crypto";

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";
import type { MemorySource } from "./types.js";
import { sanitizeEpisodeText } from "./validation.js";

const logger = getChildLogger({ module: "memory-archive" });

const MAX_EPISODES_PER_SCOPE = 400;
const MAX_USER_TEXT_LENGTH = 1_500;
const MAX_ASSISTANT_TEXT_LENGTH = 2_000;
const MAX_SUMMARY_LENGTH = 320;
const MAX_METADATA_LENGTH = 2_000;
const DEFAULT_RECENT_LIMIT = 8;
const MAX_RECENT_LIMIT = 20;
const DEFAULT_SEARCH_WINDOW = 60;

const STOP_WORDS = new Set([
	"a",
	"an",
	"and",
	"are",
	"as",
	"at",
	"be",
	"but",
	"by",
	"for",
	"from",
	"had",
	"has",
	"have",
	"how",
	"i",
	"if",
	"in",
	"is",
	"it",
	"its",
	"me",
	"my",
	"of",
	"on",
	"or",
	"our",
	"that",
	"the",
	"their",
	"them",
	"there",
	"they",
	"this",
	"to",
	"us",
	"was",
	"we",
	"were",
	"what",
	"when",
	"where",
	"which",
	"who",
	"why",
	"with",
	"you",
	"your",
]);

export type MemoryEpisode = {
	id: string;
	source: MemorySource;
	scopeKey: string;
	chatId?: string;
	sessionKey?: string;
	sessionId?: string;
	userText: string;
	assistantText: string;
	summary: string;
	metadata?: Record<string, unknown>;
	createdAt: number;
};

export type MemoryEpisodeInput = {
	source: MemorySource;
	scopeKey: string;
	chatId?: string;
	sessionKey?: string;
	sessionId?: string;
	userText: string;
	assistantText: string;
	summary?: string;
	metadata?: Record<string, unknown>;
	createdAt?: number;
};

export type MemoryEpisodeQuery = {
	source?: MemorySource;
	scopeKey?: string;
	chatId?: string;
	limit?: number;
	order?: "asc" | "desc";
};

type MemoryEpisodeRow = {
	id: string;
	source: string;
	scope_key: string;
	chat_id: string | null;
	session_key: string | null;
	session_id: string | null;
	user_text: string;
	assistant_text: string;
	summary: string;
	metadata: string | null;
	created_at: number;
};

export type MemoryEpisodeMatch = MemoryEpisode & {
	relevance: number;
};

function clampLimit(limit?: number, fallback = DEFAULT_RECENT_LIMIT): number {
	if (!Number.isFinite(limit) || !limit) return fallback;
	return Math.min(Math.max(Math.trunc(limit), 1), MAX_RECENT_LIMIT);
}

function clampSearchWindow(limit?: number): number {
	if (!Number.isFinite(limit) || !limit) return DEFAULT_SEARCH_WINDOW;
	return Math.min(Math.max(Math.trunc(limit), 1), 200);
}

function normalizeWhitespace(value: string): string {
	return value.replace(/\s+/g, " ").trim();
}

function clampText(value: string, maxLength: number): string {
	return sanitizeEpisodeText(normalizeWhitespace(value), maxLength);
}

function parseMetadata(raw: string | null): Record<string, unknown> | undefined {
	if (!raw) return undefined;
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
	} catch (error) {
		logger.warn({ error: String(error) }, "failed to parse episode metadata");
	}
	return undefined;
}

function serializeMetadata(metadata?: Record<string, unknown>): string | null {
	if (!metadata) return null;
	const serialized = JSON.stringify(metadata);
	if (serialized.length <= MAX_METADATA_LENGTH) {
		return serialized;
	}
	return JSON.stringify({ truncated: true });
}

function rowToEpisode(row: MemoryEpisodeRow): MemoryEpisode {
	return {
		id: row.id,
		source: row.source as MemorySource,
		scopeKey: row.scope_key,
		...(row.chat_id ? { chatId: row.chat_id } : {}),
		...(row.session_key ? { sessionKey: row.session_key } : {}),
		...(row.session_id ? { sessionId: row.session_id } : {}),
		userText: row.user_text,
		assistantText: row.assistant_text,
		summary: row.summary,
		...(row.metadata ? { metadata: parseMetadata(row.metadata) } : {}),
		createdAt: row.created_at,
	};
}

export function summarizeEpisode(userText: string, assistantText: string): string {
	const user = clampText(userText, 140);
	const assistant = clampText(assistantText, 140);
	if (!user && !assistant) {
		return "Short interaction recorded without textual detail.";
	}
	if (!assistant) {
		return clampText(`User said ${user}`, MAX_SUMMARY_LENGTH);
	}
	if (!user) {
		return clampText(`Assistant replied ${assistant}`, MAX_SUMMARY_LENGTH);
	}
	return clampText(`User said ${user} | Assistant replied ${assistant}`, MAX_SUMMARY_LENGTH);
}

export function recordEpisode(input: MemoryEpisodeInput): MemoryEpisode {
	const db = getDb();
	const createdAt = input.createdAt ?? Date.now();
	const userText = clampText(input.userText, MAX_USER_TEXT_LENGTH);
	const assistantText = clampText(input.assistantText, MAX_ASSISTANT_TEXT_LENGTH);
	const summary = clampText(
		input.summary ?? summarizeEpisode(userText, assistantText),
		MAX_SUMMARY_LENGTH,
	);
	const episode: MemoryEpisode = {
		id: crypto.randomUUID(),
		source: input.source,
		scopeKey: input.scopeKey,
		...(input.chatId ? { chatId: input.chatId } : {}),
		...(input.sessionKey ? { sessionKey: input.sessionKey } : {}),
		...(input.sessionId ? { sessionId: input.sessionId } : {}),
		userText,
		assistantText,
		summary,
		...(input.metadata ? { metadata: input.metadata } : {}),
		createdAt,
	};

	db.prepare(
		`INSERT INTO memory_episodes
			(id, source, scope_key, chat_id, session_key, session_id, user_text, assistant_text, summary, metadata, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	).run(
		episode.id,
		episode.source,
		episode.scopeKey,
		episode.chatId ?? null,
		episode.sessionKey ?? null,
		episode.sessionId ?? null,
		episode.userText,
		episode.assistantText,
		episode.summary,
		serializeMetadata(episode.metadata),
		episode.createdAt,
	);

	const countRow = db
		.prepare("SELECT COUNT(*) as cnt FROM memory_episodes WHERE scope_key = ?")
		.get(episode.scopeKey) as { cnt: number };
	if (countRow.cnt > MAX_EPISODES_PER_SCOPE) {
		const excess = countRow.cnt - MAX_EPISODES_PER_SCOPE;
		db.prepare(
			`DELETE FROM memory_episodes WHERE id IN (
				SELECT id FROM memory_episodes
				WHERE scope_key = ?
				ORDER BY created_at ASC
				LIMIT ?
			)`,
		).run(episode.scopeKey, excess);
		logger.info({ scopeKey: episode.scopeKey, deleted: excess }, "trimmed old episodic entries");
	}

	return episode;
}

export function getEpisodes(query: MemoryEpisodeQuery = {}): MemoryEpisode[] {
	const db = getDb();
	const where: string[] = [];
	const params: Array<string | number> = [];

	if (query.source) {
		where.push("source = ?");
		params.push(query.source);
	}
	if (query.scopeKey) {
		where.push("scope_key = ?");
		params.push(query.scopeKey);
	}
	if (query.chatId) {
		where.push("chat_id = ?");
		params.push(query.chatId);
	}

	const limit = clampLimit(query.limit, DEFAULT_RECENT_LIMIT);
	const order = query.order === "asc" ? "ASC" : "DESC";
	const sql = `SELECT id, source, scope_key, chat_id, session_key, session_id, user_text, assistant_text, summary, metadata, created_at
		FROM memory_episodes
		${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""}
		ORDER BY created_at ${order}
		LIMIT ?`;
	params.push(limit);

	const rows = db.prepare(sql).all(...params) as MemoryEpisodeRow[];
	return rows.map(rowToEpisode);
}

function tokenize(input?: string): string[] {
	if (!input) return [];
	return normalizeWhitespace(input)
		.toLowerCase()
		.split(/[^a-z0-9]+/g)
		.filter((token) => token.length >= 3 && !STOP_WORDS.has(token));
}

function countTermHits(haystack: string, terms: string[]): number {
	if (terms.length === 0) return 0;
	let hits = 0;
	const lower = haystack.toLowerCase();
	for (const term of terms) {
		if (lower.includes(term)) {
			hits += 1;
		}
	}
	return hits;
}

function computeRelevance(episode: MemoryEpisode, terms: string[], now: number): number {
	const overlap = countTermHits(
		`${episode.summary}\n${episode.userText}\n${episode.assistantText}`,
		terms,
	);
	if (terms.length > 0 && overlap === 0) {
		return 0;
	}
	const ageHours = Math.max(0, (now - episode.createdAt) / (60 * 60 * 1000));
	const recencyBoost = Math.max(0, 2 - ageHours / 24);
	return overlap * 4 + recencyBoost;
}

export function findRelevantEpisodes(options: {
	source: MemorySource;
	scopeKey: string;
	query?: string;
	limit?: number;
	searchWindow?: number;
	now?: number;
}): MemoryEpisodeMatch[] {
	const db = getDb();
	const limit = clampLimit(options.limit, 4);
	const searchWindow = clampSearchWindow(options.searchWindow);
	const now = options.now ?? Date.now();
	const terms = tokenize(options.query);

	const rows = db
		.prepare(
			`SELECT id, source, scope_key, chat_id, session_key, session_id, user_text, assistant_text, summary, metadata, created_at
			 FROM memory_episodes
			 WHERE source = ? AND scope_key = ?
			 ORDER BY created_at DESC
			 LIMIT ?`,
		)
		.all(options.source, options.scopeKey, searchWindow) as MemoryEpisodeRow[];

	return rows
		.map(rowToEpisode)
		.map((episode) => ({ ...episode, relevance: computeRelevance(episode, terms, now) }))
		.filter((episode) => episode.relevance > 0)
		.sort((a, b) => b.relevance - a.relevance || b.createdAt - a.createdAt)
		.slice(0, limit);
}
