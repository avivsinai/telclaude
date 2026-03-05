import { getChildLogger } from "../logging.js";
import { filterOutput } from "../security/output-filter.js";
import {
	createEntries,
	createQuarantinedEntry,
	getEntries,
	type MemoryEntryInput,
	promoteEntryTrust,
} from "./store.js";
import type { MemoryCategory, MemoryEntry, MemorySource, TrustLevel } from "./types.js";

const logger = getChildLogger({ module: "memory-rpc" });

export type MemoryProposeRequest = {
	entries: MemoryEntryInput[];
	userId?: string;
	chatId?: string;
};

export type MemorySnapshotRequest = {
	categories?: MemoryCategory[];
	trust?: TrustLevel[];
	sources?: MemorySource[];
	limit?: number;
	chatId?: string;
};

export type MemorySnapshotResponse = {
	entries: MemoryEntry[];
};

export type MemoryQuarantineRequest = {
	id: string;
	content: string;
	userId?: string;
	chatId?: string;
};

export type MemoryPromoteRequest = {
	id: string;
	userId?: string;
};

export type MemoryRpcResult<T> =
	| { ok: true; value: T }
	| { ok: false; status: number; error: string };

const MAX_UPDATES_PER_REQUEST = 5;
const MAX_STRING_LENGTH = 500;
const MAX_ID_LENGTH = 128;
const MAX_CHAT_ID_LENGTH = 64;
const MAX_QUERY_LIMIT = 500;
const DEFAULT_QUERY_LIMIT = 200;
const HOUR_MS = 60 * 60 * 1000;

const FORBIDDEN_PATTERNS: RegExp[] = [
	/^(system|assistant|developer|user)\s*:/i,
	/\bignore\s+(all\s+)?previous\s+instructions?\b/i,
	/\bdisregard\s+(all\s+)?previous\s+instructions?\b/i,
	/\boverride\s+(the\s+)?(system|previous)\s+instructions?\b/i,
	/\{\{[^}]{1,200}\}\}/,
	/<script/i,
	/javascript:/i,
];

const VALID_CATEGORIES: MemoryCategory[] = ["profile", "interests", "threads", "posts", "meta"];
const VALID_TRUST: TrustLevel[] = ["trusted", "quarantined", "untrusted"];
// Source IDs are validated by pattern (not a fixed list) to support
// arbitrary social service IDs configured in socialServices[].
const VALID_SOURCE_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;

const rateBuckets = new Map<string, { windowStart: number; count: number }>();

function ok<T>(value: T): MemoryRpcResult<T> {
	return { ok: true, value };
}

function fail(status: number, error: string): MemoryRpcResult<never> {
	return { ok: false, status, error };
}

function isValidCategory(value: unknown): value is MemoryCategory {
	return typeof value === "string" && VALID_CATEGORIES.includes(value as MemoryCategory);
}

function isValidTrust(value: unknown): value is TrustLevel {
	return typeof value === "string" && VALID_TRUST.includes(value as TrustLevel);
}

function isValidSource(value: unknown): value is MemorySource {
	return typeof value === "string" && VALID_SOURCE_PATTERN.test(value);
}

function normalizeList<T extends string>(value?: T[] | T): T[] | undefined {
	if (!value) return undefined;
	return Array.isArray(value) ? value : [value];
}

function normalizeLimit(limit?: number): number {
	if (!Number.isFinite(limit) || !limit) return DEFAULT_QUERY_LIMIT;
	return Math.min(Math.max(Math.trunc(limit), 1), MAX_QUERY_LIMIT);
}

function checkForbiddenPatterns(value: string): string | null {
	const trimmed = value.trim();
	for (const pattern of FORBIDDEN_PATTERNS) {
		if (pattern.test(trimmed)) {
			return `Forbidden pattern detected (${pattern.source}).`;
		}
	}
	// Block XML-like injection attempts (defense-in-depth against tag breakout)
	if (/<\/?[a-z][^>]*>/i.test(value)) {
		return "HTML/XML tags not allowed in memory entries.";
	}
	return null;
}

function validateEntry(entry: MemoryEntryInput): string | null {
	if (!entry || typeof entry !== "object") {
		return "Invalid memory entry.";
	}
	if (typeof entry.id !== "string" || entry.id.trim().length === 0) {
		return "Entry id is required.";
	}
	const trimmedId = entry.id.trim();
	if (trimmedId.length > MAX_ID_LENGTH) {
		return "Entry id too long.";
	}
	if (!isValidCategory(entry.category)) {
		return "Invalid memory category.";
	}
	if (typeof entry.content !== "string" || entry.content.trim().length === 0) {
		return "Entry content is required.";
	}
	if (entry.content.length > MAX_STRING_LENGTH) {
		return "Entry content too long.";
	}
	const forbidden = checkForbiddenPatterns(entry.content);
	if (forbidden) {
		return forbidden;
	}
	// M4: Reject content that looks like secrets/tokens
	const secretResult = filterOutput(entry.content);
	if (secretResult.blocked) {
		const names = secretResult.matches.map((m) => m.pattern).join(", ");
		return `Content rejected: potential secret detected (${names}).`;
	}
	return null;
}

let lastRateBucketPrune = 0;

function pruneRateBuckets(): void {
	const now = Date.now();
	if (now - lastRateBucketPrune < HOUR_MS) return;
	lastRateBucketPrune = now;
	const windowStart = Math.floor(now / HOUR_MS) * HOUR_MS;
	for (const [key, bucket] of rateBuckets) {
		if (bucket.windowStart < windowStart) {
			rateBuckets.delete(key);
		}
	}
}

function checkRateLimit(
	source: MemorySource,
	_userKey: string,
	count: number,
): MemoryRpcResult<void> {
	pruneRateBuckets();
	const limit = source === "telegram" ? 100 : 10;
	const now = Date.now();
	const windowStart = Math.floor(now / HOUR_MS) * HOUR_MS;
	// M3: Use scope-constant key to prevent userId spoofing
	const key = `${source}:agent`;
	const bucket = rateBuckets.get(key);

	if (!bucket || bucket.windowStart !== windowStart) {
		rateBuckets.set(key, { windowStart, count });
		return ok(undefined);
	}

	if (bucket.count + count > limit) {
		const resetMs = HOUR_MS - (now - windowStart);
		return fail(
			429,
			`Rate limit exceeded (${limit}/hour). Try again in ${Math.ceil(resetMs / 60000)} minutes.`,
		);
	}

	bucket.count += count;
	return ok(undefined);
}

function validateChatId(chatId: unknown): string | undefined {
	if (chatId === undefined || chatId === null) return undefined;
	if (typeof chatId !== "string") return undefined;
	const trimmed = chatId.trim();
	if (!trimmed || trimmed.length > MAX_CHAT_ID_LENGTH) return undefined;
	return trimmed;
}

export function handleMemoryPropose(
	request: MemoryProposeRequest,
	context: { source: MemorySource; userId?: string },
): MemoryRpcResult<{ accepted: number }> {
	if (!request || typeof request !== "object") {
		return fail(400, "Invalid request body.");
	}
	if (!Array.isArray(request.entries) || request.entries.length === 0) {
		return fail(400, "Entries array is required.");
	}
	if (request.entries.length > MAX_UPDATES_PER_REQUEST) {
		return fail(400, `Too many entries (max ${MAX_UPDATES_PER_REQUEST}).`);
	}

	const chatId = validateChatId(request.chatId);

	for (const entry of request.entries) {
		const error = validateEntry(entry);
		if (error) {
			return fail(400, error);
		}
	}

	const actor = context.userId?.trim() || "agent";
	const rateResult = checkRateLimit(context.source, actor, request.entries.length);
	if (!rateResult.ok) {
		return rateResult;
	}

	try {
		// H3: Stamp chatId on each entry for multi-user scoping
		const entriesWithChat = chatId
			? request.entries.map((e) => ({ ...e, chatId }))
			: request.entries;
		const created = createEntries(entriesWithChat, context.source);
		return ok({ accepted: created.length });
	} catch (err) {
		logger.warn({ error: String(err) }, "memory propose failed");
		return fail(400, "Unable to store memory entries.");
	}
}

function validateSnapshotFields(raw: {
	categories?: string[];
	trust?: string[];
	sources?: string[];
	limit?: number;
	chatId?: unknown;
}): MemoryRpcResult<MemorySnapshotRequest> {
	if (raw.categories && !raw.categories.every(isValidCategory)) {
		return fail(400, "Invalid categories filter.");
	}
	if (raw.trust && !raw.trust.every(isValidTrust)) {
		return fail(400, "Invalid trust filter.");
	}
	if (raw.sources && !raw.sources.every(isValidSource)) {
		return fail(400, "Invalid sources filter.");
	}

	let limit: number | undefined;
	if (raw.limit !== undefined) {
		if (!Number.isFinite(raw.limit)) {
			return fail(400, "Invalid limit.");
		}
		limit = normalizeLimit(raw.limit);
	}

	const chatId = validateChatId(raw.chatId);

	return ok({
		categories: raw.categories as MemoryCategory[] | undefined,
		trust: raw.trust as TrustLevel[] | undefined,
		sources: raw.sources as MemorySource[] | undefined,
		limit,
		chatId,
	});
}

export function parseSnapshotBody(input: unknown): MemoryRpcResult<MemorySnapshotRequest> {
	if (input === undefined || input === null) {
		return ok({});
	}
	if (typeof input !== "object") {
		return fail(400, "Invalid request body.");
	}

	const raw = input as {
		categories?: unknown;
		trust?: unknown;
		sources?: unknown;
		limit?: unknown;
		chatId?: unknown;
	};

	return validateSnapshotFields({
		categories: normalizeList(raw.categories as MemoryCategory[] | MemoryCategory | undefined),
		trust: normalizeList(raw.trust as TrustLevel[] | TrustLevel | undefined),
		sources: normalizeList(raw.sources as MemorySource[] | MemorySource | undefined),
		limit: raw.limit !== undefined ? Number(raw.limit) : undefined,
		chatId: raw.chatId,
	});
}

export function parseSnapshotQuery(query: URLSearchParams): MemoryRpcResult<MemorySnapshotRequest> {
	const parseList = (value: string | null): string[] | undefined => {
		if (!value) return undefined;
		return value
			.split(",")
			.map((part) => part.trim())
			.filter(Boolean);
	};

	const rawLimit = query.get("limit");

	return validateSnapshotFields({
		categories: parseList(query.get("categories")),
		trust: parseList(query.get("trust")),
		sources: parseList(query.get("sources")),
		limit: rawLimit ? Number(rawLimit) : undefined,
		chatId: query.get("chatId"),
	});
}

export function handleMemorySnapshot(
	request: MemorySnapshotRequest,
): MemoryRpcResult<MemorySnapshotResponse> {
	const chatId = validateChatId(request.chatId);
	const query: MemorySnapshotRequest = {
		categories: request.categories?.length ? request.categories : undefined,
		trust: request.trust?.length ? request.trust : undefined,
		sources: request.sources?.length ? request.sources : undefined,
		limit: normalizeLimit(request.limit),
		chatId,
	};

	const entries = getEntries({
		categories: query.categories,
		trust: query.trust,
		sources: query.sources,
		limit: query.limit,
		chatId: query.chatId,
		order: "desc",
	});

	return ok({ entries });
}

/**
 * Create a quarantined memory entry (for consent-based idea bridge).
 *
 * Security: TELEGRAM-ONLY. This endpoint must be gated by scope in the relay.
 * Only creates entries with:
 * - category = "posts"
 * - trust = "quarantined"
 * - source = "telegram"
 */
export function handleMemoryQuarantine(
	request: MemoryQuarantineRequest,
	context: { source: MemorySource; userId?: string },
): MemoryRpcResult<{ entry: MemoryEntry }> {
	// Security: Reject if source is not telegram (enforced here as defense-in-depth)
	if (context.source !== "telegram") {
		logger.warn({ source: context.source }, "rejected quarantine: telegram-only");
		return fail(403, "Quarantine is only available for Telegram context");
	}

	if (!request || typeof request !== "object") {
		return fail(400, "Invalid request body.");
	}

	// Delegate field validation to validateEntry (id, content, category, patterns, secrets)
	const validationError = validateEntry({
		id: request.id,
		category: "posts",
		content: request.content,
	});
	if (validationError) {
		return fail(400, validationError);
	}

	const actor = context.userId?.trim() || "agent";
	const rateResult = checkRateLimit("telegram", actor, 1);
	if (!rateResult.ok) {
		return rateResult;
	}

	const chatId = validateChatId(request.chatId);
	if (!chatId) {
		return fail(400, "Chat ID is required for quarantined entries.");
	}

	try {
		const entry = createQuarantinedEntry({
			id: request.id.trim(),
			category: "posts",
			content: request.content,
			chatId,
		});
		return ok({ entry });
	} catch (err) {
		logger.warn({ error: String(err) }, "memory quarantine failed");
		return fail(400, "Unable to create quarantined entry.");
	}
}

/**
 * Promote a memory entry to trusted for social posting.
 *
 * Security: TELEGRAM-ONLY caller. This endpoint must be gated by scope in the relay.
 * The entry itself can be from telegram (quarantined) or social (untrusted) source —
 * promoteEntryTrust() enforces per-source trust constraints.
 */
export function handleMemoryPromote(
	request: MemoryPromoteRequest,
	context: { source: MemorySource; userId?: string },
): MemoryRpcResult<{ entry: MemoryEntry }> {
	// Security: Reject if source is not telegram (enforced here as defense-in-depth)
	if (context.source !== "telegram") {
		logger.warn({ source: context.source }, "rejected promote: telegram-only");
		return fail(403, "Promote is only available for Telegram context");
	}

	if (!request || typeof request !== "object") {
		return fail(400, "Invalid request body.");
	}
	if (typeof request.id !== "string" || request.id.trim().length === 0) {
		return fail(400, "Entry id is required.");
	}
	const trimmedId = request.id.trim();
	if (trimmedId.length > MAX_ID_LENGTH) {
		return fail(400, "Entry id too long.");
	}

	const actor = context.userId?.trim() || "user";
	const result = promoteEntryTrust(trimmedId, actor);

	if (!result.ok) {
		logger.warn({ id: request.id, reason: result.reason }, "memory promote failed");
		return fail(400, result.reason);
	}

	return ok({ entry: result.entry });
}
