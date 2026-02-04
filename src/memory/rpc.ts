import { getChildLogger } from "../logging.js";
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
};

export type MemorySnapshotRequest = {
	categories?: MemoryCategory[];
	trust?: TrustLevel[];
	sources?: MemorySource[];
	limit?: number;
};

export type MemorySnapshotResponse = {
	entries: MemoryEntry[];
};

export type MemoryQuarantineRequest = {
	id: string;
	content: string;
	userId?: string;
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
const VALID_SOURCES: MemorySource[] = ["telegram", "moltbook"];

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
	return typeof value === "string" && VALID_SOURCES.includes(value as MemorySource);
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
	for (const pattern of FORBIDDEN_PATTERNS) {
		if (pattern.test(value)) {
			return `Forbidden pattern detected (${pattern.source}).`;
		}
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
	return null;
}

function checkRateLimit(
	source: MemorySource,
	userKey: string,
	count: number,
): MemoryRpcResult<void> {
	const limit = source === "telegram" ? 100 : 10;
	const now = Date.now();
	const windowStart = Math.floor(now / HOUR_MS) * HOUR_MS;
	const key = `${source}:${userKey}`;
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
		const created = createEntries(request.entries, context.source);
		return ok({ accepted: created.length });
	} catch (err) {
		logger.warn({ error: String(err) }, "memory propose failed");
		return fail(400, "Unable to store memory entries.");
	}
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
	};

	const categories = normalizeList(raw.categories as MemoryCategory[] | MemoryCategory | undefined);
	if (categories && !categories.every(isValidCategory)) {
		return fail(400, "Invalid categories filter.");
	}
	const trust = normalizeList(raw.trust as TrustLevel[] | TrustLevel | undefined);
	if (trust && !trust.every(isValidTrust)) {
		return fail(400, "Invalid trust filter.");
	}
	const sources = normalizeList(raw.sources as MemorySource[] | MemorySource | undefined);
	if (sources && !sources.every(isValidSource)) {
		return fail(400, "Invalid sources filter.");
	}

	let limit: number | undefined;
	if (raw.limit !== undefined) {
		const parsed = Number(raw.limit);
		if (!Number.isFinite(parsed)) {
			return fail(400, "Invalid limit.");
		}
		limit = normalizeLimit(parsed);
	}

	return ok({ categories, trust, sources, limit });
}

export function parseSnapshotQuery(query: URLSearchParams): MemoryRpcResult<MemorySnapshotRequest> {
	const parseList = (value: string | null): string[] | undefined => {
		if (!value) return undefined;
		return value
			.split(",")
			.map((part) => part.trim())
			.filter(Boolean);
	};

	const categories = parseList(query.get("categories"));
	if (categories && !categories.every(isValidCategory)) {
		return fail(400, "Invalid categories filter.");
	}
	const trust = parseList(query.get("trust"));
	if (trust && !trust.every(isValidTrust)) {
		return fail(400, "Invalid trust filter.");
	}
	const sources = parseList(query.get("sources"));
	if (sources && !sources.every(isValidSource)) {
		return fail(400, "Invalid sources filter.");
	}

	let limit: number | undefined;
	const rawLimit = query.get("limit");
	if (rawLimit) {
		const parsed = Number(rawLimit);
		if (!Number.isFinite(parsed)) {
			return fail(400, "Invalid limit.");
		}
		limit = normalizeLimit(parsed);
	}

	return ok({
		categories: categories as MemoryCategory[] | undefined,
		trust: trust as TrustLevel[] | undefined,
		sources: sources as MemorySource[] | undefined,
		limit,
	});
}

export function handleMemorySnapshot(
	request: MemorySnapshotRequest,
): MemoryRpcResult<MemorySnapshotResponse> {
	const query: MemorySnapshotRequest = {
		categories: request.categories?.length ? request.categories : undefined,
		trust: request.trust?.length ? request.trust : undefined,
		sources: request.sources?.length ? request.sources : undefined,
		limit: normalizeLimit(request.limit),
	};

	const entries = getEntries({
		categories: query.categories,
		trust: query.trust,
		sources: query.sources,
		limit: query.limit,
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
	if (typeof request.id !== "string" || request.id.trim().length === 0) {
		return fail(400, "Entry id is required.");
	}
	const trimmedId = request.id.trim();
	if (trimmedId.length > MAX_ID_LENGTH) {
		return fail(400, "Entry id too long.");
	}
	if (typeof request.content !== "string" || request.content.trim().length === 0) {
		return fail(400, "Entry content is required.");
	}
	if (request.content.length > MAX_STRING_LENGTH) {
		return fail(400, "Entry content too long.");
	}
	const forbidden = checkForbiddenPatterns(request.content);
	if (forbidden) {
		return fail(400, forbidden);
	}

	const actor = context.userId?.trim() || "agent";
	const rateResult = checkRateLimit("telegram", actor, 1);
	if (!rateResult.ok) {
		return rateResult;
	}

	try {
		const entry = createQuarantinedEntry({
			id: trimmedId,
			category: "posts",
			content: request.content,
		});
		return ok({ entry });
	} catch (err) {
		logger.warn({ error: String(err) }, "memory quarantine failed");
		return fail(400, "Unable to create quarantined entry.");
	}
}

/**
 * Promote a quarantined memory entry to trusted.
 *
 * Security: TELEGRAM-ONLY. This endpoint must be gated by scope in the relay.
 * Only promotes entries that are:
 * - source = "telegram"
 * - category = "posts"
 * - trust = "quarantined"
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
