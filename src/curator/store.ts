import crypto from "node:crypto";
import { redactSecrets } from "../security/output-filter.js";
import { getDb } from "../storage/db.js";
import type {
	CuratorItem,
	CuratorItemInput,
	CuratorItemKind,
	CuratorItemStatus,
	CuratorProducerKind,
	CuratorSeverity,
} from "./types.js";

type CuratorItemRow = {
	id: string;
	short_id: string;
	fingerprint: string;
	kind: string;
	status: string;
	severity: string;
	source: string;
	title: string;
	summary: string;
	rationale: string | null;
	entity_ref: string;
	proposed_action_json: string;
	evidence_json: string;
	producer_kind: string;
	producer_id: string | null;
	created_at: number;
	updated_at: number;
	expires_at: number | null;
	decided_at: number | null;
	decided_by: string | null;
	decision_reason: string | null;
};

const VALID_KINDS: CuratorItemKind[] = [
	"cron_hardening",
	"background_attention",
	"memory_queue",
	"skill_review",
];
const VALID_STATUSES: CuratorItemStatus[] = ["open", "accepted", "rejected", "expired"];
const VALID_SEVERITIES: CuratorSeverity[] = ["info", "low", "medium", "high"];
const VALID_PRODUCERS: CuratorProducerKind[] = ["system", "claude-code", "codex"];

function clampText(text: string, max = 500): string {
	const normalized = redactSecrets(text).replace(/\s+/g, " ").trim();
	return normalized.length > max ? `${normalized.slice(0, max - 1)}…` : normalized;
}

function sanitizeJsonValue(value: unknown): unknown {
	if (typeof value === "string") {
		return clampText(value, 1_000);
	}
	if (typeof value === "number" || typeof value === "boolean" || value === null) {
		return value;
	}
	if (Array.isArray(value)) {
		return value.slice(0, 50).map(sanitizeJsonValue);
	}
	if (typeof value === "object" && value !== null) {
		const out: Record<string, unknown> = {};
		for (const [key, child] of Object.entries(value).slice(0, 50)) {
			out[clampText(key, 120)] = sanitizeJsonValue(child);
		}
		return out;
	}
	return null;
}

function safeJson(value: Record<string, unknown>): string {
	const serializable = JSON.parse(JSON.stringify(value)) as unknown;
	const sanitized = sanitizeJsonValue(serializable);
	return JSON.stringify(
		sanitized && typeof sanitized === "object" && !Array.isArray(sanitized) ? sanitized : {},
	);
}

function parseJsonObject(raw: string): Record<string, unknown> {
	const parsed = JSON.parse(raw) as unknown;
	return parsed && typeof parsed === "object" && !Array.isArray(parsed)
		? (parsed as Record<string, unknown>)
		: {};
}

function rowToItem(row: CuratorItemRow): CuratorItem {
	const kind = VALID_KINDS.includes(row.kind as CuratorItemKind)
		? (row.kind as CuratorItemKind)
		: "cron_hardening";
	const status = VALID_STATUSES.includes(row.status as CuratorItemStatus)
		? (row.status as CuratorItemStatus)
		: "open";
	const severity = VALID_SEVERITIES.includes(row.severity as CuratorSeverity)
		? (row.severity as CuratorSeverity)
		: "low";
	const producerKind = VALID_PRODUCERS.includes(row.producer_kind as CuratorProducerKind)
		? (row.producer_kind as CuratorProducerKind)
		: "system";
	return {
		id: row.id,
		shortId: row.short_id,
		fingerprint: row.fingerprint,
		kind,
		status,
		severity,
		source: row.source,
		title: row.title,
		summary: row.summary,
		rationale: row.rationale,
		entityRef: row.entity_ref,
		proposedAction: parseJsonObject(row.proposed_action_json),
		evidence: parseJsonObject(row.evidence_json),
		producerKind,
		producerId: row.producer_id,
		createdAtMs: row.created_at,
		updatedAtMs: row.updated_at,
		expiresAtMs: row.expires_at,
		decidedAtMs: row.decided_at,
		decidedBy: row.decided_by,
		decisionReason: row.decision_reason,
	};
}

function getByFingerprint(fingerprint: string): CuratorItem | null {
	const db = getDb();
	const row = db.prepare("SELECT * FROM curator_items WHERE fingerprint = ?").get(fingerprint) as
		| CuratorItemRow
		| undefined;
	return row ? rowToItem(row) : null;
}

export function upsertCuratorItem(input: CuratorItemInput, nowMs = Date.now()): CuratorItem {
	const db = getDb();
	const existing = getByFingerprint(input.fingerprint);
	const producerKind = input.producerKind ?? "system";

	if (existing) {
		if (existing.status !== "open") {
			return existing;
		}
		db.prepare(
			`UPDATE curator_items
			 SET severity = ?,
			     source = ?,
			     title = ?,
			     summary = ?,
			     rationale = ?,
			     entity_ref = ?,
			     proposed_action_json = ?,
			     evidence_json = ?,
			     producer_kind = ?,
			     producer_id = ?,
			     expires_at = ?,
			     updated_at = ?
			 WHERE fingerprint = ? AND status = 'open'`,
		).run(
			input.severity,
			input.source,
			clampText(input.title, 160),
			clampText(input.summary, 500),
			input.rationale ? clampText(input.rationale, 800) : null,
			clampText(input.entityRef, 160),
			safeJson(input.proposedAction),
			safeJson(input.evidence),
			producerKind,
			input.producerId ?? null,
			input.expiresAtMs ?? null,
			nowMs,
			input.fingerprint,
		);
		return getByFingerprint(input.fingerprint) ?? existing;
	}

	const id = `curator-${crypto.randomUUID()}`;
	const shortId = crypto.randomBytes(4).toString("hex");
	db.prepare(
		`INSERT INTO curator_items (
			id, short_id, fingerprint, kind, status, severity, source,
			title, summary, rationale, entity_ref, proposed_action_json, evidence_json,
			producer_kind, producer_id, created_at, updated_at, expires_at,
			decided_at, decided_by, decision_reason
		) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`,
	).run(
		id,
		shortId,
		input.fingerprint,
		input.kind,
		input.severity,
		input.source,
		clampText(input.title, 160),
		clampText(input.summary, 500),
		input.rationale ? clampText(input.rationale, 800) : null,
		clampText(input.entityRef, 160),
		safeJson(input.proposedAction),
		safeJson(input.evidence),
		producerKind,
		input.producerId ?? null,
		nowMs,
		nowMs,
		input.expiresAtMs ?? null,
	);

	const created = getByFingerprint(input.fingerprint);
	if (!created) {
		throw new Error("Failed to create curator item");
	}
	return created;
}

export function getCuratorItem(idOrShortId: string): CuratorItem | null {
	const db = getDb();
	const row = db
		.prepare("SELECT * FROM curator_items WHERE id = ? OR short_id = ?")
		.get(idOrShortId, idOrShortId) as CuratorItemRow | undefined;
	return row ? rowToItem(row) : null;
}

export function listCuratorItems(filter?: {
	status?: CuratorItemStatus | "all";
	kind?: CuratorItemKind;
	limit?: number;
}): CuratorItem[] {
	const db = getDb();
	const clauses: string[] = [];
	const params: unknown[] = [];
	if (filter?.status && filter.status !== "all") {
		clauses.push("status = ?");
		params.push(filter.status);
	}
	if (filter?.kind) {
		clauses.push("kind = ?");
		params.push(filter.kind);
	}
	const limit = Math.max(1, Math.min(filter?.limit ?? 50, 200));
	const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
	const rows = db
		.prepare(`SELECT * FROM curator_items ${where} ORDER BY updated_at DESC LIMIT ${limit}`)
		.all(...params) as CuratorItemRow[];
	return rows.map(rowToItem);
}

export function decideCuratorItem(params: {
	id: string;
	status: "accepted" | "rejected";
	actor: string;
	reason?: string;
	nowMs?: number;
}): CuratorItem | null {
	const existing = getCuratorItem(params.id);
	if (!existing) {
		return null;
	}
	if (existing.status !== "open") {
		return existing;
	}
	const nowMs = params.nowMs ?? Date.now();
	const db = getDb();
	db.prepare(
		`UPDATE curator_items
		 SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ?, updated_at = ?
		 WHERE id = ? AND status = 'open'`,
	).run(
		params.status,
		nowMs,
		clampText(params.actor, 128),
		params.reason ? clampText(params.reason, 500) : null,
		nowMs,
		existing.id,
	);
	return getCuratorItem(existing.id);
}
