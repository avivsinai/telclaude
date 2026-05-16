import { getCronJob } from "../cron/store.js";
import { getDb } from "../storage/db.js";
import { validateAllowedCidrs } from "./cidr.js";
import { assertWebhookCronTargetAllowed } from "./policy.js";

const HOUR_MS = 60 * 60 * 1000;
const WEBHOOK_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,62})$/;

export type WebhookDefinition = {
	slug: string;
	enabled: boolean;
	targetCronJobId: string;
	vaultSecretId: string;
	allowedCidrs: string[];
	rateLimitPerHour: number;
	createdAtMs: number;
	updatedAtMs: number;
	lastHitAtMs: number | null;
	hitCount: number;
};

export type WebhookHit = {
	id: number;
	slug: string;
	sourceIp: string | null;
	signatureValid: boolean;
	timestampDeltaSeconds: number | null;
	actionTaken: string;
	targetCronJobId: string | null;
	backgroundJobId: string | null;
	failureReason: string | null;
	bodySha256: string | null;
	createdAtMs: number;
};

type WebhookRow = {
	slug: string;
	enabled: number;
	target_cron_job_id: string;
	vault_secret_id: string;
	allowed_cidrs_json: string | null;
	rate_limit_per_hour: number;
	created_at: number;
	updated_at: number;
	last_hit_at: number | null;
	hit_count: number;
};

type WebhookHitRow = {
	id: number;
	slug: string;
	source_ip: string | null;
	signature_valid: number;
	timestamp_delta_seconds: number | null;
	action_taken: string;
	target_cron_job_id: string | null;
	background_job_id: string | null;
	failure_reason: string | null;
	body_sha256: string | null;
	created_at: number;
};

function parseAllowedCidrsJson(slug: string, raw: string | null): string[] {
	if (!raw) return [];
	try {
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== "string")) {
			throw new Error("expected string array");
		}
		return validateAllowedCidrs(parsed);
	} catch (err) {
		throw new Error(
			`webhook '${slug}' has invalid allowed CIDR JSON: ${
				err instanceof Error ? err.message : String(err)
			}`,
		);
	}
}

function rowToWebhook(row: WebhookRow): WebhookDefinition {
	return {
		slug: row.slug,
		enabled: row.enabled === 1,
		targetCronJobId: row.target_cron_job_id,
		vaultSecretId: row.vault_secret_id,
		allowedCidrs: parseAllowedCidrsJson(row.slug, row.allowed_cidrs_json),
		rateLimitPerHour: row.rate_limit_per_hour,
		createdAtMs: row.created_at,
		updatedAtMs: row.updated_at,
		lastHitAtMs: row.last_hit_at,
		hitCount: row.hit_count,
	};
}

function rowToWebhookHit(row: WebhookHitRow): WebhookHit {
	return {
		id: row.id,
		slug: row.slug,
		sourceIp: row.source_ip,
		signatureValid: row.signature_valid === 1,
		timestampDeltaSeconds: row.timestamp_delta_seconds,
		actionTaken: row.action_taken,
		targetCronJobId: row.target_cron_job_id,
		backgroundJobId: row.background_job_id,
		failureReason: row.failure_reason,
		bodySha256: row.body_sha256,
		createdAtMs: row.created_at,
	};
}

export function validateWebhookSlug(slug: string): string {
	const normalized = slug.trim();
	if (!WEBHOOK_SLUG_RE.test(normalized)) {
		throw new Error("webhook slug must be 1-63 chars of lowercase letters, digits, or hyphens");
	}
	return normalized;
}

export function webhookSecretId(slug: string): string {
	return `webhook:${validateWebhookSlug(slug)}:hmac`;
}

function ensureWebhookTargetAllowed(targetCronJobId: string): void {
	const job = getCronJob(targetCronJobId);
	if (!job) {
		throw new Error(`unknown cron job id '${targetCronJobId}'`);
	}
	assertWebhookCronTargetAllowed(job);
}

export function createWebhook(
	input: {
		slug: string;
		targetCronJobId: string;
		vaultSecretId: string;
		allowedCidrs?: string[];
		rateLimitPerHour: number;
		enabled?: boolean;
	},
	nowMs = Date.now(),
): WebhookDefinition {
	const slug = validateWebhookSlug(input.slug);
	const targetCronJobId = input.targetCronJobId.trim();
	if (!targetCronJobId) {
		throw new Error("target cron job id is required");
	}
	ensureWebhookTargetAllowed(targetCronJobId);
	const vaultSecretId = input.vaultSecretId.trim();
	if (!vaultSecretId) {
		throw new Error("vault secret id is required");
	}
	if (!Number.isInteger(input.rateLimitPerHour) || input.rateLimitPerHour <= 0) {
		throw new Error("rate limit per hour must be a positive integer");
	}
	const allowedCidrs = validateAllowedCidrs(input.allowedCidrs ?? []);
	const db = getDb();
	db.prepare(
		`INSERT INTO webhooks (
			slug, enabled, target_cron_job_id, vault_secret_id, allowed_cidrs_json,
			rate_limit_per_hour, created_at, updated_at, last_hit_at, hit_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)`,
	).run(
		slug,
		input.enabled === true ? 1 : 0,
		targetCronJobId,
		vaultSecretId,
		allowedCidrs.length === 0 ? null : JSON.stringify(allowedCidrs),
		input.rateLimitPerHour,
		nowMs,
		nowMs,
	);
	const created = getWebhook(slug);
	if (!created) {
		throw new Error("failed to create webhook");
	}
	return created;
}

export function getWebhook(slug: string): WebhookDefinition | null {
	const db = getDb();
	const normalized = validateWebhookSlug(slug);
	const row = db.prepare("SELECT * FROM webhooks WHERE slug = ?").get(normalized) as
		| WebhookRow
		| undefined;
	return row ? rowToWebhook(row) : null;
}

export function listWebhooks(): WebhookDefinition[] {
	const db = getDb();
	const rows = db.prepare("SELECT * FROM webhooks ORDER BY created_at DESC").all() as WebhookRow[];
	return rows.map(rowToWebhook);
}

export function setWebhookEnabled(
	slug: string,
	enabled: boolean,
	nowMs = Date.now(),
): WebhookDefinition | null {
	const normalized = validateWebhookSlug(slug);
	const db = getDb();
	const result = db
		.prepare("UPDATE webhooks SET enabled = ?, updated_at = ? WHERE slug = ?")
		.run(enabled ? 1 : 0, nowMs, normalized);
	if (result.changes === 0) return null;
	return getWebhook(normalized);
}

export function touchWebhookUpdated(slug: string, nowMs = Date.now()): boolean {
	const normalized = validateWebhookSlug(slug);
	const db = getDb();
	const result = db
		.prepare("UPDATE webhooks SET updated_at = ? WHERE slug = ?")
		.run(nowMs, normalized);
	return result.changes > 0;
}

export function removeWebhook(slug: string): WebhookDefinition | null {
	const normalized = validateWebhookSlug(slug);
	const existing = getWebhook(normalized);
	if (!existing) return null;
	const db = getDb();
	db.prepare("DELETE FROM webhooks WHERE slug = ?").run(normalized);
	return existing;
}

export function recordWebhookHit(
	input: {
		slug: string;
		sourceIp?: string | null;
		signatureValid: boolean;
		timestampDeltaSeconds?: number | null;
		actionTaken: string;
		targetCronJobId?: string | null;
		backgroundJobId?: string | null;
		failureReason?: string | null;
		bodySha256?: string | null;
	},
	nowMs = Date.now(),
): void {
	const slug = input.slug.trim().slice(0, 128) || "<missing>";
	const db = getDb();
	db.transaction(() => {
		db.prepare(
			`INSERT INTO webhook_hits (
				slug, source_ip, signature_valid, timestamp_delta_seconds, action_taken,
				target_cron_job_id, background_job_id, failure_reason, body_sha256, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		).run(
			slug,
			input.sourceIp ?? null,
			input.signatureValid ? 1 : 0,
			input.timestampDeltaSeconds ?? null,
			input.actionTaken,
			input.targetCronJobId ?? null,
			input.backgroundJobId ?? null,
			input.failureReason ?? null,
			input.bodySha256 ?? null,
			nowMs,
		);
		db.prepare(
			`UPDATE webhooks
			 SET last_hit_at = ?, hit_count = hit_count + 1
			 WHERE slug = ?`,
		).run(nowMs, slug);
	})();
}

export function listWebhookHits(slug: string, limit = 50): WebhookHit[] {
	const normalized = validateWebhookSlug(slug);
	const rows = getDb()
		.prepare(
			`SELECT * FROM webhook_hits
			 WHERE slug = ?
			 ORDER BY created_at DESC, id DESC
			 LIMIT ?`,
		)
		.all(normalized, Math.max(1, Math.min(limit, 500))) as WebhookHitRow[];
	return rows.map(rowToWebhookHit);
}

export type WebhookRateLimitResult = {
	allowed: boolean;
	remaining: number;
	resetMs: number;
	limitType?: "global" | "webhook" | "ingress";
};

function hourWindowStart(nowMs: number): number {
	return Math.floor(nowMs / HOUR_MS) * HOUR_MS;
}

export function consumeWebhookRateLimit(params: {
	slug: string;
	perWebhookLimit: number;
	globalLimit: number;
	nowMs?: number;
}): WebhookRateLimitResult {
	const slug = validateWebhookSlug(params.slug);
	const perWebhookLimit = Math.max(1, params.perWebhookLimit);
	const globalLimit = Math.max(1, params.globalLimit);
	const nowMs = params.nowMs ?? Date.now();
	const windowStart = hourWindowStart(nowMs);
	const resetMs = HOUR_MS - (nowMs - windowStart);
	const db = getDb();

	return db.transaction(() => {
		const getPoints = (type: string, key: string): number => {
			const row = db
				.prepare(
					"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
				)
				.get(type, key, windowStart) as { points: number } | undefined;
			return row?.points ?? 0;
		};
		const globalPoints = getPoints("webhook_global_hour", "global");
		if (globalPoints >= globalLimit) {
			return { allowed: false, remaining: 0, resetMs, limitType: "global" as const };
		}
		const webhookPoints = getPoints("webhook_hour", slug);
		if (webhookPoints >= perWebhookLimit) {
			return { allowed: false, remaining: 0, resetMs, limitType: "webhook" as const };
		}

		for (const [type, key] of [
			["webhook_global_hour", "global"],
			["webhook_hour", slug],
		] as const) {
			db.prepare(
				`INSERT INTO rate_limits (limiter_type, key, window_start, points)
				 VALUES (?, ?, ?, 1)
				 ON CONFLICT(limiter_type, key, window_start)
				 DO UPDATE SET points = points + 1`,
			).run(type, key, windowStart);
		}

		const remainingGlobal = globalLimit - (globalPoints + 1);
		const remainingWebhook = perWebhookLimit - (webhookPoints + 1);
		return {
			allowed: true,
			remaining: Math.max(0, Math.min(remainingGlobal, remainingWebhook)),
			resetMs,
		};
	})();
}

export function consumeWebhookIngressRateLimit(params: {
	key: string;
	perKeyLimit: number;
	globalLimit: number;
	nowMs?: number;
}): WebhookRateLimitResult {
	const key = params.key.trim().slice(0, 160) || "unknown";
	const perKeyLimit = Math.max(1, params.perKeyLimit);
	const globalLimit = Math.max(1, params.globalLimit);
	const nowMs = params.nowMs ?? Date.now();
	const windowStart = hourWindowStart(nowMs);
	const resetMs = HOUR_MS - (nowMs - windowStart);
	const db = getDb();

	return db.transaction(() => {
		const getPoints = (type: string, key: string): number => {
			const row = db
				.prepare(
					"SELECT points FROM rate_limits WHERE limiter_type = ? AND key = ? AND window_start = ?",
				)
				.get(type, key, windowStart) as { points: number } | undefined;
			return row?.points ?? 0;
		};
		const globalPoints = getPoints("webhook_ingress_global_hour", "global");
		if (globalPoints >= globalLimit) {
			return { allowed: false, remaining: 0, resetMs, limitType: "global" as const };
		}
		const keyPoints = getPoints("webhook_ingress_hour", key);
		if (keyPoints >= perKeyLimit) {
			return { allowed: false, remaining: 0, resetMs, limitType: "ingress" as const };
		}

		for (const [type, rateKey] of [
			["webhook_ingress_global_hour", "global"],
			["webhook_ingress_hour", key],
		] as const) {
			db.prepare(
				`INSERT INTO rate_limits (limiter_type, key, window_start, points)
				 VALUES (?, ?, ?, 1)
				 ON CONFLICT(limiter_type, key, window_start)
				 DO UPDATE SET points = points + 1`,
			).run(type, rateKey, windowStart);
		}

		const remainingGlobal = globalLimit - (globalPoints + 1);
		const remainingKey = perKeyLimit - (keyPoints + 1);
		return {
			allowed: true,
			remaining: Math.max(0, Math.min(remainingGlobal, remainingKey)),
			resetMs,
		};
	})();
}

export type WebhookDeliveryReservation = {
	fresh: boolean;
	backgroundJobId: string | null;
};

export function reserveWebhookDelivery(
	input: {
		slug: string;
		signatureDigest: string;
		bodySha256: string;
	},
	nowMs = Date.now(),
): WebhookDeliveryReservation {
	const slug = validateWebhookSlug(input.slug);
	if (!/^[a-f0-9]{64}$/.test(input.signatureDigest)) {
		throw new Error("signature digest must be a 64-character hex string");
	}
	if (!/^[a-f0-9]{64}$/.test(input.bodySha256)) {
		throw new Error("body SHA-256 must be a 64-character hex string");
	}
	const db = getDb();
	const result = db
		.prepare(
			`INSERT OR IGNORE INTO webhook_deliveries (
				slug, signature_digest, body_sha256, background_job_id, created_at
			) VALUES (?, ?, ?, NULL, ?)`,
		)
		.run(slug, input.signatureDigest, input.bodySha256, nowMs);
	if (result.changes > 0) {
		return { fresh: true, backgroundJobId: null };
	}
	const row = db
		.prepare(
			`SELECT background_job_id FROM webhook_deliveries
			 WHERE slug = ? AND signature_digest = ?`,
		)
		.get(slug, input.signatureDigest) as { background_job_id: string | null } | undefined;
	return { fresh: false, backgroundJobId: row?.background_job_id ?? null };
}

export function completeWebhookDelivery(params: {
	slug: string;
	signatureDigest: string;
	backgroundJobId: string;
}): void {
	const slug = validateWebhookSlug(params.slug);
	getDb()
		.prepare(
			`UPDATE webhook_deliveries
			 SET background_job_id = ?
			 WHERE slug = ? AND signature_digest = ?`,
		)
		.run(params.backgroundJobId, slug, params.signatureDigest);
}

export function releaseWebhookDelivery(params: { slug: string; signatureDigest: string }): void {
	const slug = validateWebhookSlug(params.slug);
	getDb()
		.prepare("DELETE FROM webhook_deliveries WHERE slug = ? AND signature_digest = ?")
		.run(slug, params.signatureDigest);
}
