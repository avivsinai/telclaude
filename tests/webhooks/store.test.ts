import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("webhook store", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-webhook-store-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("requires an existing enabled non-social cron target", async () => {
		const { addCronJob } = await import("../../src/cron/store.js");
		const { createWebhook } = await import("../../src/webhooks/store.js");

		const privateJob = addCronJob({
			id: "private-ok",
			name: "private",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "private-heartbeat" },
		});
		const webhook = createWebhook({
			slug: "build",
			targetCronJobId: privateJob.id,
			vaultSecretId: "webhook:build:hmac",
			rateLimitPerHour: 10,
		});
		expect(webhook.enabled).toBe(false);
		expect(webhook.targetCronJobId).toBe("private-ok");

		const disabledJob = addCronJob({
			id: "disabled",
			name: "disabled",
			enabled: false,
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "private-heartbeat" },
		});
		expect(() =>
			createWebhook({
				slug: "disabled",
				targetCronJobId: disabledJob.id,
				vaultSecretId: "webhook:disabled:hmac",
				rateLimitPerHour: 10,
			}),
		).toThrow(/disabled/);

		const socialJob = addCronJob({
			id: "social",
			name: "social",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "social-heartbeat" },
		});
		expect(() =>
			createWebhook({
				slug: "social",
				targetCronJobId: socialJob.id,
				vaultSecretId: "webhook:social:hmac",
				rateLimitPerHour: 10,
			}),
		).toThrow(/not an allowed webhook target/);
	});

	it("consumes per-webhook and global hourly limits atomically", async () => {
		const { addCronJob } = await import("../../src/cron/store.js");
		const { consumeWebhookRateLimit, createWebhook } = await import("../../src/webhooks/store.js");

		addCronJob({
			id: "private-ok",
			name: "private",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "private-heartbeat" },
		});
		createWebhook({
			slug: "rate",
			targetCronJobId: "private-ok",
			vaultSecretId: "webhook:rate:hmac",
			rateLimitPerHour: 1,
		});

		expect(
			consumeWebhookRateLimit({
				slug: "rate",
				perWebhookLimit: 1,
				globalLimit: 10,
				nowMs: 1_700_000_000_000,
			}).allowed,
		).toBe(true);
		const second = consumeWebhookRateLimit({
			slug: "rate",
			perWebhookLimit: 1,
			globalLimit: 10,
			nowMs: 1_700_000_100_000,
		});
		expect(second.allowed).toBe(false);
		expect(second.limitType).toBe("webhook");
	});

	it("prunes stale webhook replay guards and hit audit rows during cleanup", async () => {
		const now = Date.now();
		const oldDeliveryDigest = "a".repeat(64);
		const freshDeliveryDigest = "b".repeat(64);
		const oldBodyHash = "c".repeat(64);
		const freshBodyHash = "d".repeat(64);
		const { cleanupExpired, getDb } = await import("../../src/storage/db.js");
		const { recordWebhookHit, reserveWebhookDelivery } = await import(
			"../../src/webhooks/store.js"
		);

		expect(
			reserveWebhookDelivery(
				{
					slug: "deploy",
					signatureDigest: oldDeliveryDigest,
					bodySha256: oldBodyHash,
				},
				now - 25 * 60 * 60 * 1000,
			).fresh,
		).toBe(true);
		expect(
			reserveWebhookDelivery(
				{
					slug: "deploy",
					signatureDigest: freshDeliveryDigest,
					bodySha256: freshBodyHash,
				},
				now,
			).fresh,
		).toBe(true);
		recordWebhookHit(
			{
				slug: "deploy",
				signatureValid: true,
				actionTaken: "accepted",
				bodySha256: oldBodyHash,
			},
			now - 31 * 24 * 60 * 60 * 1000,
		);
		recordWebhookHit(
			{
				slug: "deploy",
				signatureValid: true,
				actionTaken: "accepted",
				bodySha256: freshBodyHash,
			},
			now,
		);

		const result = cleanupExpired();

		expect(result.webhookDeliveries).toBe(1);
		expect(result.webhookHits).toBe(1);
		expect(getDb().prepare("SELECT COUNT(*) AS count FROM webhook_deliveries").get()).toMatchObject(
			{ count: 1 },
		);
		expect(getDb().prepare("SELECT COUNT(*) AS count FROM webhook_hits").get()).toMatchObject({
			count: 1,
		});
		expect(
			reserveWebhookDelivery({
				slug: "deploy",
				signatureDigest: oldDeliveryDigest,
				bodySha256: oldBodyHash,
			}).fresh,
		).toBe(true);
		expect(
			reserveWebhookDelivery({
				slug: "deploy",
				signatureDigest: freshDeliveryDigest,
				bodySha256: freshBodyHash,
			}).fresh,
		).toBe(false);
	});

	it("ingestWebhookDelivery enqueues once and returns the existing job on replay", async () => {
		const { ingestWebhookDelivery } = await import("../../src/webhooks/store.js");
		const digest = "a".repeat(64);
		const body = "b".repeat(64);
		let calls = 0;
		const enqueue = () => {
			calls += 1;
			return { id: `job-${calls}` };
		};

		const first = ingestWebhookDelivery(
			{ slug: "deploy", signatureDigest: digest, bodySha256: body },
			enqueue,
		);
		expect(first).toEqual({ duplicate: false, job: { id: "job-1" } });

		const replay = ingestWebhookDelivery(
			{ slug: "deploy", signatureDigest: digest, bodySha256: body },
			enqueue,
		);
		expect(replay).toEqual({ duplicate: true, backgroundJobId: "job-1" });
		// The replay must NOT enqueue a second job (the double-trigger this guards against).
		expect(calls).toBe(1);
	});

	it("ingestWebhookDelivery rolls back the job and the reservation on a crash before completion", async () => {
		const { ingestWebhookDelivery } = await import("../../src/webhooks/store.js");
		const { createJob } = await import("../../src/background/jobs.js");
		const { getDb } = await import("../../src/storage/db.js");
		const digest = "c".repeat(64);
		const body = "d".repeat(64);
		const jobInput = {
			title: "Webhook deploy",
			description: "trigger",
			userId: "webhook:deploy",
			tier: "WRITE_LOCAL" as const,
			payload: {
				kind: "cron-run" as const,
				jobId: "target-cron",
				webhook: { slug: "deploy", bodyHash: body },
			},
		};

		// Real job insert, then a failure BEFORE completeWebhookDelivery runs — exactly
		// the crash-after-enqueue/before-complete window. The transaction must undo both.
		expect(() =>
			ingestWebhookDelivery({ slug: "deploy", signatureDigest: digest, bodySha256: body }, () => {
				createJob(jobInput);
				throw new Error("crash before complete");
			}),
		).toThrow(/crash before complete/);

		const db = getDb();
		expect(
			db
				.prepare("SELECT COUNT(*) AS count FROM webhook_deliveries WHERE signature_digest = ?")
				.get(digest),
		).toMatchObject({ count: 0 });
		// The job insert was rolled back too — no orphan queued job survives the crash.
		expect(db.prepare("SELECT COUNT(*) AS count FROM background_jobs").get()).toMatchObject({
			count: 0,
		});

		// A retry now succeeds and enqueues exactly one job — no double-trigger.
		let made = 0;
		const retry = ingestWebhookDelivery(
			{ slug: "deploy", signatureDigest: digest, bodySha256: body },
			() => {
				made += 1;
				return createJob(jobInput);
			},
		);
		expect(retry.duplicate).toBe(false);
		expect(made).toBe(1);
		expect(db.prepare("SELECT COUNT(*) AS count FROM background_jobs").get()).toMatchObject({
			count: 1,
		});
	});

	it("ingestWebhookDelivery self-heals a stale reservation without double-enqueuing", async () => {
		const { ingestWebhookDelivery, reserveWebhookDelivery } = await import(
			"../../src/webhooks/store.js"
		);
		const { getDb } = await import("../../src/storage/db.js");
		const digest = "e".repeat(64);
		const body = "f".repeat(64);

		// A reservation row with no job id, as left by a crash under an older path.
		expect(
			reserveWebhookDelivery({ slug: "deploy", signatureDigest: digest, bodySha256: body }).fresh,
		).toBe(true);

		let calls = 0;
		const result = ingestWebhookDelivery(
			{ slug: "deploy", signatureDigest: digest, bodySha256: body },
			() => {
				calls += 1;
				return { id: "job-heal" };
			},
		);
		expect(result).toEqual({ duplicate: false, job: { id: "job-heal" } });
		expect(calls).toBe(1);
		expect(
			getDb()
				.prepare(
					"SELECT background_job_id AS jobId FROM webhook_deliveries WHERE signature_digest = ?",
				)
				.get(digest),
		).toMatchObject({ jobId: "job-heal" });
	});
});
