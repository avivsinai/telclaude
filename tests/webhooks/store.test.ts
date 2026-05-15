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
});
