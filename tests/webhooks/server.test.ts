import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWebhookSignatureHeader } from "../../src/webhooks/auth.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;
const SECRET = "0123456789abcdef0123456789abcdef";

describe("webhook server", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-webhook-server-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
		const { addCronJob } = await import("../../src/cron/store.js");
		addCronJob({
			id: "curator-webhook",
			name: "curator",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "curator-scan" },
		});
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	async function createServer(options?: {
		enabled?: boolean;
		webhookEnabled?: boolean;
		rate?: number;
		unauthenticatedRate?: number;
		allowedCidrs?: string[];
		trustedProxies?: string[];
		allowedHosts?: string[];
	}) {
		const { buildWebhookServer } = await import("../../src/webhooks/server.js");
		const { createWebhook } = await import("../../src/webhooks/store.js");
		createWebhook({
			slug: "build",
			targetCronJobId: "curator-webhook",
			vaultSecretId: "webhook:build:hmac",
			allowedCidrs: options?.allowedCidrs ?? ["127.0.0.1/32"],
			rateLimitPerHour: options?.rate ?? 60,
			enabled: options?.webhookEnabled ?? true,
		});
		const server = await buildWebhookServer({
			config: {
				enabled: options?.enabled ?? true,
				port: 0,
				maxBodyBytes: 256 * 1024,
				globalRateLimitPerHour: 600,
				defaultRateLimitPerHour: 60,
				unauthenticatedRateLimitPerHour: options?.unauthenticatedRate ?? 120,
				trustedProxies: options?.trustedProxies ?? [],
				allowedHosts: options?.allowedHosts ?? [],
			},
			logLevel: "silent",
			getSecret: async (secretId) => (secretId === "webhook:build:hmac" ? SECRET : null),
		});
		await server.ready();
		return server;
	}

	it("queues a background cron-run job after validating the signature", async () => {
		const server = await createServer();
		const payload = Buffer.from('{"event":"push"}');
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: payload });

		const res = await server.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: {
				host: "127.0.0.1",
				"x-telclaude-webhook-signature": signature,
				"content-type": "application/json",
			},
			payload,
		});

		expect(res.statusCode).toBe(202);
		const body = JSON.parse(res.body);
		expect(body.job.shortId).toMatch(/^[a-f0-9]{8}$/);

		const { listJobs } = await import("../../src/background/jobs.js");
		const jobs = listJobs({ userId: "webhook:build" });
		expect(jobs).toHaveLength(1);
		expect(jobs[0].payload).toMatchObject({
			kind: "cron-run",
			jobId: "curator-webhook",
			webhook: { slug: "build" },
		});
		if (jobs[0].payload.kind === "cron-run") {
			expect(jobs[0].payload.webhook?.bodyHash).toMatch(/^[a-f0-9]{64}$/);
		}

		const { listWebhookHits, getWebhook } = await import("../../src/webhooks/store.js");
		expect(getWebhook("build")?.hitCount).toBe(1);
		const hits = listWebhookHits("build");
		expect(hits[0].actionTaken).toBe("queued");
		expect(hits[0].signatureValid).toBe(true);

		await server.close();
	});

	it("limits bad-signature traffic before repeated audit writes", async () => {
		const server = await createServer({ unauthenticatedRate: 1 });
		const request = {
			method: "POST" as const,
			url: "/v1/webhooks/build",
			headers: {
				host: "127.0.0.1",
				"x-telclaude-webhook-signature": "t=1700000000,v1=bad",
			},
			payload: Buffer.from("bad"),
		};

		expect((await server.inject(request)).statusCode).toBe(401);
		const second = await server.inject(request);
		expect(second.statusCode).toBe(429);

		const { listWebhookHits } = await import("../../src/webhooks/store.js");
		const hits = listWebhookHits("build");
		expect(hits).toHaveLength(1);
		expect(hits[0].failureReason).toBe("invalid_signature_header");
		await server.close();
	});

	it("uses explicitly trusted proxy hops for source CIDR checks", async () => {
		const server = await createServer({
			allowedCidrs: ["203.0.113.0/24"],
			trustedProxies: ["127.0.0.1"],
			allowedHosts: ["hooks.example.com"],
		});
		const payload = Buffer.from("x");
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: payload });

		const res = await server.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: {
				host: "hooks.example.com",
				"x-forwarded-for": "203.0.113.8",
				"x-telclaude-webhook-signature": signature,
			},
			payload,
		});

		expect(res.statusCode).toBe(202);
		await server.close();
	});

	it("ignores spoofed forwarded IPs when no proxy hop is trusted", async () => {
		const server = await createServer({ allowedCidrs: ["203.0.113.0/24"] });
		const payload = Buffer.from("x");
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: payload });

		const res = await server.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: {
				host: "127.0.0.1",
				"x-forwarded-for": "203.0.113.8",
				"x-telclaude-webhook-signature": signature,
			},
			payload,
		});

		expect(res.statusCode).toBe(404);
		const { listJobs } = await import("../../src/background/jobs.js");
		expect(listJobs({ userId: "webhook:build" })).toHaveLength(0);
		const { listWebhookHits } = await import("../../src/webhooks/store.js");
		expect(listWebhookHits("build")[0].failureReason).toBe("source_ip_not_allowed");
		await server.close();
	});

	it("rejects invalid signatures without queueing a job", async () => {
		const server = await createServer();
		const res = await server.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: {
				host: "127.0.0.1",
				"x-telclaude-webhook-signature": "t=1700000000,v1=bad",
			},
			payload: Buffer.from("bad"),
		});

		expect(res.statusCode).toBe(401);
		const { listJobs } = await import("../../src/background/jobs.js");
		expect(listJobs({ userId: "webhook:build" })).toHaveLength(0);
		const { listWebhookHits } = await import("../../src/webhooks/store.js");
		expect(listWebhookHits("build")[0].failureReason).toBe("invalid_signature_header");

		await server.close();
	});

	it("refuses a webhook target mutated into a social cron action", async () => {
		const server = await createServer();
		const { getDb } = await import("../../src/storage/db.js");
		getDb()
			.prepare(
				`UPDATE cron_jobs
					 SET action_kind = 'social-heartbeat',
					     action_service_id = 'xtwitter',
					     action_prompt = NULL
					 WHERE id = 'curator-webhook'`,
			)
			.run();

		const payload = Buffer.from("x");
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: payload });
		const res = await server.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: { host: "127.0.0.1", "x-telclaude-webhook-signature": signature },
			payload,
		});

		expect(res.statusCode).toBe(409);
		const { listJobs } = await import("../../src/background/jobs.js");
		expect(listJobs({ userId: "webhook:build" })).toHaveLength(0);
		const { listWebhookHits } = await import("../../src/webhooks/store.js");
		expect(listWebhookHits("build")[0].failureReason).toBe("target_cron_job_social_not_allowed");
		await server.close();
	});

	it("is disabled by global config and by per-webhook flag", async () => {
		const globallyDisabled = await createServer({ enabled: false });
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: Buffer.from("x") });
		const globalRes = await globallyDisabled.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: { host: "127.0.0.1", "x-telclaude-webhook-signature": signature },
			payload: Buffer.from("x"),
		});
		expect(globalRes.statusCode).toBe(404);
		await globallyDisabled.close();

		vi.resetModules();
		const { resetDatabase } = await import("../../src/storage/db.js");
		resetDatabase();
		const { addCronJob } = await import("../../src/cron/store.js");
		addCronJob({
			id: "curator-webhook",
			name: "curator",
			schedule: { kind: "every", everyMs: 60_000 },
			action: { kind: "curator-scan" },
		});
		const webhookDisabled = await createServer({ webhookEnabled: false });
		const disabledRes = await webhookDisabled.inject({
			method: "POST",
			url: "/v1/webhooks/build",
			headers: { host: "127.0.0.1", "x-telclaude-webhook-signature": signature },
			payload: Buffer.from("x"),
		});
		expect(disabledRes.statusCode).toBe(404);
		await webhookDisabled.close();
	});

	it("rate limits accepted signatures", async () => {
		const server = await createServer({ rate: 1 });
		const payload = Buffer.from("x");
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: payload });
		const request = {
			method: "POST" as const,
			url: "/v1/webhooks/build",
			headers: { host: "127.0.0.1", "x-telclaude-webhook-signature": signature },
			payload,
		};
		expect((await server.inject(request)).statusCode).toBe(202);
		expect((await server.inject(request)).statusCode).toBe(429);

		const { listWebhookHits } = await import("../../src/webhooks/store.js");
		expect(listWebhookHits("build")[0].actionTaken).toBe("rate_limited");
		await server.close();
	});

	it("deduplicates exact signed request replays", async () => {
		const server = await createServer();
		const payload = Buffer.from("replay");
		const signature = createWebhookSignatureHeader({ secret: SECRET, rawBody: payload });
		const request = {
			method: "POST" as const,
			url: "/v1/webhooks/build",
			headers: { host: "127.0.0.1", "x-telclaude-webhook-signature": signature },
			payload,
		};

		const first = await server.inject(request);
		const second = await server.inject(request);

		expect(first.statusCode).toBe(202);
		expect(second.statusCode).toBe(202);
		expect(JSON.parse(second.body).duplicate).toBe(true);

		const { listJobs } = await import("../../src/background/jobs.js");
		expect(listJobs({ userId: "webhook:build" })).toHaveLength(1);
		const { listWebhookHits } = await import("../../src/webhooks/store.js");
		expect(listWebhookHits("build")[0].actionTaken).toBe("duplicate");
		await server.close();
	});

	it("allows relay shutdown to close the listening handle more than once", async () => {
		const { startWebhookServer } = await import("../../src/webhooks/server.js");
		const handle = await startWebhookServer({
			config: {
				enabled: true,
				port: 0,
				maxBodyBytes: 256 * 1024,
				globalRateLimitPerHour: 600,
				defaultRateLimitPerHour: 60,
				unauthenticatedRateLimitPerHour: 120,
				trustedProxies: [],
				allowedHosts: [],
			},
			logLevel: "silent",
		});

		await expect(handle.close()).resolves.toBeUndefined();
		await expect(handle.close()).resolves.toBeUndefined();
	});
});
