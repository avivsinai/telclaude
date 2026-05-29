import crypto from "node:crypto";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { createJob } from "../background/jobs.js";
import type { BackgroundJob, BackgroundJobCreateInput } from "../background/types.js";
import type { WebhooksConfig } from "../config/config.js";
import { getCronJob } from "../cron/store.js";
import { getChildLogger } from "../logging.js";
import { getSecret } from "../secrets/index.js";
import { verifyWebhookSignature, WEBHOOK_SIGNATURE_HEADER } from "./auth.js";
import { ipAllowedByCidrs } from "./cidr.js";
import { getWebhookCronTargetRejection } from "./policy.js";
import {
	consumeWebhookIngressRateLimit,
	consumeWebhookRateLimit,
	getWebhook,
	ingestWebhookDelivery,
	recordWebhookHit,
	type WebhookDefinition,
	type WebhookDeliveryIngest,
} from "./store.js";

const logger = getChildLogger({ module: "webhook-server" });
const ALLOWED_HOST_NAMES = new Set(["127.0.0.1", "localhost", "::1", "[::1]", "ip6-localhost"]);

export type WebhookServerOptions = {
	config: WebhooksConfig;
	logLevel?: string;
	getSecret?: (secretId: string) => Promise<string | null>;
	createJob?: (input: BackgroundJobCreateInput) => BackgroundJob;
};

export type WebhookServerHandle = {
	server: FastifyInstance;
	port: number;
	host: string;
	close(): Promise<void>;
};

function normalizeHostName(raw: string): string {
	if (raw.startsWith("[")) {
		const end = raw.indexOf("]");
		return end > 0 ? raw.slice(0, end + 1) : raw;
	}
	return raw.split(":")[0] ?? raw;
}

function rejectNonLoopbackHost(
	request: FastifyRequest,
	reply: FastifyReply,
	allowedHosts: string[],
): boolean {
	const raw = request.headers.host;
	if (!raw) {
		reply.status(400).send({ ok: false, error: "missing Host header" });
		return false;
	}
	const name = normalizeHostName(raw);
	const extraHosts = new Set(allowedHosts.map(normalizeHostName));
	if (!ALLOWED_HOST_NAMES.has(name) && !extraHosts.has(name)) {
		reply.status(400).send({ ok: false, error: "non-loopback Host rejected" });
		return false;
	}
	return true;
}

function bodyToBuffer(body: unknown): Buffer {
	if (Buffer.isBuffer(body)) return body;
	if (typeof body === "string") return Buffer.from(body);
	if (body === undefined || body === null) return Buffer.alloc(0);
	return Buffer.from(String(body));
}

function sha256Hex(buf: Buffer): string {
	return crypto.createHash("sha256").update(buf).digest("hex");
}

function ingressRateLimitKey(sourceIp: string | undefined, slug: string): string {
	return `${sourceIp ?? "unknown"}:${slug.trim().slice(0, 80) || "<missing>"}`;
}

function signatureDigest(header: string | string[] | undefined, bodyHash: string): string {
	const rawHeader = Array.isArray(header) ? header[0] : (header ?? "");
	return sha256Hex(Buffer.from(`${rawHeader}.${bodyHash}`, "utf8"));
}

function auditHit(params: {
	slug: string;
	sourceIp?: string;
	webhook?: WebhookDefinition | null;
	signatureValid: boolean;
	timestampDeltaSeconds?: number | null;
	actionTaken: string;
	failureReason?: string | null;
	bodyHash: string;
	backgroundJobId?: string | null;
}): void {
	recordWebhookHit({
		slug: params.slug,
		sourceIp: params.sourceIp ?? null,
		signatureValid: params.signatureValid,
		timestampDeltaSeconds: params.timestampDeltaSeconds ?? null,
		actionTaken: params.actionTaken,
		targetCronJobId: params.webhook?.targetCronJobId ?? null,
		backgroundJobId: params.backgroundJobId ?? null,
		failureReason: params.failureReason ?? null,
		bodySha256: params.bodyHash,
	});
}

export async function buildWebhookServer(opts: WebhookServerOptions): Promise<FastifyInstance> {
	const cfg = opts.config;
	const readSecret = opts.getSecret ?? getSecret;
	const enqueueJob = opts.createJob ?? createJob;
	const server = Fastify({
		logger: { level: opts.logLevel ?? "warn" },
		disableRequestLogging: true,
		bodyLimit: cfg.maxBodyBytes,
		trustProxy: cfg.trustedProxies.length > 0 ? cfg.trustedProxies : undefined,
	});

	server.removeAllContentTypeParsers();
	server.addContentTypeParser(
		"*",
		{ parseAs: "buffer", bodyLimit: cfg.maxBodyBytes },
		(_request, body, done) => done(null, body),
	);

	server.addHook("onRequest", async (request, reply) => {
		if (!rejectNonLoopbackHost(request, reply, cfg.allowedHosts)) return;
	});

	server.get("/v1/health", async () => ({
		ok: true,
		enabled: cfg.enabled,
		maxBodyBytes: cfg.maxBodyBytes,
	}));

	server.post<{
		Params: { slug: string };
	}>("/v1/webhooks/:slug", async (request, reply) => {
		const rawSlug = request.params.slug;
		const rawBody = bodyToBuffer(request.body);
		const bodyHash = sha256Hex(rawBody);
		const sourceIp = request.ip;
		const ingressRateLimit = consumeWebhookIngressRateLimit({
			key: ingressRateLimitKey(sourceIp, rawSlug),
			perKeyLimit: cfg.unauthenticatedRateLimitPerHour,
			globalLimit: cfg.globalRateLimitPerHour,
		});
		if (!ingressRateLimit.allowed) {
			reply.header("retry-after", Math.ceil(ingressRateLimit.resetMs / 1000).toString());
			return reply.status(429).send({ ok: false });
		}

		if (!cfg.enabled) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				signatureValid: false,
				actionTaken: "rejected",
				failureReason: "webhooks_disabled",
				bodyHash,
			});
			return reply.status(404).send({ ok: false });
		}

		let webhook: WebhookDefinition | null = null;
		try {
			webhook = getWebhook(rawSlug);
		} catch {
			auditHit({
				slug: rawSlug,
				sourceIp,
				signatureValid: false,
				actionTaken: "rejected",
				failureReason: "invalid_slug",
				bodyHash,
			});
			return reply.status(404).send({ ok: false });
		}

		if (!webhook?.enabled) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: false,
				actionTaken: "rejected",
				failureReason: webhook ? "webhook_disabled" : "unknown_webhook",
				bodyHash,
			});
			return reply.status(404).send({ ok: false });
		}

		if (!ipAllowedByCidrs(sourceIp, webhook.allowedCidrs)) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: false,
				actionTaken: "rejected",
				failureReason: "source_ip_not_allowed",
				bodyHash,
			});
			return reply.status(404).send({ ok: false });
		}

		const secret = await readSecret(webhook.vaultSecretId);
		if (!secret) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: false,
				actionTaken: "rejected",
				failureReason: "missing_secret",
				bodyHash,
			});
			logger.error({ slug: webhook.slug }, "webhook secret missing");
			return reply.status(503).send({ ok: false, error: "webhook unavailable" });
		}

		const verification = verifyWebhookSignature({
			header: request.headers[WEBHOOK_SIGNATURE_HEADER],
			secret,
			rawBody,
		});
		if (!verification.ok) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: verification.signatureValid,
				timestampDeltaSeconds: verification.timestampDeltaSeconds ?? null,
				actionTaken: "rejected",
				failureReason: verification.failureReason ?? "signature_rejected",
				bodyHash,
			});
			return reply.status(401).send({ ok: false });
		}

		const targetCronJob = getCronJob(webhook.targetCronJobId);
		const targetRejection = targetCronJob
			? getWebhookCronTargetRejection(targetCronJob)
			: "target_cron_job_missing";
		if (targetRejection) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: true,
				timestampDeltaSeconds: verification.timestampDeltaSeconds ?? null,
				actionTaken: "rejected",
				failureReason: targetRejection,
				bodyHash,
			});
			return reply.status(409).send({ ok: false, error: "target unavailable" });
		}
		if (!targetCronJob) {
			throw new Error("unreachable: missing target cron job after webhook target validation");
		}

		const rateLimit = consumeWebhookRateLimit({
			slug: webhook.slug,
			perWebhookLimit: webhook.rateLimitPerHour || cfg.defaultRateLimitPerHour,
			globalLimit: cfg.globalRateLimitPerHour,
		});
		if (!rateLimit.allowed) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: true,
				timestampDeltaSeconds: verification.timestampDeltaSeconds ?? null,
				actionTaken: "rate_limited",
				failureReason: `${rateLimit.limitType ?? "webhook"}_rate_limit`,
				bodyHash,
			});
			reply.header("retry-after", Math.ceil(rateLimit.resetMs / 1000).toString());
			return reply.status(429).send({ ok: false });
		}

		const deliveryDigest = signatureDigest(request.headers[WEBHOOK_SIGNATURE_HEADER], bodyHash);
		// Reserve the replay guard, enqueue the job, and record the job id atomically.
		// A crash mid-transaction rolls back both, so a retry can never enqueue a twin
		// job alongside a half-committed one (which would double-trigger the target cron).
		let delivery: WebhookDeliveryIngest<BackgroundJob>;
		try {
			delivery = ingestWebhookDelivery(
				{
					slug: webhook.slug,
					signatureDigest: deliveryDigest,
					bodySha256: bodyHash,
				},
				() =>
					enqueueJob({
						title: `Webhook ${webhook.slug}`,
						description: `Trigger cron job ${targetCronJob.id} (${targetCronJob.name})`,
						userId: `webhook:${webhook.slug}`,
						tier: "WRITE_LOCAL",
						payload: {
							kind: "cron-run",
							jobId: targetCronJob.id,
							webhook: {
								slug: webhook.slug,
								bodyHash,
							},
						},
					}),
			);
		} catch (err) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: true,
				timestampDeltaSeconds: verification.timestampDeltaSeconds ?? null,
				actionTaken: "rejected",
				failureReason: `enqueue_failed:${err instanceof Error ? err.message : String(err)}`,
				bodyHash,
			});
			throw err;
		}

		if (delivery.duplicate) {
			auditHit({
				slug: rawSlug,
				sourceIp,
				webhook,
				signatureValid: true,
				timestampDeltaSeconds: verification.timestampDeltaSeconds ?? null,
				actionTaken: "duplicate",
				bodyHash,
				backgroundJobId: delivery.backgroundJobId,
			});
			return reply.status(202).send({
				ok: true,
				duplicate: true,
				job: { id: delivery.backgroundJobId },
				targetCronJobId: targetCronJob.id,
			});
		}

		const job = delivery.job;

		auditHit({
			slug: rawSlug,
			sourceIp,
			webhook,
			signatureValid: true,
			timestampDeltaSeconds: verification.timestampDeltaSeconds ?? null,
			actionTaken: "queued",
			bodyHash,
			backgroundJobId: job.id,
		});

		return reply.status(202).send({
			ok: true,
			job: {
				id: job.id,
				shortId: job.shortId,
			},
			targetCronJobId: targetCronJob.id,
		});
	});

	return server;
}

export async function startWebhookServer(opts: {
	config: WebhooksConfig;
	logLevel?: string;
	port?: number;
	host?: string;
}): Promise<WebhookServerHandle> {
	const host = opts.host ?? "127.0.0.1";
	if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
		throw new Error(`webhook receiver refuses to bind to non-loopback host ${host}`);
	}
	const server = await buildWebhookServer({ config: opts.config, logLevel: opts.logLevel });
	await server.listen({ port: opts.port ?? opts.config.port, host });
	const address = server.addresses()[0];
	const actualPort = address?.port ?? opts.port ?? opts.config.port;
	let closed = false;
	logger.info({ host, port: actualPort }, "webhook receiver listening");
	return {
		server,
		port: actualPort,
		host,
		async close() {
			if (closed) return;
			closed = true;
			await server.close();
		},
	};
}
