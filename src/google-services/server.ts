/**
 * Fastify REST server for the Google Services sidecar.
 *
 * Routes:
 *   GET  /v1/health  — coarse or detailed health status
 *   GET  /v1/schema  — action catalog for LLM tool generation
 *   POST /v1/fetch   — dispatch service action (read or approval-gated)
 */

import crypto from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { getAction, getActionsForService, getAllActions } from "./actions.js";
import { type JtiStore, verifyApprovalToken } from "./approval.js";
import { handleCalendar } from "./handlers/calendar.js";
import { handleContacts } from "./handlers/contacts.js";
import { handleDrive } from "./handlers/drive.js";
import { handleGmail } from "./handlers/gmail.js";
import type { HealthStore } from "./health.js";
import type { TokenManager } from "./token-manager.js";
import { FetchRequestSchema, type FetchResponse } from "./types.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Server Options
// ═══════════════════════════════════════════════════════════════════════════════

export interface ServerOptions {
	tokenManager: TokenManager;
	jtiStore: JtiStore;
	healthStore: HealthStore;
	logLevel?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Build Server
// ═══════════════════════════════════════════════════════════════════════════════

export async function buildServer(opts: ServerOptions): Promise<FastifyInstance> {
	const { tokenManager, jtiStore, healthStore } = opts;

	const server = Fastify({
		logger: { level: opts.logLevel ?? "info" },
	});

	// ─── GET /v1/health ────────────────────────────────────────────────────────
	server.get("/v1/health", async (request, reply) => {
		const detail = (request.query as Record<string, string>).detail === "true";
		const body = detail ? healthStore.getDetailedHealth() : healthStore.getCoarseHealth();
		return reply.send(body);
	});

	// ─── GET /v1/schema ────────────────────────────────────────────────────────
	server.get("/v1/schema", async (_request, reply) => {
		const serviceIds = ["gmail", "calendar", "drive", "contacts"] as const;
		const services = serviceIds.map((id) => ({
			id,
			actions: getActionsForService(id).map((a) => ({
				id: a.id,
				type: a.type,
				description: a.description,
				params: a.params,
			})),
		}));
		return reply.send({ services, totalActions: getAllActions().length });
	});

	// ─── POST /v1/fetch ────────────────────────────────────────────────────────
	server.post("/v1/fetch", async (request, reply) => {
		// 1. Require actor identity
		const actorUserId = (request.headers as Record<string, string>)["x-actor-user-id"];
		if (!actorUserId) {
			return reply.status(401).send({ status: "error", error: "Missing x-actor-user-id header" });
		}

		// 2. Parse and validate request body
		const parsed = FetchRequestSchema.safeParse(request.body);
		if (!parsed.success) {
			return reply
				.status(400)
				.send({ status: "error", error: `Invalid request: ${parsed.error.message}` });
		}
		const fetchReq = parsed.data;

		// 3. Look up action definition
		const actionDef = getAction(fetchReq.service, fetchReq.action);
		if (!actionDef) {
			return reply.status(400).send({
				status: "error",
				error: `Unknown action: ${fetchReq.service}.${fetchReq.action}`,
			});
		}

		// 4. For action-type, verify approval token
		if (actionDef.type === "action") {
			const approvalToken = (request.headers as Record<string, string>)["x-approval-token"];
			if (!approvalToken) {
				return reply.status(403).send({
					status: "error",
					errorCode: "approval_required",
					error: "Action requires approval token",
				});
			}

			const pubKey = await tokenManager.getPublicKey();
			const verifySignature = (payload: string, signature: string): boolean => {
				const message = `approval-v1\n${payload}`;
				const key = crypto.createPublicKey({
					key: Buffer.from(pubKey, "base64"),
					format: "der",
					type: "spki",
				});
				return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature, "base64url"));
			};

			const result = verifyApprovalToken(
				approvalToken,
				fetchReq,
				actorUserId,
				verifySignature,
				jtiStore,
			);
			if (!result.ok) {
				return reply.status(403).send({
					status: "error",
					errorCode: result.code,
					error: result.message,
				});
			}
		}

		// 5. Get access token
		const tokenResult = await tokenManager.getAccessToken();
		if (!tokenResult.ok) {
			const statusCode = tokenResult.errorClass === "auth_expired" ? 401 : 502;
			return reply.status(statusCode).send({
				status: "error",
				errorCode: tokenResult.errorClass,
				error: tokenResult.error,
			});
		}

		// 6. Dispatch to service handler
		let response: FetchResponse;
		try {
			switch (fetchReq.service) {
				case "gmail":
					response = await handleGmail(fetchReq, tokenResult.token);
					break;
				case "calendar":
					response = await handleCalendar(fetchReq, tokenResult.token);
					break;
				case "drive":
					response = await handleDrive(fetchReq, tokenResult.token);
					break;
				case "contacts":
					response = await handleContacts(fetchReq, tokenResult.token);
					break;
				default:
					return reply
						.status(400)
						.send({ status: "error", error: `Unknown service: ${fetchReq.service}` });
			}
		} catch (err) {
			healthStore.recordFailure(fetchReq.service);
			return reply.status(500).send({
				status: "error",
				error: err instanceof Error ? err.message : String(err),
			});
		}

		// 7. Update health and return
		if (response.status === "ok") {
			healthStore.recordSuccess(fetchReq.service);
		} else {
			healthStore.recordFailure(fetchReq.service);
		}

		const statusCode = response.status === "ok" ? 200 : 502;
		return reply.status(statusCode).send(response);
	});

	return server;
}
