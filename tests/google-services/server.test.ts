import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { JtiStore } from "../../src/google-services/approval.js";
import { HealthStore } from "../../src/google-services/health.js";
import { buildServer } from "../../src/google-services/server.js";
import type { TokenManager } from "../../src/google-services/token-manager.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Mock token manager — never calls real vault
// ═══════════════════════════════════════════════════════════════════════════════

function createMockTokenManager(overrides?: {
	getAccessToken?: TokenManager["getAccessToken"];
	getPublicKey?: TokenManager["getPublicKey"];
}): TokenManager {
	return {
		getAccessToken:
			overrides?.getAccessToken ??
			(async () => ({ ok: true as const, token: "mock-access-token", expiresAt: Date.now() + 3600 })),
		getPublicKey: overrides?.getPublicKey ?? (async () => "mock-public-key"),
	} as TokenManager;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Server test suite
// ═══════════════════════════════════════════════════════════════════════════════

describe("google-services server", () => {
	let server: FastifyInstance;
	let dir: string;
	let jtiStore: JtiStore;

	beforeAll(async () => {
		dir = join(tmpdir(), `server-test-${Date.now()}`);
		mkdirSync(dir, { recursive: true });
		jtiStore = new JtiStore(dir);
		const healthStore = new HealthStore();
		const tokenManager = createMockTokenManager();

		server = await buildServer({
			tokenManager,
			jtiStore,
			healthStore,
			logLevel: "silent",
		});
		await server.ready();
	});

	afterAll(async () => {
		await server.close();
		jtiStore.close();
		if (existsSync(dir)) rmSync(dir, { recursive: true });
	});

	// ─── /v1/health ──────────────────────────────────────────────────────────

	it("GET /v1/health returns coarse status", async () => {
		const res = await server.inject({ method: "GET", url: "/v1/health" });
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.status).toBe("ok");
		expect(body.services).toBeDefined();
		expect(body.services.gmail).toBe("ok");
		expect(body.services.calendar).toBe("ok");
		expect(body.services.drive).toBe("ok");
		expect(body.services.contacts).toBe("ok");
	});

	it("GET /v1/health?detail=true returns detailed status", async () => {
		const res = await server.inject({ method: "GET", url: "/v1/health?detail=true" });
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.services.gmail).toHaveProperty("failureCount");
	});

	// ─── /v1/schema ──────────────────────────────────────────────────────────

	it("GET /v1/schema returns action catalog", async () => {
		const res = await server.inject({ method: "GET", url: "/v1/schema" });
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.services).toBeInstanceOf(Array);
		expect(body.services.length).toBe(4);
		expect(body.services.some((s: { id: string }) => s.id === "gmail")).toBe(true);
		expect(body.totalActions).toBe(20);
	});

	it("GET /v1/schema includes action params", async () => {
		const res = await server.inject({ method: "GET", url: "/v1/schema" });
		const body = JSON.parse(res.body);
		const gmail = body.services.find((s: { id: string }) => s.id === "gmail");
		const search = gmail.actions.find((a: { id: string }) => a.id === "search");
		expect(search.params.q).toBeDefined();
		expect(search.type).toBe("read");
	});

	// ─── /v1/fetch ───────────────────────────────────────────────────────────

	it("POST /v1/fetch requires x-actor-user-id", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/v1/fetch",
			payload: { service: "gmail", action: "search", params: { q: "test" } },
		});
		expect(res.statusCode).toBe(401);
	});

	it("POST /v1/fetch rejects unknown action", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/v1/fetch",
			headers: { "x-actor-user-id": "telegram:123" },
			payload: { service: "gmail", action: "nonexistent", params: {} },
		});
		expect(res.statusCode).toBe(400);
		const body = JSON.parse(res.body);
		expect(body.error).toContain("Unknown action");
	});

	it("POST /v1/fetch rejects action type without approval token", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/v1/fetch",
			headers: { "x-actor-user-id": "telegram:123" },
			payload: {
				service: "gmail",
				action: "create_draft",
				params: { to: "x@y.com", subject: "hi", body: "test" },
			},
		});
		expect(res.statusCode).toBe(403);
		const body = JSON.parse(res.body);
		expect(body.errorCode).toBe("approval_required");
	});

	it("POST /v1/fetch rejects invalid request body", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/v1/fetch",
			headers: { "x-actor-user-id": "telegram:123" },
			payload: { service: "invalid_service", action: "search" },
		});
		expect(res.statusCode).toBe(400);
	});
});

// ═══════════════════════════════════════════════════════════════════════════════
// Token failure scenarios
// ═══════════════════════════════════════════════════════════════════════════════

describe("google-services server — token failures", () => {
	let server: FastifyInstance;
	let dir: string;
	let jtiStore: JtiStore;

	beforeAll(async () => {
		dir = join(tmpdir(), `server-tokfail-${Date.now()}`);
		mkdirSync(dir, { recursive: true });
		jtiStore = new JtiStore(dir);
		const healthStore = new HealthStore();
		const tokenManager = createMockTokenManager({
			getAccessToken: async () => ({
				ok: false as const,
				error: "Token expired",
				errorClass: "auth_expired",
			}),
		});

		server = await buildServer({
			tokenManager,
			jtiStore,
			healthStore,
			logLevel: "silent",
		});
		await server.ready();
	});

	afterAll(async () => {
		await server.close();
		jtiStore.close();
		if (existsSync(dir)) rmSync(dir, { recursive: true });
	});

	it("POST /v1/fetch returns 401 when token is auth_expired", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/v1/fetch",
			headers: { "x-actor-user-id": "telegram:123" },
			payload: { service: "gmail", action: "search", params: { q: "test" } },
		});
		expect(res.statusCode).toBe(401);
		const body = JSON.parse(res.body);
		expect(body.errorCode).toBe("auth_expired");
	});
});
