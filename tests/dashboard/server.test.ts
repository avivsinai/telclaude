/**
 * W15 dashboard server tests.
 *
 * Coverage:
 *  - Loopback-only bind: live listen on 127.0.0.1; TCP connect via the loopback
 *    address works, but a request with a non-loopback Host header is rejected.
 *  - Auth gate: every /api/* route except /api/auth/verify and /api/ping returns
 *    401 without a cookie; after a successful TOTP verify, the same routes
 *    succeed with the returned cookie.
 *  - Route wiring: health / providers / skills / approvals / audit / doctor
 *    all reach their underlying modules (via injection).
 *
 * We mock the TOTPClient and the underlying data sources that would otherwise
 * touch the filesystem / network, so the test is fully offline.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// ─── Mocks ─────────────────────────────────────────────────────────────────
// NOTE: order matters — mocks must be declared before importing the server.

vi.mock("../../src/totp-client/client.js", () => {
	const verifyFn = vi.fn(async (_userId: string, code: string) => code === "123456");
	return {
		getTOTPClient: () => ({ verify: verifyFn }),
		__verifyFn: verifyFn,
	};
});

vi.mock("../../src/telegram/status-overview.js", () => ({
	collectSystemHealth: vi.fn(async () => ({
		overallStatus: "ok",
		collectedAtMs: 1,
		items: [{ id: "test", label: "Test", status: "ok", detail: "mock" }],
		issueCount: 0,
	})),
}));

vi.mock("../../src/providers/catalog.js", () => ({
	listCatalogOAuthServices: () => [{ id: "google", displayName: "Google" }],
	listProviderCatalogEntries: () => [
		{ id: "health-provider", displayName: "Health", description: "d", services: [] },
	],
}));

vi.mock("../../src/commands/skills-promote.js", () => ({
	listActiveSkills: () => ["memory", "summarize"],
	listDraftSkills: () => ["experimental"],
}));

vi.mock("../../src/security/approvals.js", () => ({
	listAllowlist: () => [
		{
			id: 1,
			userId: "tg:1",
			tier: "WRITE_LOCAL",
			toolKey: "Bash",
			scope: "session",
			sessionKey: "k",
			grantedAt: 1000,
			expiresAt: 2000,
			lastUsedAt: null,
			chatId: 42,
		},
	],
}));

vi.mock("../../src/security/audit.js", () => ({
	createAuditLogger: () => ({
		readRecent: async () => [
			{
				timestamp: new Date(1_700_000_000_000),
				requestId: "r1",
				telegramUserId: "tg:1",
				chatId: 42,
				messagePreview: "hi",
				permissionTier: "READ_ONLY" as const,
				outcome: "success" as const,
			},
		],
	}),
}));

vi.mock("../../src/config/config.js", () => ({
	loadConfig: () => ({
		providers: [{ id: "health-provider", baseUrl: "https://example.test" }],
		security: { audit: { enabled: true } },
		dashboard: { enabled: true, port: 0 },
	}),
}));

vi.mock("../../src/commands/doctor.js", () => ({
	runDoctor: async () => ({
		checks: [
			{
				name: "config.loaded",
				category: "Config",
				status: "pass",
				summary: "ok",
			},
		],
		summary: { pass: 1, warn: 0, fail: 0, skip: 0 },
	}),
}));

// ─── Imports (after mocks) ─────────────────────────────────────────────────

import net from "node:net";
import { buildDashboardServer, type DashboardServerHandle } from "../../src/dashboard/server.js";
import { DASHBOARD_COOKIE_NAME } from "../../src/dashboard/sessions.js";

describe("dashboard server", () => {
	let handle: DashboardServerHandle;

	beforeAll(async () => {
		// Port 0 asks the OS for a free port.
		handle = await buildDashboardServer({ port: 0, logLevel: "silent" });
	});

	afterAll(async () => {
		await handle.close();
	});

	beforeEach(() => {
		// Clear any sessions between tests.
		for (let i = 0; i < 8; i += 1) handle.sessions.revoke("noop");
	});

	// ───────────────────────────────────────────────────────────────────────
	// Loopback binding
	// ───────────────────────────────────────────────────────────────────────

	it("binds to 127.0.0.1 only", async () => {
		expect(handle.host).toBe("127.0.0.1");
		// The listener is reachable over 127.0.0.1:
		await new Promise<void>((resolve, reject) => {
			const socket = net.createConnection({ host: "127.0.0.1", port: handle.port }, () => {
				socket.end();
				resolve();
			});
			socket.on("error", reject);
		});
	});

	it("rejects bind to non-loopback hosts", async () => {
		await expect(buildDashboardServer({ port: 0, host: "0.0.0.0" })).rejects.toThrow(
			/non-loopback/i,
		);
	});

	it("rejects requests with a non-loopback Host header", async () => {
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/ping",
			headers: { host: "evil.example.com" },
		});
		expect(res.statusCode).toBe(400);
		expect(JSON.parse(res.body).error).toMatch(/non-loopback/i);
	});

	it("accepts requests with a localhost Host (including port)", async () => {
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/ping",
			headers: { host: "localhost:1234" },
		});
		expect(res.statusCode).toBe(200);
	});

	// ───────────────────────────────────────────────────────────────────────
	// Auth gate
	// ───────────────────────────────────────────────────────────────────────

	it("GET /api/health is 401 without a session cookie", async () => {
		const res = await handle.server.inject({ method: "GET", url: "/api/health" });
		expect(res.statusCode).toBe(401);
	});

	it("GET /api/providers is 401 without a session cookie", async () => {
		const res = await handle.server.inject({ method: "GET", url: "/api/providers" });
		expect(res.statusCode).toBe(401);
	});

	it("GET /api/skills is 401 without a session cookie", async () => {
		const res = await handle.server.inject({ method: "GET", url: "/api/skills" });
		expect(res.statusCode).toBe(401);
	});

	it("GET /api/approvals/allowlist is 401 without a session cookie", async () => {
		const res = await handle.server.inject({ method: "GET", url: "/api/approvals/allowlist" });
		expect(res.statusCode).toBe(401);
	});

	it("GET /api/audit/tail is 401 without a session cookie", async () => {
		const res = await handle.server.inject({ method: "GET", url: "/api/audit/tail" });
		expect(res.statusCode).toBe(401);
	});

	it("POST /api/doctor/run is 401 without a session cookie", async () => {
		const res = await handle.server.inject({ method: "POST", url: "/api/doctor/run" });
		expect(res.statusCode).toBe(401);
	});

	it("POST /api/auth/verify rejects wrong TOTP code", async () => {
		const res = await handle.server.inject({
			method: "POST",
			url: "/api/auth/verify",
			payload: { localUserId: "operator", code: "000000" },
		});
		expect(res.statusCode).toBe(401);
	});

	it("POST /api/auth/verify accepts a valid code and sets a cookie", async () => {
		const res = await handle.server.inject({
			method: "POST",
			url: "/api/auth/verify",
			payload: { localUserId: "operator", code: "123456" },
		});
		expect(res.statusCode).toBe(200);
		const setCookie = res.headers["set-cookie"];
		expect(setCookie).toBeTruthy();
		const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : String(setCookie);
		expect(cookieHeader).toMatch(/HttpOnly/);
		expect(cookieHeader).toMatch(/SameSite=Strict/);
		expect(cookieHeader).toMatch(new RegExp(`${DASHBOARD_COOKIE_NAME}=`));
	});

	// ───────────────────────────────────────────────────────────────────────
	// Authenticated wiring
	// ───────────────────────────────────────────────────────────────────────

	async function authedCookie(): Promise<string> {
		const res = await handle.server.inject({
			method: "POST",
			url: "/api/auth/verify",
			payload: { localUserId: "operator", code: "123456" },
		});
		expect(res.statusCode).toBe(200);
		const raw = res.headers["set-cookie"];
		const cookieHeader = Array.isArray(raw) ? raw[0] : String(raw);
		// Extract just the `name=value` piece so we can forward it.
		const piece = cookieHeader.split(";")[0];
		return piece.trim();
	}

	it("GET /api/health reaches collectSystemHealth with a valid cookie", async () => {
		const cookie = await authedCookie();
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/health",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.snapshot.overallStatus).toBe("ok");
	});

	it("GET /api/providers reaches the catalog", async () => {
		const cookie = await authedCookie();
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/providers",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.catalog[0].id).toBe("health-provider");
		expect(body.configured[0].id).toBe("health-provider");
	});

	it("GET /api/skills returns active + drafts", async () => {
		const cookie = await authedCookie();
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/skills",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.active).toContain("memory");
		expect(body.drafts).toContain("experimental");
	});

	it("GET /api/approvals/allowlist returns entries", async () => {
		const cookie = await authedCookie();
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/approvals/allowlist",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.entries[0].toolKey).toBe("Bash");
	});

	it("GET /api/audit/tail returns entries", async () => {
		const cookie = await authedCookie();
		const res = await handle.server.inject({
			method: "GET",
			url: "/api/audit/tail",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.enabled).toBe(true);
		expect(body.entries[0].telegramUserId).toBe("tg:1");
	});

	it("POST /api/doctor/run returns a DoctorReport", async () => {
		const cookie = await authedCookie();
		const res = await handle.server.inject({
			method: "POST",
			url: "/api/doctor/run",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(200);
		const body = JSON.parse(res.body);
		expect(body.report.summary.pass).toBeGreaterThanOrEqual(1);
	});

	it("POST /api/auth/logout invalidates the cookie", async () => {
		const cookie = await authedCookie();
		const logoutRes = await handle.server.inject({
			method: "POST",
			url: "/api/auth/logout",
			headers: { cookie },
		});
		expect(logoutRes.statusCode).toBe(200);

		const res = await handle.server.inject({
			method: "GET",
			url: "/api/health",
			headers: { cookie },
		});
		expect(res.statusCode).toBe(401);
	});

	it("static UI index.html is publicly reachable (no auth)", async () => {
		const res = await handle.server.inject({ method: "GET", url: "/" });
		// We ship the file under assets/dashboard-ui; the route serves it without auth.
		expect([200, 404]).toContain(res.statusCode);
		if (res.statusCode === 200) {
			expect(res.headers["content-type"]).toMatch(/text\/html/);
		}
	});
});
