import path from "node:path";

import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { readFixtureFile } from "../../src/testing/live-replay.js";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/totp-client/client.js", () => ({
	getTOTPClient: () => ({ verify: async (_userId: string, code: string) => code === "123456" }),
}));

vi.mock("../../src/telegram/status-overview.js", () => ({
	collectSystemHealth: async () => ({
		overallStatus: "ok",
		collectedAtMs: 1,
		items: [{ id: "test", label: "Test", status: "ok", detail: "mock" }],
		issueCount: 0,
	}),
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
			userId: "[REDACTED_ID:user]",
			tier: "WRITE_LOCAL",
			toolKey: "Bash",
			scope: "session",
			sessionKey: "k",
			grantedAt: 1000,
			expiresAt: 2000,
			lastUsedAt: null,
			chatId: "[REDACTED_ID:chat]",
		},
	],
}));

vi.mock("../../src/security/audit.js", () => ({
	createAuditLogger: () => ({
		readRecent: async () => [
			{
				timestamp: new Date(1_700_000_000_000),
				requestId: "r1",
				telegramUserId: "[REDACTED_ID:user]",
				chatId: "[REDACTED_ID:chat]",
				messagePreview: "[REDACTED_TEXT]",
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

vi.mock("../../src/dashboard/routes/operator.js", () => ({
	registerOperatorRoutes: async () => {},
}));

import { registerApprovalsRoute } from "../../src/dashboard/routes/approvals.js";
import { registerAuditRoute } from "../../src/dashboard/routes/audit.js";
import { registerDoctorRoute } from "../../src/dashboard/routes/doctor.js";
import { registerHealthRoute } from "../../src/dashboard/routes/health.js";
import { registerProvidersRoute } from "../../src/dashboard/routes/providers.js";
import { registerSkillsRoute } from "../../src/dashboard/routes/skills.js";

type DashboardRoutesFixture = {
	routes: Record<string, { statusCode: number; body: unknown }>;
};

const fixturePath = path.join(
	process.cwd(),
	"tests",
	"fixtures",
	"integration",
	"dashboard-routes.json",
);

describe("dashboard route replay snapshots", () => {
	let server: FastifyInstance;

	beforeAll(async () => {
		server = Fastify({ logger: false });
		await registerHealthRoute(server);
		await registerProvidersRoute(server);
		await registerSkillsRoute(server);
		await registerApprovalsRoute(server);
		await registerAuditRoute(server);
		await registerDoctorRoute(server);
		await server.ready();
	});

	afterAll(async () => {
		await server.close();
	});

	it("matches checked-in route snapshots without live services", async () => {
		const fixture = await readFixtureFile<DashboardRoutesFixture>(fixturePath);

		for (const [key, expected] of Object.entries(fixture.data.routes)) {
			const [method, url] = key.split(" ");
			const res = await server.inject({
				method: method as "GET" | "POST",
				url,
			});
			expect({ statusCode: res.statusCode, body: JSON.parse(res.body) }).toEqual(expected);
		}
	});
});
