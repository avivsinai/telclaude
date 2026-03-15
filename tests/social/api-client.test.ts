import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getSecretMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

vi.mock("../../src/secrets/index.js", () => ({
	getSecret: (...args: unknown[]) => getSecretMock(...args),
	SECRET_KEYS: { MOLTBOOK_API_KEY: "moltbook-api-key" },
}));

import { createMoltbookClient, MoltbookClient } from "../../src/social/backends/moltbook.js";

const baseUrl = "https://moltbook.test/api/v1";

function jsonResponse(payload: unknown, status = 200) {
	return new Response(JSON.stringify(payload), { status });
}

describe("moltbook api client", () => {
	beforeEach(() => {
		getSecretMock.mockReset();
	});

	afterEach(() => {
		delete process.env.MOLTBOOK_API_BASE;
	});

	it("createMoltbookClient returns null without api key", async () => {
		getSecretMock.mockResolvedValueOnce(null);
		const client = await createMoltbookClient({
			enabled: true,
			heartbeatIntervalHours: 4,
		} as any);
		expect(client).toBeNull();
	});

	it("createMoltbookClient uses secrets store", async () => {
		getSecretMock.mockResolvedValueOnce("secret-key");
		process.env.MOLTBOOK_API_BASE = baseUrl;
		const client = await createMoltbookClient({
			enabled: true,
			heartbeatIntervalHours: 4,
		} as any);
		expect(client).toBeInstanceOf(MoltbookClient);
	});

	it("fetchNotifications supports array payload", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/notifications`);
			const headers = new Headers(init?.headers);
			expect(headers.get("Authorization")).toBe("Bearer test-key");
			return jsonResponse([{ id: "n1" }]);
		});
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([{ id: "n1" }]);
	});

	it("fetchNotifications supports notifications envelope", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ notifications: [{ id: "n2" }] }));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([{ id: "n2" }]);
	});

	it("fetchNotifications supports data envelope", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ data: [{ id: "n3" }] }));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([{ id: "n3" }]);
	});

	it("fetchNotifications returns empty array on rate limit", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([]);
	});

	it("fetchNotifications throws on server error", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "boom" }, 500));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		await expect(client.fetchNotifications()).rejects.toMatchObject({
			message: expect.stringContaining("Moltbook notifications failed (500): boom"),
			status: 500,
			statusCode: 500,
		});
	});

	it("postReply succeeds on 200", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/posts/post-1/comments`);
			const body = JSON.parse(String(init?.body));
			expect(body.body).toBe("hello");
			return jsonResponse({ ok: true }, 200);
		});
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.postReply("post-1", "hello");
		expect(result.ok).toBe(true);
		expect(result.status).toBe(200);
	});

	it("postReply flags rate limit on 429", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.postReply("post-1", "hello");
		expect(result.ok).toBe(false);
		expect(result.rateLimited).toBe(true);
		expect(result.status).toBe(429);
	});

	it("postReply returns error for non-429 failures", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "bad request" }, 400));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.postReply("post-1", "hello");
		expect(result.ok).toBe(false);
		expect(result.status).toBe(400);
		expect(result.error).toContain("bad request");
	});

	it("lookupUser resolves an account by canonical handle", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/accounts/lookup?acct=Alice%40Example.com`);
			expect(init?.method).toBe("GET");
			return jsonResponse({
				id: "acct-42",
				display_name: "Alice Example",
				acct: "Alice@Example.com",
			});
		});
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.lookupUser("@Alice@Example.com");

		expect(result).toEqual({
			ok: true,
			status: 200,
			userId: "acct-42",
			displayName: "Alice Example",
			handle: "Alice@Example.com",
		});
	});

	it("lookupUser returns error details for missing accounts", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "Account not found" }, 404));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.lookupUser("missing");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(404);
		expect(result.error).toBe("Account not found");
	});

	it("lookupUser marks rate limits explicitly", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.lookupUser("writer");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(429);
		expect(result.rateLimited).toBe(true);
	});

	it("follow returns pending when the account is locked", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/accounts/acct-42/follow`);
			expect(init?.method).toBe("POST");
			return jsonResponse({ requested: true, following: false }, 200);
		});
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.follow("acct-42");

		expect(result).toEqual({
			ok: true,
			status: 200,
			following: false,
			pending: true,
		});
	});

	it("follow marks rate limits explicitly", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.follow("acct-42");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(429);
		expect(result.rateLimited).toBe(true);
	});

	it("unfollow returns following false on success", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/accounts/acct-42/unfollow`);
			expect(init?.method).toBe("POST");
			return jsonResponse({ following: false }, 200);
		});
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.unfollow("acct-42");

		expect(result).toEqual({
			ok: true,
			status: 200,
			following: false,
		});
	});

	it("unfollow marks rate limits explicitly", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookClient({ apiKey: "test-key", baseUrl, fetchImpl });

		const result = await client.unfollow("acct-42");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(429);
		expect(result.rateLimited).toBe(true);
	});
});
