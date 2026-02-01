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

import { createMoltbookApiClient, MoltbookApiClient } from "../../src/moltbook/api-client.js";

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

	it("createMoltbookApiClient returns null without api key", async () => {
		getSecretMock.mockResolvedValueOnce(null);
		const client = await createMoltbookApiClient({
			enabled: true,
			heartbeatIntervalHours: 4,
		} as any);
		expect(client).toBeNull();
	});

	it("createMoltbookApiClient uses secrets store", async () => {
		getSecretMock.mockResolvedValueOnce("secret-key");
		process.env.MOLTBOOK_API_BASE = baseUrl;
		const client = await createMoltbookApiClient({
			enabled: true,
			heartbeatIntervalHours: 4,
		} as any);
		expect(client).toBeInstanceOf(MoltbookApiClient);
	});

	it("fetchNotifications supports array payload", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/notifications`);
			const headers = new Headers(init?.headers);
			expect(headers.get("Authorization")).toBe("Bearer test-key");
			return jsonResponse([{ id: "n1" }]);
		});
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([{ id: "n1" }]);
	});

	it("fetchNotifications supports notifications envelope", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ notifications: [{ id: "n2" }] }));
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([{ id: "n2" }]);
	});

	it("fetchNotifications supports data envelope", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ data: [{ id: "n3" }] }));
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([{ id: "n3" }]);
	});

	it("fetchNotifications returns empty array on rate limit", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.fetchNotifications();
		expect(result).toEqual([]);
	});

	it("fetchNotifications throws on server error", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "boom" }, 500));
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		await expect(client.fetchNotifications()).rejects.toThrow("Moltbook notifications failed");
	});

	it("postReply succeeds on 200", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe(`${baseUrl}/posts/post-1/comments`);
			const body = JSON.parse(String(init?.body));
			expect(body.body).toBe("hello");
			return jsonResponse({ ok: true }, 200);
		});
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.postReply("post-1", "hello");
		expect(result.ok).toBe(true);
		expect(result.status).toBe(200);
	});

	it("postReply flags rate limit on 429", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "rate limit" }, 429));
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.postReply("post-1", "hello");
		expect(result.ok).toBe(false);
		expect(result.rateLimited).toBe(true);
		expect(result.status).toBe(429);
	});

	it("postReply returns error for non-429 failures", async () => {
		const fetchImpl = vi.fn(async () => jsonResponse({ error: "bad request" }, 400));
		const client = new MoltbookApiClient({ apiKey: "test-key", baseUrl, fetchImpl });
		const result = await client.postReply("post-1", "hello");
		expect(result.ok).toBe(false);
		expect(result.status).toBe(400);
		expect(result.error).toContain("bad request");
	});
});
