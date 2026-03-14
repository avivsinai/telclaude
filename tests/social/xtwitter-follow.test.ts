import { describe, expect, it, vi } from "vitest";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import { XTwitterClient } from "../../src/social/backends/xtwitter.js";

function jsonResponse(payload: unknown, status = 200) {
	return new Response(JSON.stringify(payload), { status });
}

describe("XTwitterClient.lookupUser", () => {
	it("looks up a user by username and normalizes the result", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe("https://api.x.com/2/users/by/username/writer");
			expect(init?.method).toBe("GET");
			return jsonResponse({
				data: { id: "user-7", name: "Writer", username: "writer" },
			});
		});

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.lookupUser("@writer");

		expect(result).toEqual({
			ok: true,
			status: 200,
			userId: "user-7",
			displayName: "Writer",
			handle: "writer",
		});
	});

	it("returns a not-found error when lookup fails with 404", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse(
				{
					errors: [
						{
							message: "User not found",
							type: "https://api.x.com/2/problems/resource-not-found",
						},
					],
				},
				404,
			),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.lookupUser("missing-user");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(404);
		expect(result.error).toContain("User not found");
	});

	it("returns a graceful tier-gated error for forbidden lookups", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse({ errors: [{ message: "Forbidden", type: "about:blank" }] }, 403),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.lookupUser("writer");

		expect(result).toEqual({
			ok: false,
			status: 403,
			error: "not available on current API tier",
		});
	});
});

describe("XTwitterClient.follow", () => {
	it("follows a user and returns follow state", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe("https://api.x.com/2/users/auth-user/following");
			expect(init?.method).toBe("POST");
			expect(JSON.parse(String(init?.body))).toEqual({ target_user_id: "target-9" });
			return jsonResponse({
				data: { following: true, pending_follow: true },
			});
		});

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.follow("target-9");

		expect(result).toEqual({
			ok: true,
			status: 200,
			following: true,
			pending: true,
		});
	});

	it("returns a graceful tier-gated error for forbidden follows", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse({ errors: [{ message: "Forbidden", type: "about:blank" }] }, 403),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.follow("target-9");

		expect(result).toEqual({
			ok: false,
			status: 403,
			error: "follow not available on current API tier (requires Basic)",
		});
	});

	it("marks follow requests as rate limited on 429", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse({ errors: [{ message: "Rate limit exceeded", type: "about:blank" }] }, 429),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.follow("target-9");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(429);
		expect(result.rateLimited).toBe(true);
		expect(result.error).toContain("Rate limit exceeded");
	});
});

describe("XTwitterClient.unfollow", () => {
	it("unfollows a user and returns following false", async () => {
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			expect(url).toBe("https://api.x.com/2/users/auth-user/following/target-9");
			expect(init?.method).toBe("DELETE");
			return jsonResponse({
				data: { following: false },
			});
		});

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.unfollow("target-9");

		expect(result).toEqual({
			ok: true,
			status: 200,
			following: false,
		});
	});

	it("returns a graceful tier-gated error for forbidden unfollows", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse({ errors: [{ message: "Forbidden", type: "about:blank" }] }, 403),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.unfollow("target-9");

		expect(result).toEqual({
			ok: false,
			status: 403,
			error: "unfollow not available on current API tier (requires Basic)",
		});
	});

	it("marks unfollow requests as rate limited on 429", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse({ errors: [{ message: "Rate limit exceeded", type: "about:blank" }] }, 429),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.unfollow("target-9");

		expect(result.ok).toBe(false);
		expect(result.status).toBe(429);
		expect(result.rateLimited).toBe(true);
		expect(result.error).toContain("Rate limit exceeded");
	});
});
