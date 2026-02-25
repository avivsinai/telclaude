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

describe("XTwitterClient.createThread", () => {
	it("posts a 3-tweet thread via reply-to-self chain", async () => {
		const calls: Array<{ url: string; body: unknown }> = [];
		const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body));
			calls.push({ url, body });
			const index = calls.length;
			return jsonResponse({ data: { id: `tweet-${index}`, text: body.text } }, 201);
		});

		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.createThread([
			"Hook tweet",
			"Body tweet",
			"CTA tweet",
		]);

		expect(result.ok).toBe(true);
		expect(result.postId).toBe("tweet-1");
		expect(result.tweetIds).toEqual(["tweet-1", "tweet-2", "tweet-3"]);
		expect(fetchImpl).toHaveBeenCalledTimes(3);

		// First tweet: no reply field
		expect(calls[0].body).toEqual({ text: "Hook tweet" });
		// Second tweet: replies to first
		expect(calls[1].body).toEqual({
			text: "Body tweet",
			reply: { in_reply_to_tweet_id: "tweet-1" },
		});
		// Third tweet: replies to second (not first!)
		expect(calls[2].body).toEqual({
			text: "CTA tweet",
			reply: { in_reply_to_tweet_id: "tweet-2" },
		});
	});

	it("returns error for empty thread", async () => {
		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl: vi.fn(),
		});

		const result = await client.createThread([]);
		expect(result.ok).toBe(false);
		expect(result.error).toBe("empty thread");
	});

	it("delegates to createPost for single-tweet thread", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse({ data: { id: "single-1", text: "hello" } }, 201),
		);
		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.createThread(["Single tweet"]);
		expect(result.ok).toBe(true);
		expect(result.postId).toBe("single-1");
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("handles mid-chain failure with partial tweetIds", async () => {
		let callCount = 0;
		const fetchImpl = vi.fn(async () => {
			callCount++;
			if (callCount === 2) {
				return jsonResponse({ errors: [{ message: "forbidden" }] }, 403);
			}
			return jsonResponse({ data: { id: `tweet-${callCount}`, text: "ok" } }, 201);
		});

		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.createThread(["tweet 1", "tweet 2", "tweet 3"]);
		expect(result.ok).toBe(false);
		expect(result.error).toContain("tweet 2/3");
		expect(result.postId).toBe("tweet-1"); // first tweet was posted
		expect(result.tweetIds).toEqual(["tweet-1"]); // only first succeeded
	});

	it("handles rate limit mid-chain", async () => {
		let callCount = 0;
		const fetchImpl = vi.fn(async () => {
			callCount++;
			if (callCount === 3) {
				return jsonResponse({ errors: [{ message: "rate limit" }] }, 429);
			}
			return jsonResponse({ data: { id: `tweet-${callCount}`, text: "ok" } }, 201);
		});

		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.createThread(["a", "b", "c", "d"]);
		expect(result.ok).toBe(false);
		expect(result.rateLimited).toBe(true);
		expect(result.tweetIds).toEqual(["tweet-1", "tweet-2"]);
	});

	it("fails if API returns ok but missing tweet ID", async () => {
		let callCount = 0;
		const fetchImpl = vi.fn(async () => {
			callCount++;
			if (callCount === 2) {
				// API returns 200 but no data.id
				return jsonResponse({ data: {} }, 200);
			}
			return jsonResponse({ data: { id: `tweet-${callCount}`, text: "ok" } }, 201);
		});

		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.createThread(["a", "b", "c"]);
		expect(result.ok).toBe(false);
		expect(result.error).toContain("missing tweet ID");
		expect(result.tweetIds).toEqual(["tweet-1"]);
	});

	it("truncates individual tweets that exceed 280 chars", async () => {
		const longTweet = "a".repeat(300);
		const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body));
			// Verify the text was truncated
			expect(body.text.length).toBeLessThanOrEqual(280);
			return jsonResponse({ data: { id: "t1", text: body.text } }, 201);
		});

		const client = new XTwitterClient({
			userId: "user-1",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		const result = await client.createThread([longTweet]);
		expect(result.ok).toBe(true);
	});
});
