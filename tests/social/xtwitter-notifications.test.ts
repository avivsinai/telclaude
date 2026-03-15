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

describe("XTwitterClient.fetchNotifications", () => {
	it("throws status-tagged errors for upstream server failures", async () => {
		const fetchImpl = vi.fn(async () =>
			jsonResponse(
				{
					errors: [{ message: "Bad gateway: upstream request failed", type: "about:blank" }],
				},
				502,
			),
		);

		const client = new XTwitterClient({
			userId: "auth-user",
			baseUrl: "https://api.x.com",
			fetchImpl,
		});

		await expect(client.fetchNotifications()).rejects.toMatchObject({
			message: expect.stringContaining(
				"X mentions failed (502): [{\"message\":\"Bad gateway: upstream request failed\"",
			),
			status: 502,
			statusCode: 502,
		});
	});
});
