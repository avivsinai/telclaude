import http from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

import { startCapabilityServer } from "../../src/relay/capabilities.js";

const ORIGINAL_ENV = {
	CLAUDE_CODE_OAUTH_TOKEN: process.env.CLAUDE_CODE_OAUTH_TOKEN,
	ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
};

type RequestResult = { status: number; body: string };

function makeRequest(
	baseUrl: string,
	path: string,
	body?: string,
	method: string = "POST",
): Promise<RequestResult> {
	return new Promise((resolve, reject) => {
		const url = new URL(path, baseUrl);
		const req = http.request(
			{
				hostname: url.hostname,
				port: Number(url.port),
				path: url.pathname + url.search,
				method,
				headers: {
					"Content-Type": "application/json",
					"Content-Length": body ? Buffer.byteLength(body) : 0,
				},
			},
			(res) => {
				let data = "";
				res.on("data", (chunk) => {
					data += chunk.toString();
				});
				res.on("end", () => {
					resolve({ status: res.statusCode ?? 0, body: data });
				});
			},
		);
		req.on("error", reject);
		if (body) {
			req.write(body);
		}
		req.end();
	});
}

describe("anthropic proxy", () => {
	let server: ReturnType<typeof startCapabilityServer> | null = null;
	let baseUrl = "";

	beforeEach(async () => {
		process.env.CLAUDE_CODE_OAUTH_TOKEN = "oauth-token";
		delete process.env.ANTHROPIC_API_KEY;

		server = startCapabilityServer({ port: 0, host: "127.0.0.1" });
		await once(server, "listening");
		const address = server.address() as AddressInfo;
		baseUrl = `http://127.0.0.1:${address.port}`;
	});

	afterEach(() => {
		if (server) {
			server.close();
			server = null;
		}
		if (ORIGINAL_ENV.CLAUDE_CODE_OAUTH_TOKEN === undefined) {
			delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
		} else {
			process.env.CLAUDE_CODE_OAUTH_TOKEN = ORIGINAL_ENV.CLAUDE_CODE_OAUTH_TOKEN;
		}
		if (ORIGINAL_ENV.ANTHROPIC_API_KEY === undefined) {
			delete process.env.ANTHROPIC_API_KEY;
		} else {
			process.env.ANTHROPIC_API_KEY = ORIGINAL_ENV.ANTHROPIC_API_KEY;
		}
		vi.unstubAllGlobals();
	});

	it("injects oauth token when proxying", async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe("https://api.anthropic.com/v1/messages");
			const headers = new Headers(init?.headers);
			expect(headers.get("authorization")).toBe("Bearer oauth-token");
			return new Response(JSON.stringify({ ok: true }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		});
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/anthropic-proxy/v1/messages", "{}");
		expect(result.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it("rejects non-anthropic proxy paths", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(
			baseUrl,
			"/v1/anthropic-proxy/https://evil.example.com/",
			"{}",
		);
		expect(result.status).toBe(400);
		expect(fetchSpy).not.toHaveBeenCalled();
	});
});
