import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const vaultClientMock = vi.hoisted(() => ({
	getSecret: vi.fn(),
	store: vi.fn(),
}));
const isVaultAvailableMock = vi.hoisted(() => vi.fn());
const loggerMock = vi.hoisted(() => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
}));

vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => loggerMock,
}));

vi.mock("../../src/vault-daemon/client.js", () => ({
	getVaultClient: () => vaultClientMock,
	isVaultAvailable: isVaultAvailableMock,
}));

import {
	resetAnthropicOauthState,
	startAnthropicOauthRefreshScheduler,
} from "../../src/relay/anthropic-proxy.js";
import { startCapabilityServer } from "../../src/relay/capabilities.js";

const ORIGINAL_ENV = {
	CLAUDE_CODE_OAUTH_TOKEN: process.env.CLAUDE_CODE_OAUTH_TOKEN,
	ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
	ANTHROPIC_PROXY_TOKEN: process.env.ANTHROPIC_PROXY_TOKEN,
};

type RequestResult = { status: number; body: string };

function makeRequest(
	baseUrl: string,
	path: string,
	body?: string,
	method: string = "POST",
	headers: Record<string, string> = {},
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
					...headers,
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
		process.env.ANTHROPIC_PROXY_TOKEN = "proxy-token";
		isVaultAvailableMock.mockReset().mockResolvedValue(false);
		vaultClientMock.getSecret.mockReset();
		vaultClientMock.store.mockReset();
		loggerMock.info.mockReset();
		loggerMock.warn.mockReset();
		loggerMock.error.mockReset();
		loggerMock.debug.mockReset();

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
		if (ORIGINAL_ENV.ANTHROPIC_PROXY_TOKEN === undefined) {
			delete process.env.ANTHROPIC_PROXY_TOKEN;
		} else {
			process.env.ANTHROPIC_PROXY_TOKEN = ORIGINAL_ENV.ANTHROPIC_PROXY_TOKEN;
		}
		resetAnthropicOauthState();
		vi.useRealTimers();
		vi.unstubAllGlobals();
	});

	it("injects oauth token when proxying", async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe("https://api.anthropic.com/v1/messages");
			const headers = new Headers(init?.headers);
			expect(headers.get("authorization")).toBe("Bearer oauth-token");
			expect(headers.get("anthropic-beta")).toBe("oauth-2025-04-20");
			return new Response(JSON.stringify({ ok: true }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		});
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/anthropic-proxy/v1/messages", "{}", "POST", {
			Authorization: "Bearer proxy-token",
		});
		expect(result.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it("falls back to env oauth when the vault secret is missing", async () => {
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getSecret.mockResolvedValue({
			ok: false,
			type: "get-secret",
			error: "not_found",
		});

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

		const result = await makeRequest(baseUrl, "/v1/anthropic-proxy/v1/messages", "{}", "POST", {
			Authorization: "Bearer proxy-token",
		});
		expect(result.status).toBe(200);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(
			loggerMock.info.mock.calls.find((call) => call[1] === "proxying to Anthropic")?.[0],
		).toMatchObject({
			authSource: "env-oauth",
		});
	});

	it("returns the vault-backed oauth token from the dedicated token endpoint", async () => {
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getSecret.mockResolvedValue({
			ok: true,
			type: "get-secret",
			value: JSON.stringify({
				accessToken: "vault-access-token",
				refreshToken: "refresh-123",
				expiresAt: Date.now() + 60 * 60 * 1000,
				scopes: ["user:inference"],
			}),
		});

		const result = await makeRequest(baseUrl, "/v1/token/anthropic", undefined, "GET", {
			"x-proxy-token": "proxy-token",
		});
		expect(result.status).toBe(200);
		expect(result.body).toBe("vault-access-token");
	});

	it("returns the env oauth token when the vault secret is missing", async () => {
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getSecret.mockResolvedValue({
			ok: false,
			type: "get-secret",
			error: "not_found",
		});

		const result = await makeRequest(baseUrl, "/v1/token/anthropic", undefined, "GET", {
			"x-proxy-token": "proxy-token",
		});
		expect(result.status).toBe(200);
		expect(result.body).toBe("oauth-token");
	});

	it("rejects invalid proxy token on the dedicated token endpoint", async () => {
		const result = await makeRequest(baseUrl, "/v1/token/anthropic", undefined, "GET", {
			"x-proxy-token": "wrong-token",
		});
		expect(result.status).toBe(401);
	});

	it("rejects non-anthropic proxy paths", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(
			baseUrl,
			"/v1/anthropic-proxy/https://evil.example.com/",
			"{}",
			"POST",
			{ Authorization: "Bearer proxy-token" },
		);
		expect(result.status).toBe(400);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("rejects path traversal segments", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/anthropic-proxy/v1/../models", "{}", "POST", {
			Authorization: "Bearer proxy-token",
		});
		expect(result.status).toBe(400);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("proactively refreshes near-expiry vault oauth tokens", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-03-29T12:00:00Z"));
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getSecret.mockResolvedValue({
			ok: true,
			type: "get-secret",
			value: JSON.stringify({
				accessToken: "stale-access",
				refreshToken: "refresh-123",
				expiresAt: Date.now() + 4 * 60 * 1000,
				scopes: ["user:inference"],
			}),
		});
		vaultClientMock.store.mockResolvedValue({ type: "store", ok: true });

		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe("https://platform.claude.com/v1/oauth/token");
			expect(JSON.parse(String(init?.body))).toMatchObject({
				grant_type: "refresh_token",
				refresh_token: "refresh-123",
			});
			return new Response(
				JSON.stringify({
					access_token: "fresh-access",
					refresh_token: "fresh-refresh",
					expires_in: 3600,
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			);
		});
		vi.stubGlobal("fetch", fetchSpy);

		const scheduler = startAnthropicOauthRefreshScheduler({ intervalMs: 60_000 });
		await vi.advanceTimersByTimeAsync(0);

		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(vaultClientMock.store).toHaveBeenCalledTimes(1);
		expect(vaultClientMock.store).toHaveBeenCalledWith(
			expect.objectContaining({
				protocol: "secret",
				target: "anthropic-oauth",
				label: "Anthropic OAuth (auto-refreshed)",
			}),
		);
		const storedValue = vaultClientMock.store.mock.calls[0]?.[0]?.credential?.value;
		expect(JSON.parse(String(storedValue))).toMatchObject({
			accessToken: "fresh-access",
			refreshToken: "fresh-refresh",
		});

		scheduler.stop();
	});

	it("refreshes near-expiry oauth tokens through the dedicated token endpoint", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-03-29T12:00:00Z"));
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getSecret.mockResolvedValue({
			ok: true,
			type: "get-secret",
			value: JSON.stringify({
				accessToken: "stale-access",
				refreshToken: "refresh-123",
				expiresAt: Date.now() + 4 * 60 * 1000,
				scopes: ["user:inference"],
			}),
		});
		vaultClientMock.store.mockResolvedValue({ type: "store", ok: true });

		const fetchSpy = vi.fn(async () => {
			return new Response(
				JSON.stringify({
					access_token: "fresh-access",
					refresh_token: "fresh-refresh",
					expires_in: 3600,
				}),
				{ status: 200, headers: { "Content-Type": "application/json" } },
			);
		});
		vi.stubGlobal("fetch", fetchSpy);

		const result = await makeRequest(baseUrl, "/v1/token/anthropic", undefined, "GET", {
			"x-proxy-token": "proxy-token",
		});
		expect(result.status).toBe(200);
		expect(result.body).toBe("fresh-access");
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(vaultClientMock.store).toHaveBeenCalledTimes(1);
	});

	it("skips proactive refresh when vault oauth is still fresh", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-03-29T12:00:00Z"));
		isVaultAvailableMock.mockResolvedValue(true);
		vaultClientMock.getSecret.mockResolvedValue({
			ok: true,
			type: "get-secret",
			value: JSON.stringify({
				accessToken: "fresh-access",
				refreshToken: "refresh-123",
				expiresAt: Date.now() + 60 * 60 * 1000,
				scopes: ["user:inference"],
			}),
		});

		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);

		const scheduler = startAnthropicOauthRefreshScheduler({ intervalMs: 60_000 });
		await vi.advanceTimersByTimeAsync(0);
		await vi.advanceTimersByTimeAsync(60_000);

		expect(fetchSpy).not.toHaveBeenCalled();
		expect(vaultClientMock.store).not.toHaveBeenCalled();

		scheduler.stop();
	});
});
