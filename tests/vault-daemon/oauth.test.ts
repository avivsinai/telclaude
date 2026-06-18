import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearTokenCache, getAccessToken } from "../../src/vault-daemon/oauth.js";

describe("vault oauth refresh", () => {
	beforeEach(() => {
		clearTokenCache();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("omits client_secret for public-client OAuth refresh", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				access_token: "access-token",
				token_type: "bearer",
				expires_in: 3600,
			}),
		});
		vi.stubGlobal("fetch", fetchMock);

		const result = await getAccessToken("api.example.com", {
			type: "oauth2",
			clientId: "public-client",
			refreshToken: "refresh-token",
			tokenEndpoint: "https://oauth2.example.com/token",
		});

		expect(result.ok).toBe(true);
		expect(fetchMock).toHaveBeenCalledOnce();
		const [, options] = fetchMock.mock.calls[0];
		const body = new URLSearchParams(options.body as string);
		expect(options.headers).toEqual({ "Content-Type": "application/x-www-form-urlencoded" });
		expect(body.get("client_id")).toBe("public-client");
		expect(body.get("refresh_token")).toBe("refresh-token");
		expect(body.has("client_secret")).toBe(false);
	});

	it("uses JSON refresh bodies for providers that require them", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({
				access_token: "access-token",
				token_type: "bearer",
				expires_in: 3600,
			}),
		});
		vi.stubGlobal("fetch", fetchMock);

		const result = await getAccessToken("openai-codex", {
			type: "oauth2",
			clientId: "public-client",
			refreshToken: "refresh-token",
			tokenEndpoint: "https://auth.openai.com/oauth/token",
			tokenRequestFormat: "json",
		});

		expect(result.ok).toBe(true);
		expect(fetchMock).toHaveBeenCalledOnce();
		const [, options] = fetchMock.mock.calls[0];
		expect(options.headers).toEqual({ "Content-Type": "application/json" });
		expect(JSON.parse(options.body as string)).toEqual({
			grant_type: "refresh_token",
			client_id: "public-client",
			refresh_token: "refresh-token",
		});
	});
});
