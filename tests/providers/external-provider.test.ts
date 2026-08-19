import crypto from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	PROVIDER_SIDECAR_HMAC_SECRET_ENV,
	resetProviderSidecarHmacSecretCacheForTests,
} from "../../src/relay/provider-sidecar-auth.js";

const loadConfigMock = vi.hoisted(() => vi.fn(() => ({ logging: {}, providers: [] })));
const validateProviderBaseUrlMock = vi.hoisted(() => vi.fn());
const getSecretMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/config/config.js", () => ({
	loadConfig: loadConfigMock,
}));

vi.mock("../../src/providers/provider-validation.js", () => ({
	validateProviderBaseUrl: validateProviderBaseUrlMock,
}));

vi.mock("../../src/vault-daemon/client.js", () => ({
	getVaultClient: () => ({ getSecret: getSecretMock }),
}));

import { sendProviderOtp } from "../../src/providers/external-provider.js";

const provider = {
	id: "israel-services",
	baseUrl: "https://israel-services.test",
	services: ["clalit"],
};
const secret = "provider-sidecar-hmac-secret-with-at-least-32-bytes";

describe("external provider OTP transport", () => {
	beforeEach(() => {
		loadConfigMock.mockReturnValue({ providers: [provider] });
		validateProviderBaseUrlMock.mockResolvedValue({ url: new URL(provider.baseUrl) });
		getSecretMock.mockResolvedValue({ ok: false, type: "error" });
		process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] = secret;
		resetProviderSidecarHmacSecretCacheForTests();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		delete process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV];
		resetProviderSidecarHmacSecretCacheForTests();
		vi.clearAllMocks();
	});

	it("sends the exact challenge body with relay HMAC and actor-bound headers", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ status: "ok" }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			sendProviderOtp({
				service: "clalit",
				challengeId: "challenge-1",
				code: "123456",
				actorUserId: "555",
				requestId: "req-otp",
			}),
		).resolves.toEqual({ status: "ok" });

		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const rawBody = JSON.stringify({
			service: "clalit",
			challengeId: "challenge-1",
			code: "123456",
		});
		const headers = new Headers(init.headers);
		const timestamp = headers.get("x-relay-timestamp");
		const nonce = headers.get("x-relay-nonce");
		expect(url).toBe("https://israel-services.test/v1/challenge/respond");
		expect(init.method).toBe("POST");
		expect(init.body).toBe(rawBody);
		expect(headers.get("accept")).toBe("application/json");
		expect(headers.get("content-type")).toBe("application/json");
		expect(headers.get("x-relay-proxy")).toBe("true");
		expect(headers.get("x-actor-user-id")).toBe("555");
		expect(headers.get("x-request-id")).toBe("req-otp");
		expect(headers.get("x-relay-key-id")).toBe("v1");
		expect(headers.get("x-relay-signature")).toBeTruthy();
		expect(headers.get("x-relay-actor-signature")).toBeTruthy();
		if (!timestamp || !nonce) throw new Error("expected signed request metadata");

		const bodyHash = crypto.createHash("sha256").update(rawBody).digest("hex");
		const canonical = ["POST", "/v1/challenge/respond", bodyHash, timestamp, nonce].join("\n");
		const expectedSignature = crypto
			.createHmac("sha256", secret)
			.update(canonical)
			.digest("base64url");
		const expectedActorSignature = crypto
			.createHmac("sha256", secret)
			.update(`${canonical}\nACTOR\n555`)
			.digest("base64url");
		expect(headers.get("x-relay-signature")).toBe(expectedSignature);
		expect(headers.get("x-relay-actor-signature")).toBe(expectedActorSignature);
		expect(JSON.parse(String(init.body))).not.toHaveProperty("actorUserId");
	});

	it("fails closed before sending when the sidecar HMAC secret is unavailable", async () => {
		delete process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV];
		resetProviderSidecarHmacSecretCacheForTests();
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			sendProviderOtp({
				service: "clalit",
				code: "123456",
				actorUserId: "555",
			}),
		).rejects.toThrow("Provider sidecar HMAC secret is not configured");
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
