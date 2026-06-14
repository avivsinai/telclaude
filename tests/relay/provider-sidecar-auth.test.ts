import crypto from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";

import {
	buildProviderSidecarHmacHeaders,
	buildRequiredProviderSidecarRelayAuthHeaders,
	PROVIDER_SIDECAR_HMAC_SECRET_ENV,
} from "../../src/relay/provider-sidecar-auth.js";

describe("provider sidecar relay auth", () => {
	afterEach(() => {
		delete process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV];
		delete process.env.TELCLAUDE_ISRAEL_SIDECAR_HMAC_KEY_ID;
	});

	it("signs the agreed HMAC contract over the raw body bytes", () => {
		const rawBody = '{"service":"poalim","action":"balance","params":{}}';
		const timestampMs = 1_700_000_000_123;
		const nonce = "0123456789abcdef012345";
		const secret = "sidecar-hmac-secret-with-at-least-32-bytes";

		const headers = buildProviderSidecarHmacHeaders({
			keyId: "v1",
			method: "POST",
			path: "/v1/fetch",
			rawBody,
			secret,
			timestampMs,
			nonce,
		});

		const bodyHash = crypto.createHash("sha256").update(rawBody).digest("hex");
		const canonical = ["POST", "/v1/fetch", bodyHash, String(timestampMs), nonce].join("\n");
		const expectedSignature = crypto
			.createHmac("sha256", secret)
			.update(canonical)
			.digest("base64url");

		expect(headers).toEqual({
			"x-relay-key-id": "v1",
			"x-relay-timestamp": String(timestampMs),
			"x-relay-nonce": nonce,
			"x-relay-signature": expectedSignature,
		});
	});

	it("uses the fixed v1 key id even if an old key-id env var is present", async () => {
		process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] = "sidecar-hmac-secret-with-at-least-32-bytes";
		process.env.TELCLAUDE_ISRAEL_SIDECAR_HMAC_KEY_ID = "v2";

		const headers = await buildRequiredProviderSidecarRelayAuthHeaders({
			provider: {
				id: "israel-services",
				baseUrl: "https://israel-services.test",
				services: ["clalit"],
			},
			method: "GET",
			path: "/v1/fetch",
			rawBody: "",
		});

		expect(headers["x-relay-key-id"]).toBe("v1");
	});
});
