import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PROVIDER_SIDECAR_HMAC_SECRET_ENV } from "../../src/relay/provider-sidecar-auth.js";

const loadConfigMock = vi.hoisted(() =>
	vi.fn(() => ({
		logging: {},
		providers: [
			{
				id: "israel-services",
				baseUrl: "https://israel-services.test",
				services: ["clalit"],
			},
		],
	})),
);
const validateProviderBaseUrlMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/config/config.js", () => ({
	loadConfig: loadConfigMock,
}));

vi.mock("../../src/providers/provider-validation.js", () => ({
	validateProviderBaseUrl: validateProviderBaseUrlMock,
}));

import {
	pollProviderSessionEnrollment,
	startProviderSessionEnrollment,
} from "../../src/relay/provider-enrollment.js";

describe("provider enrollment relay client", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] =
			"relay-sidecar-hmac-secret-with-at-least-32-bytes";
		loadConfigMock.mockReturnValue({
			providers: [
				{
					id: "israel-services",
					baseUrl: "https://israel-services.test",
					services: ["clalit"],
				},
			],
		});
		validateProviderBaseUrlMock.mockResolvedValue({ url: new URL("https://israel-services.test") });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		delete process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV];
	});

	it("starts session enrollment with HMAC over the exact request body", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(
					JSON.stringify({
						status: "enroll_pending",
						enrollmentId: "enr_123",
						interactUrl: "https://novnc.test/?token=single-use",
						expiresAt: 1_700_000_100_000,
						pollPath: "/v1/credentials/enroll-session/enr_123",
					}),
					{ status: 202, headers: { "content-type": "application/json" } },
				),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			startProviderSessionEnrollment({
				service: "clalit",
				subjectUserId: "admin",
				actorUserId: "453371121",
			}),
		).resolves.toMatchObject({
			status: "enroll_pending",
			enrollmentId: "enr_123",
			pollPath: "/v1/credentials/enroll-session/enr_123",
		});

		const [, init] = fetchMock.mock.calls[0];
		const body = JSON.stringify({ service: "clalit", subjectUserId: "admin" });
		const headers = init?.headers as Record<string, string>;
		const canonical = [
			"POST",
			"/v1/credentials/enroll-session",
			crypto.createHash("sha256").update(body).digest("hex"),
			headers["x-relay-timestamp"],
			headers["x-relay-nonce"],
		].join("\n");
		const expectedSignature = crypto
			.createHmac("sha256", process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] ?? "")
			.update(canonical)
			.digest("base64url");

		expect(fetchMock).toHaveBeenCalledWith(
			"https://israel-services.test/v1/credentials/enroll-session",
			expect.objectContaining({
				method: "POST",
				body,
			}),
		);
		expect(headers["x-actor-user-id"]).toBe("453371121");
		expect(headers["x-relay-key-id"]).toBe("v1");
		expect(headers["x-relay-signature"]).toBe(expectedSignature);
	});

	it("polls enrollment status with an empty-body HMAC", async () => {
		const fetchMock = vi.fn(
			async () =>
				new Response(
					JSON.stringify({
						status: "ok",
						summary: {
							service: "clalit",
							owner: "admin",
							authorizedOperators: ["453371121"],
							credentialKeys: [],
							hasSession: true,
							updatedAt: "2026-06-13T20:45:00.000Z",
						},
					}),
					{ status: 200, headers: { "content-type": "application/json" } },
				),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			pollProviderSessionEnrollment({
				service: "clalit",
				pollPath: "/v1/credentials/enroll-session/enr_123",
				actorUserId: "453371121",
			}),
		).resolves.toMatchObject({
			status: "ok",
			summary: { service: "clalit", owner: "admin", hasSession: true },
		});

		const [, init] = fetchMock.mock.calls[0];
		const headers = init?.headers as Record<string, string>;
		const canonical = [
			"GET",
			"/v1/credentials/enroll-session/enr_123",
			crypto.createHash("sha256").update("").digest("hex"),
			headers["x-relay-timestamp"],
			headers["x-relay-nonce"],
		].join("\n");
		const expectedSignature = crypto
			.createHmac("sha256", process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] ?? "")
			.update(canonical)
			.digest("base64url");

		expect(init?.body).toBeUndefined();
		expect(headers["x-relay-signature"]).toBe(expectedSignature);
	});
});
