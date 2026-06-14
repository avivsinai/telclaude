import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PROVIDER_SIDECAR_HMAC_SECRET_ENV } from "../../src/relay/provider-sidecar-auth.js";

const loadConfigMock = vi.hoisted(() =>
	vi.fn(() => ({
		logging: {},
		providers: [{ id: "google", baseUrl: "https://provider.test" }],
	})),
);
const validateProviderBaseUrlMock = vi.hoisted(() => vi.fn());
const createProviderApprovalMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/config/config.js", () => ({
	loadConfig: loadConfigMock,
}));

vi.mock("../../src/providers/provider-validation.js", () => ({
	validateProviderBaseUrl: validateProviderBaseUrlMock,
}));

vi.mock("../../src/relay/provider-approval.js", () => ({
	createProviderApproval: createProviderApprovalMock,
}));

import { proxyProviderRequest } from "../../src/relay/provider-proxy.js";

describe("provider proxy approval interception", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		loadConfigMock.mockReturnValue({
			logging: {},
			providers: [{ id: "google", baseUrl: "https://provider.test" }],
		});
		validateProviderBaseUrlMock.mockResolvedValue({ url: new URL("https://provider.test") });
		createProviderApprovalMock.mockReturnValue("nonce-approval");
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							errorCode: "approval_required",
							error: "Action requires approval",
						}),
						{
							status: 403,
							headers: { "content-type": "application/json" },
						},
					),
			),
		);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("creates legacy approvals for interactive provider calls", async () => {
		await expect(
			proxyProviderRequest({
				providerId: "google",
				path: "/v1/fetch",
				body: JSON.stringify({
					service: "gmail",
					action: "create_draft",
					params: { to: "a@example.com" },
				}),
				userId: "operator",
			}),
		).resolves.toMatchObject({
			status: "error",
			errorCode: "approval_required",
			approvalNonce: "nonce-approval",
		});

		expect(createProviderApprovalMock).toHaveBeenCalledTimes(1);
	});

	it("does not create legacy approvals for Hermes ledger-originated executes", async () => {
		await expect(
			proxyProviderRequest({
				providerId: "google",
				path: "/v1/fetch",
				body: JSON.stringify({
					service: "gmail",
					action: "create_draft",
					params: { to: "a@example.com" },
				}),
				userId: "operator",
				approvalToken: "v1.sidecar.claims.sig",
				approvalMode: "preapproved-ledger",
			}),
		).resolves.toMatchObject({
			status: "error",
			errorCode: "approval_required",
			error: "Action requires approval",
		});

		expect(createProviderApprovalMock).not.toHaveBeenCalled();
	});

	it("does not expose provider challenge interaction URLs or visual payloads to callers", async () => {
		const opaqueFrame = Buffer.from("login-page-capture".repeat(64)).toString("base64");
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							status: "challenge_pending",
							message: "Open the secure browser challenge.",
							interactUrl: "https://operator-console.test/session/secret",
							challenge: {
								challengeId: "challenge-1",
								interactUrl: "https://operator-console.test/session/secret",
								screenshot: "base64-screenshot",
								preview: { html: "<form>secret</form>" },
								snapshotFrame: opaqueFrame,
							},
						}),
						{
							status: 202,
							headers: { "content-type": "application/json" },
						},
					),
			),
		);

		const result = await proxyProviderRequest({
			providerId: "google",
			path: "/v1/fetch",
			body: JSON.stringify({ service: "gmail", action: "search", params: {} }),
			userId: "operator",
		});

		const serialized = JSON.stringify(result);
		expect(result).toMatchObject({
			status: "error",
			errorCode: "challenge_pending",
			error: "Provider challenge pending; check the relay-rendered operator prompt.",
			data: {
				status: "challenge_pending",
				message: "Open the secure browser challenge.",
				challenge: { challengeId: "challenge-1" },
			},
		});
		expect(serialized).not.toContain("operator-console.test");
		expect(serialized).not.toContain("base64-screenshot");
		expect(serialized).not.toContain("<form>");
		expect(serialized).not.toContain(opaqueFrame);
	});

	it("redacts embedded interactive bearer URLs from HTTP 202 challenge strings", async () => {
		const marker = "embedded-202-marker";
		const tokenQuery = new URLSearchParams([["token", marker]]).toString();
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							status: "challenge_pending",
							message: `Open https://operator-console.test/novnc?${tokenQuery} to continue.`,
							challenge: { challengeId: "challenge-202" },
						}),
						{
							status: 202,
							headers: { "content-type": "application/json" },
						},
					),
			),
		);

		const result = await proxyProviderRequest({
			providerId: "google",
			path: "/v1/fetch",
			body: JSON.stringify({ service: "gmail", action: "search", params: {} }),
			userId: "operator",
		});

		const serialized = JSON.stringify(result);
		expect(result).toMatchObject({
			status: "error",
			errorCode: "challenge_pending",
			data: {
				status: "challenge_pending",
				challenge: { challengeId: "challenge-202" },
			},
		});
		expect(serialized).not.toContain(marker);
		expect(serialized).not.toContain("operator-console.test");
		expect(serialized).not.toContain("message");
	});

	it("redacts interactive bearer URLs from generic provider read challenge responses", async () => {
		const marker = "provider-redaction-marker";
		const tokenQuery = new URLSearchParams([["token", marker]]).toString();
		const sessionTokenQuery = new URLSearchParams([["session_token", marker]]).toString();
		const authTokenQuery = new URLSearchParams([["auth_token", marker]]).toString();
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							status: "challenge_pending",
							challengeRef: "challenge:poalim:read:123",
							message: `Open https://operator-console.test/novnc?${tokenQuery} to continue.`,
							interactUrl: `https://operator-console.test/novnc?${tokenQuery}`,
							challenge: {
								challengeId: "challenge-1",
								noVncUrl: `https://operator-console.test/vnc?${sessionTokenQuery}`,
								controlUrl: `https://operator-console.test/v1/challenge/interactive/abc/respond?${tokenQuery}`,
								pathTokenUrl:
									"https://operator-console.test/v1/challenge/interactive/opaqueSingleUseToken123/respond",
								links: [
									`https://operator-console.test/browser/session?${authTokenQuery}`,
									{ label: "public help", url: "https://help.example.com/article" },
								],
							},
						}),
						{
							status: 200,
							headers: { "content-type": "application/json" },
						},
					),
			),
		);

		const result = await proxyProviderRequest({
			providerId: "google",
			path: "/v1/fetch",
			body: JSON.stringify({ service: "gmail", action: "search", params: {} }),
			userId: "operator",
		});

		const serialized = JSON.stringify(result);
		expect(result).toMatchObject({
			status: "error",
			errorCode: "challenge_pending",
			error: "Provider challenge pending; check the relay-rendered operator prompt.",
			data: {
				status: "challenge_pending",
				challengeRef: "challenge:poalim:read:123",
				challenge: {
					challengeId: "challenge-1",
					links: [{ label: "public help", url: "https://help.example.com/article" }],
				},
			},
		});
		expect(serialized).not.toContain(marker);
		expect(serialized).not.toContain("opaqueSingleUseToken123");
		expect(serialized).not.toContain("operator-console.test");
		expect(serialized).not.toContain("noVncUrl");
		expect(serialized).not.toContain("message");
	});

	it("redacts embedded interactive bearer URLs from provider error strings", async () => {
		const marker = "error-path-marker";
		const tokenQuery = new URLSearchParams([["session_token", marker]]).toString();
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							errorCode: "provider_failed",
							error: `Provider needs login at https://operator-console.test/browser/session?${tokenQuery}.`,
						}),
						{
							status: 500,
							headers: { "content-type": "application/json" },
						},
					),
			),
		);

		const result = await proxyProviderRequest({
			providerId: "google",
			path: "/v1/fetch",
			body: JSON.stringify({ service: "gmail", action: "search", params: {} }),
			userId: "operator",
		});

		const serialized = JSON.stringify(result);
		expect(result).toEqual({
			status: "error",
			errorCode: "provider_failed",
			error: "Provider error: 500",
		});
		expect(serialized).not.toContain(marker);
		expect(serialized).not.toContain("operator-console.test");
	});

	it("redacts embedded interactive bearer URLs from approval-required errors", async () => {
		const marker = "approval-error-marker";
		const tokenQuery = new URLSearchParams([["auth_token", marker]]).toString();
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({
							errorCode: "approval_required",
							error: `Approve after opening https://operator-console.test/vnc?${tokenQuery}.`,
						}),
						{
							status: 403,
							headers: { "content-type": "application/json" },
						},
					),
			),
		);

		const result = await proxyProviderRequest({
			providerId: "google",
			path: "/v1/fetch",
			body: JSON.stringify({
				service: "gmail",
				action: "create_draft",
				params: { to: "a@example.com" },
			}),
			userId: "operator",
		});

		const serialized = JSON.stringify(result);
		expect(result).toEqual({
			status: "error",
			errorCode: "approval_required",
			error: "Action requires approval",
			approvalNonce: "nonce-approval",
		});
		expect(serialized).not.toContain(marker);
		expect(serialized).not.toContain("operator-console.test");
	});

	it("routes canonical provider domains through a matching configured service", async () => {
		loadConfigMock.mockReturnValue({
			logging: {},
			providers: [
				{
					id: "israel-services",
					baseUrl: "https://israel-services.test",
					services: ["clalit", "poalim"],
				},
			],
		});
		validateProviderBaseUrlMock.mockResolvedValue({
			url: new URL("https://israel-services.test"),
		});
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ appointments: [{ id: "appt-1" }] }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			proxyProviderRequest({
				providerId: "clalit",
				path: "/v1/fetch",
				body: JSON.stringify({
					service: "clalit",
					action: "appointments.list",
					params: {},
				}),
				userId: "operator",
			}),
		).resolves.toEqual({
			status: "ok",
			data: { appointments: [{ id: "appt-1" }] },
		});

		expect(validateProviderBaseUrlMock).toHaveBeenCalledWith("https://israel-services.test");
		expect(fetchMock).toHaveBeenCalledWith(
			"https://israel-services.test/v1/fetch",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({
					service: "clalit",
					action: "appointments.list",
					params: {},
				}),
			}),
		);
	});

	it("routes canonical bank through the configured poalim connector alias", async () => {
		loadConfigMock.mockReturnValue({
			logging: {},
			providers: [
				{
					id: "israel-services",
					baseUrl: "https://israel-services.test",
					services: ["clalit", "poalim"],
				},
			],
		});
		validateProviderBaseUrlMock.mockResolvedValue({
			url: new URL("https://israel-services.test"),
		});
		const fetchMock = vi.fn(
			async () =>
				new Response(JSON.stringify({ balances: [{ accountId: "primary" }] }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(
			proxyProviderRequest({
				providerId: "bank",
				path: "/v1/fetch",
				body: JSON.stringify({
					service: "bank",
					action: "balance",
					params: {},
				}),
				userId: "operator",
			}),
		).resolves.toEqual({
			status: "ok",
			data: { balances: [{ accountId: "primary" }] },
		});

		expect(validateProviderBaseUrlMock).toHaveBeenCalledWith("https://israel-services.test");
		expect(fetchMock).toHaveBeenCalledWith(
			"https://israel-services.test/v1/fetch",
			expect.objectContaining({
				method: "POST",
				body: JSON.stringify({
					service: "poalim",
					action: "balance",
					params: {},
				}),
			}),
		);
	});

	it("signs israel-services requests over the exact rewritten body bytes", async () => {
		const previousSecret = process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV];
		process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] =
			"relay-sidecar-hmac-secret-with-at-least-32-bytes";
		try {
			loadConfigMock.mockReturnValue({
				logging: {},
				providers: [
					{
						id: "israel-services",
						baseUrl: "https://israel-services.test",
						services: ["poalim"],
					},
				],
			});
			validateProviderBaseUrlMock.mockResolvedValue({
				url: new URL("https://israel-services.test"),
			});
			const fetchMock = vi.fn(
				async () =>
					new Response(JSON.stringify({ balances: [{ accountId: "primary" }] }), {
						status: 200,
						headers: { "content-type": "application/json" },
					}),
			);
			vi.stubGlobal("fetch", fetchMock);

			const originalBody = JSON.stringify({
				service: "bank",
				action: "balance",
				params: {},
			});
			const rewrittenBody = JSON.stringify({
				service: "poalim",
				action: "balance",
				params: {},
			});

			await expect(
				proxyProviderRequest({
					providerId: "bank",
					path: "/v1/fetch",
					body: originalBody,
					userId: "operator",
				}),
			).resolves.toMatchObject({ status: "ok" });

			const [, init] = fetchMock.mock.calls[0];
			const headers = init?.headers as Record<string, string>;
			const timestamp = headers["x-relay-timestamp"];
			const nonce = headers["x-relay-nonce"];
			const bodyHash = crypto.createHash("sha256").update(rewrittenBody).digest("hex");
			const canonical = ["POST", "/v1/fetch", bodyHash, timestamp, nonce].join("\n");
			const expectedSignature = crypto
				.createHmac("sha256", process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] ?? "")
				.update(canonical)
				.digest("base64url");

			expect(init?.body).toBe(rewrittenBody);
			expect(headers["x-relay-key-id"]).toBe("v1");
			expect(headers["x-relay-signature"]).toBe(expectedSignature);
		} finally {
			if (previousSecret === undefined) {
				delete process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV];
			} else {
				process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV] = previousSecret;
			}
		}
	});

	it("prefers exact provider id matches over service membership matches", async () => {
		loadConfigMock.mockReturnValue({
			logging: {},
			providers: [
				{
					id: "israel-services",
					baseUrl: "https://israel-services.test",
					services: ["google"],
				},
				{ id: "google", baseUrl: "https://google-services.test", services: ["gmail"] },
			],
		});
		validateProviderBaseUrlMock.mockResolvedValue({
			url: new URL("https://google-services.test"),
		});
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(JSON.stringify({ messages: [] }), {
						status: 200,
						headers: { "content-type": "application/json" },
					}),
			),
		);

		await expect(
			proxyProviderRequest({
				providerId: "google",
				path: "/v1/fetch",
				body: JSON.stringify({ service: "gmail", action: "search", params: {} }),
				userId: "operator",
			}),
		).resolves.toMatchObject({ status: "ok" });

		expect(validateProviderBaseUrlMock).toHaveBeenCalledWith("https://google-services.test");
	});
});
