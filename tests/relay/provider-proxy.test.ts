import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
			vi.fn(async () =>
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
		const fetchMock = vi.fn(async () =>
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
		const fetchMock = vi.fn(async () =>
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
			vi.fn(async () =>
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
