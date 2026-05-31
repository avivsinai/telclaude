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
});
