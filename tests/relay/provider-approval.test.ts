import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Reset the in-memory store between tests by re-importing
let createProviderApproval: typeof import("../../src/relay/provider-approval.js").createProviderApproval;
let consumeProviderApproval: typeof import("../../src/relay/provider-approval.js").consumeProviderApproval;
let isProviderApproval: typeof import("../../src/relay/provider-approval.js").isProviderApproval;
let describeProviderApproval: typeof import("../../src/relay/provider-approval.js").describeProviderApproval;

// Mock vault client and approval token generation
vi.mock("../../src/relay/approval-token.js", () => ({
	generateApprovalToken: vi.fn().mockResolvedValue("v1.mock-claims.mock-sig"),
}));

// Mock proxyProviderRequest to avoid real HTTP
vi.mock("../../src/relay/provider-proxy.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../src/relay/provider-proxy.js")>();
	return {
		...actual,
		proxyProviderRequest: vi.fn().mockResolvedValue({ status: "ok", data: { result: true } }),
	};
});

const mockRequest = {
	providerId: "google",
	path: "/v1/fetch",
	method: "POST",
	body: '{"service":"gmail","action":"create_draft","params":{"to":"a@b.com"}}',
	userId: "telegram:123",
};

const mockParsedBody = {
	service: "gmail",
	action: "create_draft",
	params: { to: "a@b.com" },
};

const mockVaultClient = {
	signPayload: vi.fn().mockResolvedValue({ type: "sign-payload", signature: "mock-sig" }),
} as any;

beforeEach(async () => {
	vi.resetModules();
	const mod = await import("../../src/relay/provider-approval.js");
	createProviderApproval = mod.createProviderApproval;
	consumeProviderApproval = mod.consumeProviderApproval;
	isProviderApproval = mod.isProviderApproval;
	describeProviderApproval = mod.describeProviderApproval;
});

describe("createProviderApproval", () => {
	it("returns a hex nonce", () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		expect(nonce).toMatch(/^[a-f0-9]{16}$/);
	});

	it("creates a recognizable pending approval", () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		expect(isProviderApproval(nonce)).toBe(true);
	});

	it("returns unique nonces", () => {
		const n1 = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		const n2 = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		expect(n1).not.toBe(n2);
	});
});

describe("isProviderApproval", () => {
	it("returns false for unknown nonce", () => {
		expect(isProviderApproval("deadbeef12345678")).toBe(false);
	});

	it("returns false for expired approval", async () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		// Simulate expiry by advancing time
		vi.useFakeTimers();
		vi.advanceTimersByTime(6 * 60 * 1000); // 6 minutes > 5 min TTL
		expect(isProviderApproval(nonce)).toBe(false);
		vi.useRealTimers();
	});
});

describe("describeProviderApproval", () => {
	it("returns service.action description", () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		expect(describeProviderApproval(nonce)).toBe("gmail.create_draft");
	});

	it("returns null for unknown nonce", () => {
		expect(describeProviderApproval("deadbeef12345678")).toBeNull();
	});
});

describe("consumeProviderApproval", () => {
	it("generates token, replays request, and returns result", async () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		const result = await consumeProviderApproval(nonce, mockVaultClient);

		expect(result).not.toBeNull();
		expect(result!.status).toBe("ok");
	});

	it("consumes the nonce (one-time use)", async () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		await consumeProviderApproval(nonce, mockVaultClient);

		// Second consume should return null
		const result2 = await consumeProviderApproval(nonce, mockVaultClient);
		expect(result2).toBeNull();
	});

	it("returns null for unknown nonce", async () => {
		const result = await consumeProviderApproval("deadbeef12345678", mockVaultClient);
		expect(result).toBeNull();
	});

	it("returns null for expired nonce", async () => {
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		vi.useFakeTimers();
		vi.advanceTimersByTime(6 * 60 * 1000);
		const result = await consumeProviderApproval(nonce, mockVaultClient);
		expect(result).toBeNull();
		vi.useRealTimers();
	});

	it("calls generateApprovalToken with correct args", async () => {
		const { generateApprovalToken } = await import("../../src/relay/approval-token.js");
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		await consumeProviderApproval(nonce, mockVaultClient);

		expect(generateApprovalToken).toHaveBeenCalledWith(
			expect.objectContaining({
				actorUserId: "telegram:123",
				service: "gmail",
				action: "create_draft",
				approvalNonce: nonce,
			}),
			mockVaultClient,
		);
	});

	it("replays original request with approval token", async () => {
		const { proxyProviderRequest } = await import("../../src/relay/provider-proxy.js");
		const nonce = createProviderApproval(mockRequest, mockParsedBody, "telegram:123");
		await consumeProviderApproval(nonce, mockVaultClient);

		expect(proxyProviderRequest).toHaveBeenCalledWith(
			expect.objectContaining({
				providerId: "google",
				path: "/v1/fetch",
				approvalToken: "v1.mock-claims.mock-sig",
			}),
		);
	});
});

describe("real CLI request shape roundtrip", () => {
	// provider-query sends: path=/v1/fetch, body={service,action,params}
	const cliRequest = {
		providerId: "google",
		path: "/v1/fetch",
		method: "POST",
		body: JSON.stringify({
			service: "gmail",
			action: "create_draft",
			params: { to: "user@example.com", subject: "Test", body: "Hello" },
		}),
		userId: "telegram:456",
	};

	it("preserves service/action from body in token claims", async () => {
		const { generateApprovalToken } = await import("../../src/relay/approval-token.js");
		const parsedBody = JSON.parse(cliRequest.body);
		const nonce = createProviderApproval(
			cliRequest,
			{ service: parsedBody.service, action: parsedBody.action, params: parsedBody.params },
			cliRequest.userId!,
		);
		await consumeProviderApproval(nonce, mockVaultClient);

		expect(generateApprovalToken).toHaveBeenCalledWith(
			expect.objectContaining({
				service: "gmail",
				action: "create_draft",
				actorUserId: "telegram:456",
			}),
			mockVaultClient,
		);
	});

	it("nonce roundtrip: create → check → consume → gone", async () => {
		const parsedBody = JSON.parse(cliRequest.body);
		const nonce = createProviderApproval(
			cliRequest,
			{ service: parsedBody.service, action: parsedBody.action, params: parsedBody.params },
			cliRequest.userId!,
		);

		// Check it exists
		expect(isProviderApproval(nonce)).toBe(true);
		expect(describeProviderApproval(nonce)).toBe("gmail.create_draft");

		// Consume it
		const result = await consumeProviderApproval(nonce, mockVaultClient);
		expect(result).not.toBeNull();
		expect(result!.status).toBe("ok");

		// Gone after consumption
		expect(isProviderApproval(nonce)).toBe(false);
		const result2 = await consumeProviderApproval(nonce, mockVaultClient);
		expect(result2).toBeNull();
	});
});
