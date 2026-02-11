/**
 * Tests for OAuth2 authorization flow.
 *
 * Mocks oauth-callback and fetch to test flow logic without network/browser.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock oauth-callback
vi.mock("oauth-callback", () => ({
	getAuthCode: vi.fn(),
	getRedirectUrl: vi.fn((opts?: { port?: number }) => `http://localhost:${opts?.port ?? 3000}/callback`),
}));

// Mock open (browser launcher)
vi.mock("open", () => ({
	default: vi.fn(),
}));

import { getAuthCode } from "oauth-callback";
import { authorize, getCallbackUrl } from "../../src/oauth/flow.js";
import type { OAuth2ServiceDefinition } from "../../src/oauth/registry.js";

const mockGetAuthCode = vi.mocked(getAuthCode);

// Test service definition
const testService: OAuth2ServiceDefinition = {
	id: "test",
	displayName: "Test Service",
	authorizationUrl: "https://auth.example.com/authorize",
	tokenEndpoint: "https://auth.example.com/token",
	defaultScopes: ["read", "write"],
	confidentialClient: true,
	vaultTarget: "api.example.com",
	vaultLabel: "Test OAuth2",
};

// Shared fetch mock setup
function mockFetch(response: Record<string, unknown>, status = 200) {
	return vi.fn().mockResolvedValue({
		ok: status >= 200 && status < 300,
		status,
		json: async () => response,
		text: async () => JSON.stringify(response),
	});
}

describe("OAuth2 Flow", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	describe("getCallbackUrl", () => {
		it("should return localhost callback URL with port", () => {
			expect(getCallbackUrl(3000)).toBe("http://localhost:3000/callback");
			expect(getCallbackUrl(8080)).toBe("http://localhost:8080/callback");
		});
	});

	describe("authorize", () => {
		it("should complete the full flow successfully", async () => {
			// Mock oauth-callback to return a valid code + matching state
			mockGetAuthCode.mockImplementation(async (opts) => {
				// Extract state from the authorization URL
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					const state = url.searchParams.get("state");
					return { code: "test-auth-code", state: state ?? undefined };
				}
				return { code: "test-auth-code" };
			});

			// Mock token exchange
			const fetchMock = mockFetch({
				access_token: "access-123",
				refresh_token: "refresh-456",
				expires_in: 7200,
				scope: "read write",
				token_type: "bearer",
			});
			vi.stubGlobal("fetch", fetchMock);

			const result = await authorize({
				service: testService,
				clientId: "client-id",
				clientSecret: "client-secret",
				launch: vi.fn(),
			});

			expect(result.accessToken).toBe("access-123");
			expect(result.refreshToken).toBe("refresh-456");
			expect(result.expiresIn).toBe(7200);
			expect(result.scope).toBe("read write");
		});

		it("should send PKCE code_verifier in token exchange", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "auth-code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "auth-code" };
			});

			const fetchMock = mockFetch({
				access_token: "at",
				refresh_token: "rt",
				expires_in: 3600,
				token_type: "bearer",
			});
			vi.stubGlobal("fetch", fetchMock);

			await authorize({
				service: testService,
				clientId: "cid",
				clientSecret: "csec",
				launch: vi.fn(),
			});

			// Verify token exchange request
			expect(fetchMock).toHaveBeenCalledOnce();
			const [url, options] = fetchMock.mock.calls[0];
			expect(url).toBe("https://auth.example.com/token");
			expect(options.method).toBe("POST");

			// Verify PKCE verifier is in body
			const body = new URLSearchParams(options.body);
			expect(body.get("code_verifier")).toBeTruthy();
			expect(body.get("code_verifier")!.length).toBeGreaterThanOrEqual(43);
			expect(body.get("grant_type")).toBe("authorization_code");
			expect(body.get("code")).toBe("auth-code");
		});

		it("should use Basic auth for confidential clients", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			const fetchMock = mockFetch({
				access_token: "at",
				refresh_token: "rt",
				expires_in: 3600,
				token_type: "bearer",
			});
			vi.stubGlobal("fetch", fetchMock);

			await authorize({
				service: { ...testService, confidentialClient: true },
				clientId: "my-client",
				clientSecret: "my-secret",
				launch: vi.fn(),
			});

			const [, options] = fetchMock.mock.calls[0];
			const authHeader = options.headers.Authorization;
			expect(authHeader).toBe(`Basic ${Buffer.from("my-client:my-secret").toString("base64")}`);

			// client_id should NOT be in body for confidential clients
			const body = new URLSearchParams(options.body);
			expect(body.has("client_id")).toBe(false);
		});

		it("should put client_id in body for public clients", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			const fetchMock = mockFetch({
				access_token: "at",
				refresh_token: "rt",
				expires_in: 3600,
				token_type: "bearer",
			});
			vi.stubGlobal("fetch", fetchMock);

			await authorize({
				service: { ...testService, confidentialClient: false },
				clientId: "public-client",
				clientSecret: "",
				launch: vi.fn(),
			});

			const [, options] = fetchMock.mock.calls[0];
			expect(options.headers.Authorization).toBeUndefined();

			const body = new URLSearchParams(options.body);
			expect(body.get("client_id")).toBe("public-client");
		});

		it("should fail on state mismatch", async () => {
			mockGetAuthCode.mockResolvedValue({
				code: "auth-code",
				state: "wrong-state-value",
			});

			await expect(
				authorize({
					service: testService,
					clientId: "cid",
					clientSecret: "csec",
					launch: vi.fn(),
				}),
			).rejects.toThrow("State mismatch");
		});

		it("should fail when no authorization code received", async () => {
			mockGetAuthCode.mockResolvedValue({
				error: "access_denied",
				error_description: "User denied access",
			});

			await expect(
				authorize({
					service: testService,
					clientId: "cid",
					clientSecret: "csec",
					launch: vi.fn(),
				}),
			).rejects.toThrow("User denied access");
		});

		it("should fail when token endpoint returns error", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			vi.stubGlobal(
				"fetch",
				mockFetch({ error: "invalid_grant" }, 400),
			);

			await expect(
				authorize({
					service: testService,
					clientId: "cid",
					clientSecret: "csec",
					launch: vi.fn(),
				}),
			).rejects.toThrow("Token endpoint returned 400");
		});

		it("should fail when no refresh token is returned", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			vi.stubGlobal(
				"fetch",
				mockFetch({
					access_token: "at",
					expires_in: 3600,
					token_type: "bearer",
					// no refresh_token
				}),
			);

			await expect(
				authorize({
					service: testService,
					clientId: "cid",
					clientSecret: "csec",
					launch: vi.fn(),
				}),
			).rejects.toThrow("refresh token");
		});

		it("should include PKCE challenge in authorization URL", async () => {
			let capturedUrl: string | undefined;

			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					capturedUrl = opts.authorizationUrl;
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			vi.stubGlobal(
				"fetch",
				mockFetch({
					access_token: "at",
					refresh_token: "rt",
					expires_in: 3600,
					token_type: "bearer",
				}),
			);

			await authorize({
				service: testService,
				clientId: "cid",
				clientSecret: "csec",
				launch: vi.fn(),
			});

			expect(capturedUrl).toBeDefined();
			const url = new URL(capturedUrl!);
			expect(url.searchParams.get("code_challenge")).toBeTruthy();
			expect(url.searchParams.get("code_challenge_method")).toBe("S256");
			expect(url.searchParams.get("response_type")).toBe("code");
			expect(url.searchParams.get("client_id")).toBe("cid");
			expect(url.searchParams.get("scope")).toBe("read write");
		});

		it("should use redirect: error to prevent credential leakage", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			const fetchMock = mockFetch({
				access_token: "at",
				refresh_token: "rt",
				expires_in: 3600,
				token_type: "bearer",
			});
			vi.stubGlobal("fetch", fetchMock);

			await authorize({
				service: testService,
				clientId: "cid",
				clientSecret: "csec",
				launch: vi.fn(),
			});

			const [, options] = fetchMock.mock.calls[0];
			expect(options.redirect).toBe("error");
		});

		it("should fetch user ID when userIdEndpoint is configured", async () => {
			mockGetAuthCode.mockImplementation(async (opts) => {
				if ("authorizationUrl" in opts && opts.authorizationUrl) {
					const url = new URL(opts.authorizationUrl);
					return { code: "code", state: url.searchParams.get("state") ?? undefined };
				}
				return { code: "code" };
			});

			let callCount = 0;
			vi.stubGlobal("fetch", vi.fn(async (url: string) => {
				callCount++;
				if (callCount === 1) {
					// Token exchange
					return {
						ok: true,
						json: async () => ({
							access_token: "at",
							refresh_token: "rt",
							expires_in: 3600,
							token_type: "bearer",
						}),
					};
				}
				// User ID fetch
				return {
					ok: true,
					json: async () => ({
						data: { id: "12345", username: "testuser" },
					}),
				};
			}));

			const result = await authorize({
				service: {
					...testService,
					userIdEndpoint: "https://api.example.com/me",
					userIdJsonPath: "data.id",
				},
				clientId: "cid",
				clientSecret: "csec",
				launch: vi.fn(),
			});

			expect(result.userId).toBe("12345");
			expect(result.username).toBe("testuser");
		});
	});
});
