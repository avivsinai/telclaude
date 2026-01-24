/**
 * Tests for vault protocol schema validation.
 */

import { describe, expect, it } from "vitest";

import {
	CredentialEntrySchema,
	HttpCredentialSchema,
	makeStorageKey,
	OAuth2CredentialSchema,
	parseStorageKey,
	VaultRequestSchema,
	VaultResponseSchema,
} from "../../src/vault-daemon/protocol.js";

describe("Protocol schemas", () => {
	describe("HttpCredentialSchema", () => {
		it("should validate bearer credential", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "bearer",
				token: "sk-12345",
			});
			expect(result.success).toBe(true);
		});

		it("should validate api-key credential", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "api-key",
				token: "api-key-value",
				header: "X-API-Key",
			});
			expect(result.success).toBe(true);
		});

		it("should validate basic credential", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "basic",
				username: "user",
				password: "pass",
			});
			expect(result.success).toBe(true);
		});

		it("should validate query credential", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "query",
				token: "token-value",
				param: "api_key",
			});
			expect(result.success).toBe(true);
		});

		it("should reject invalid type", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "invalid",
				token: "test",
			});
			expect(result.success).toBe(false);
		});

		it("should reject empty token", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "bearer",
				token: "",
			});
			expect(result.success).toBe(false);
		});

		it("should reject api-key with invalid header name (injection attempt)", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "api-key",
				token: "test",
				header: "X-API-Key\r\nX-Injected: evil",
			});
			expect(result.success).toBe(false);
		});

		it("should reject api-key with header containing spaces", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "api-key",
				token: "test",
				header: "X API Key",
			});
			expect(result.success).toBe(false);
		});

		it("should accept api-key with valid RFC7230 token header", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "api-key",
				token: "test",
				header: "X-Custom_Header.Name",
			});
			expect(result.success).toBe(true);
		});

		it("should reject query param with injection characters", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "query",
				token: "test",
				param: "key&injected=evil",
			});
			expect(result.success).toBe(false);
		});

		it("should reject query param with equals sign", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "query",
				token: "test",
				param: "key=value",
			});
			expect(result.success).toBe(false);
		});

		it("should accept query param with underscore and hyphen", () => {
			const result = HttpCredentialSchema.safeParse({
				type: "query",
				token: "test",
				param: "api_key-v2",
			});
			expect(result.success).toBe(true);
		});
	});

	describe("OAuth2CredentialSchema", () => {
		it("should validate complete oauth2 credential", () => {
			const result = OAuth2CredentialSchema.safeParse({
				type: "oauth2",
				clientId: "client-123",
				clientSecret: "secret-456",
				refreshToken: "refresh-789",
				tokenEndpoint: "https://oauth2.example.com/token",
				scope: "email profile",
			});
			expect(result.success).toBe(true);
		});

		it("should validate oauth2 without optional scope", () => {
			const result = OAuth2CredentialSchema.safeParse({
				type: "oauth2",
				clientId: "client",
				clientSecret: "secret",
				refreshToken: "refresh",
				tokenEndpoint: "https://oauth2.example.com/token",
			});
			expect(result.success).toBe(true);
		});

		it("should reject invalid token endpoint URL", () => {
			const result = OAuth2CredentialSchema.safeParse({
				type: "oauth2",
				clientId: "client",
				clientSecret: "secret",
				refreshToken: "refresh",
				tokenEndpoint: "not-a-url",
			});
			expect(result.success).toBe(false);
		});
	});

	describe("VaultRequestSchema", () => {
		it("should validate get request", () => {
			const result = VaultRequestSchema.safeParse({
				type: "get",
				protocol: "http",
				target: "api.example.com",
			});
			expect(result.success).toBe(true);
		});

		it("should validate get-token request", () => {
			const result = VaultRequestSchema.safeParse({
				type: "get-token",
				protocol: "http",
				target: "api.example.com",
			});
			expect(result.success).toBe(true);
		});

		it("should validate store request", () => {
			const result = VaultRequestSchema.safeParse({
				type: "store",
				protocol: "http",
				target: "api.example.com",
				credential: {
					type: "bearer",
					token: "test-token",
				},
			});
			expect(result.success).toBe(true);
		});

		it("should validate delete request", () => {
			const result = VaultRequestSchema.safeParse({
				type: "delete",
				protocol: "http",
				target: "api.example.com",
			});
			expect(result.success).toBe(true);
		});

		it("should validate list request without filter", () => {
			const result = VaultRequestSchema.safeParse({
				type: "list",
			});
			expect(result.success).toBe(true);
		});

		it("should validate list request with protocol filter", () => {
			const result = VaultRequestSchema.safeParse({
				type: "list",
				protocol: "postgres",
			});
			expect(result.success).toBe(true);
		});

		it("should validate ping request", () => {
			const result = VaultRequestSchema.safeParse({
				type: "ping",
			});
			expect(result.success).toBe(true);
		});

		it("should reject unknown request type", () => {
			const result = VaultRequestSchema.safeParse({
				type: "unknown",
			});
			expect(result.success).toBe(false);
		});

		it("should reject invalid protocol", () => {
			const result = VaultRequestSchema.safeParse({
				type: "get",
				protocol: "invalid",
				target: "test",
			});
			expect(result.success).toBe(false);
		});
	});

	describe("VaultResponseSchema", () => {
		it("should validate get success response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "get",
				ok: true,
				entry: {
					protocol: "http",
					target: "api.example.com",
					credential: { type: "bearer", token: "test" },
					createdAt: new Date().toISOString(),
				},
			});
			expect(result.success).toBe(true);
		});

		it("should validate get not found response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "get",
				ok: false,
				error: "not_found",
			});
			expect(result.success).toBe(true);
		});

		it("should validate get-token success response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "get-token",
				ok: true,
				token: "access-token-123",
				expiresAt: Date.now() + 3600000,
			});
			expect(result.success).toBe(true);
		});

		it("should validate get-token error response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "get-token",
				ok: false,
				error: "Token refresh failed",
			});
			expect(result.success).toBe(true);
		});

		it("should validate store response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "store",
				ok: true,
			});
			expect(result.success).toBe(true);
		});

		it("should validate delete response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "delete",
				ok: true,
				deleted: true,
			});
			expect(result.success).toBe(true);
		});

		it("should validate list response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "list",
				ok: true,
				entries: [
					{
						protocol: "http",
						target: "api.example.com",
						credentialType: "bearer",
						createdAt: new Date().toISOString(),
					},
				],
			});
			expect(result.success).toBe(true);
		});

		it("should validate pong response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "pong",
			});
			expect(result.success).toBe(true);
		});

		it("should validate error response", () => {
			const result = VaultResponseSchema.safeParse({
				type: "error",
				error: "Something went wrong",
			});
			expect(result.success).toBe(true);
		});
	});

	describe("CredentialEntrySchema", () => {
		it("should validate complete entry with all optional fields", () => {
			const result = CredentialEntrySchema.safeParse({
				protocol: "http",
				target: "api.example.com",
				label: "Example API",
				credential: { type: "bearer", token: "test" },
				allowedPaths: ["^/v1/.*"],
				rateLimitPerMinute: 60,
				createdAt: new Date().toISOString(),
				expiresAt: new Date(Date.now() + 86400000).toISOString(),
			});
			expect(result.success).toBe(true);
		});

		it("should validate minimal entry", () => {
			const result = CredentialEntrySchema.safeParse({
				protocol: "postgres",
				target: "db.example.com:5432",
				credential: {
					type: "db",
					username: "admin",
					password: "pass",
				},
				createdAt: new Date().toISOString(),
			});
			expect(result.success).toBe(true);
		});
	});

	describe("makeStorageKey / parseStorageKey", () => {
		it("should create and parse http key", () => {
			const key = makeStorageKey("http", "api.example.com");
			expect(key).toBe("http:api.example.com");

			const parsed = parseStorageKey(key);
			expect(parsed).toEqual({
				protocol: "http",
				target: "api.example.com",
			});
		});

		it("should create and parse postgres key with port", () => {
			const key = makeStorageKey("postgres", "db.example.com:5432");
			expect(key).toBe("postgres:db.example.com:5432");

			const parsed = parseStorageKey(key);
			expect(parsed).toEqual({
				protocol: "postgres",
				target: "db.example.com:5432",
			});
		});

		it("should return null for invalid key format", () => {
			expect(parseStorageKey("no-colon")).toBeNull();
		});

		it("should return null for invalid protocol", () => {
			expect(parseStorageKey("invalid:target")).toBeNull();
		});
	});
});
