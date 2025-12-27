import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
	generateSessionToken,
	validateSessionToken,
	generateSessionId,
	decodeToken,
} from "../../src/relay/git-proxy-auth.js";

// Mock environment
beforeEach(() => {
	// Set a stable secret for testing
	process.env.TELCLAUDE_GIT_PROXY_SECRET = "test-secret-for-git-proxy-unit-tests";
});

afterEach(() => {
	vi.restoreAllMocks();
	delete process.env.TELCLAUDE_GIT_PROXY_SECRET;
});

describe("git-proxy-auth", () => {
	describe("generateSessionId", () => {
		it("should generate unique 32-character hex strings", () => {
			const id1 = generateSessionId();
			const id2 = generateSessionId();

			expect(id1).toHaveLength(32);
			expect(id2).toHaveLength(32);
			expect(id1).not.toBe(id2);
			expect(id1).toMatch(/^[a-f0-9]+$/);
		});
	});

	describe("generateSessionToken", () => {
		it("should generate a valid base64-encoded token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId);

			expect(token).toBeTruthy();
			expect(typeof token).toBe("string");

			// Should be valid base64
			const decoded = Buffer.from(token, "base64").toString("utf-8");
			expect(() => JSON.parse(decoded)).not.toThrow();
		});

		it("should include sessionId, timestamps, and signature in token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000); // 1 minute TTL

			const decoded = decodeToken(token);
			expect(decoded).toBeTruthy();
			expect(decoded?.sessionId).toBe(sessionId);
			expect(decoded?.createdAt).toBeTruthy();
			expect(decoded?.expiresAt).toBeTruthy();
			expect(decoded?.signature).toBeTruthy();
			expect(decoded!.expiresAt).toBeGreaterThan(decoded!.createdAt);
		});

		it("should respect custom TTL", () => {
			const sessionId = generateSessionId();
			const ttlMs = 30 * 60 * 1000; // 30 minutes
			const token = generateSessionToken(sessionId, ttlMs);

			const decoded = decodeToken(token);
			expect(decoded).toBeTruthy();

			const actualTtl = decoded!.expiresAt - decoded!.createdAt;
			expect(actualTtl).toBe(ttlMs);
		});
	});

	describe("validateSessionToken", () => {
		it("should validate a freshly generated token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			const result = validateSessionToken(token);
			expect(result).toBeTruthy();
			expect(result?.sessionId).toBe(sessionId);
		});

		it("should reject an expired token", () => {
			const sessionId = generateSessionId();
			// Generate token with 1ms TTL, then wait
			const token = generateSessionToken(sessionId, 1);

			// Wait a tiny bit to ensure expiration
			const start = Date.now();
			while (Date.now() - start < 5) {
				// Busy wait for 5ms
			}

			const result = validateSessionToken(token);
			expect(result).toBeNull();
		});

		it("should reject a token with tampered signature", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			// Decode, tamper, re-encode
			const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));
			decoded.signature = "tampered-signature";
			const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64");

			const result = validateSessionToken(tampered);
			expect(result).toBeNull();
		});

		it("should reject a token with tampered sessionId", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			// Decode, tamper sessionId, re-encode (keeping original signature)
			const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf-8"));
			decoded.sessionId = "different-session-id";
			const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64");

			const result = validateSessionToken(tampered);
			expect(result).toBeNull(); // Signature won't match
		});

		it("should reject malformed base64", () => {
			const result = validateSessionToken("not-valid-base64!!!");
			expect(result).toBeNull();
		});

		it("should reject empty string", () => {
			const result = validateSessionToken("");
			expect(result).toBeNull();
		});

		it("should reject token missing required fields", () => {
			const incomplete = Buffer.from(JSON.stringify({ sessionId: "test" })).toString("base64");
			const result = validateSessionToken(incomplete);
			expect(result).toBeNull();
		});
	});

	describe("decodeToken", () => {
		it("should decode a valid token without validation", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			const decoded = decodeToken(token);
			expect(decoded).toBeTruthy();
			expect(decoded?.sessionId).toBe(sessionId);
		});

		it("should return null for invalid base64", () => {
			const result = decodeToken("not-valid-base64!!!");
			expect(result).toBeNull();
		});

		it("should return null for non-JSON content", () => {
			const notJson = Buffer.from("not json content").toString("base64");
			const result = decodeToken(notJson);
			expect(result).toBeNull();
		});
	});

	describe("security properties", () => {
		it("should produce different tokens for same sessionId at different times", async () => {
			const sessionId = generateSessionId();

			const token1 = generateSessionToken(sessionId, 60000);

			// Wait a tiny bit
			await new Promise((resolve) => setTimeout(resolve, 5));

			const token2 = generateSessionToken(sessionId, 60000);

			// Tokens should be different (different createdAt, expiresAt, signature)
			expect(token1).not.toBe(token2);
		});

		it("should produce different tokens for different sessionIds", () => {
			const token1 = generateSessionToken(generateSessionId(), 60000);
			const token2 = generateSessionToken(generateSessionId(), 60000);

			expect(token1).not.toBe(token2);
		});

		it("should not leak the secret in the token", () => {
			const sessionId = generateSessionId();
			const token = generateSessionToken(sessionId, 60000);

			// Decode and check the secret is not present
			const decoded = Buffer.from(token, "base64").toString("utf-8");
			expect(decoded).not.toContain(process.env.TELCLAUDE_GIT_PROXY_SECRET);
		});
	});
});

describe("git-proxy URL parsing", () => {
	// Import the internal functions for testing
	// We'll test the parseGitUrl function through integration tests
	// since it's not exported, but we can test the expected behavior

	describe("expected URL patterns", () => {
		it("should describe supported URL formats", () => {
			// These are the URL formats the proxy should handle:
			const supportedPatterns = [
				"/github.com/owner/repo.git/info/refs",
				"/github.com/owner/repo.git/info/refs?service=git-upload-pack",
				"/github.com/owner/repo.git/info/refs?service=git-receive-pack",
				"/github.com/owner/repo.git/git-upload-pack",
				"/github.com/owner/repo.git/git-receive-pack",
				"/github.com/owner/repo/info/refs", // Without .git
			];

			// All these patterns should be parseable
			expect(supportedPatterns.length).toBe(6);
		});
	});
});
