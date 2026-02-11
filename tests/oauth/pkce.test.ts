/**
 * Tests for PKCE challenge generation.
 */

import { describe, expect, it } from "vitest";

import {
	generateCodeChallenge,
	generateCodeVerifier,
	generatePKCE,
} from "../../src/oauth/pkce.js";

// Base64url character set (RFC 4648 Section 5)
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

describe("PKCE", () => {
	describe("generateCodeVerifier", () => {
		it("should generate a verifier of default length (64)", () => {
			const verifier = generateCodeVerifier();
			expect(verifier).toHaveLength(64);
		});

		it("should generate verifiers within RFC 7636 bounds (43-128)", () => {
			const short = generateCodeVerifier(43);
			expect(short).toHaveLength(43);

			const long = generateCodeVerifier(128);
			expect(long).toHaveLength(128);
		});

		it("should use only base64url characters", () => {
			const verifier = generateCodeVerifier();
			expect(verifier).toMatch(BASE64URL_REGEX);
		});

		it("should produce unique values on each call", () => {
			const a = generateCodeVerifier();
			const b = generateCodeVerifier();
			expect(a).not.toBe(b);
		});

		it("should reject length below 43", () => {
			expect(() => generateCodeVerifier(42)).toThrow(RangeError);
		});

		it("should reject length above 128", () => {
			expect(() => generateCodeVerifier(129)).toThrow(RangeError);
		});
	});

	describe("generateCodeChallenge", () => {
		it("should produce base64url-encoded output", () => {
			const verifier = generateCodeVerifier();
			const challenge = generateCodeChallenge(verifier);
			expect(challenge).toMatch(BASE64URL_REGEX);
		});

		it("should be deterministic for same verifier", () => {
			const verifier = "test-verifier-that-is-long-enough-for-the-test-case";
			const a = generateCodeChallenge(verifier);
			const b = generateCodeChallenge(verifier);
			expect(a).toBe(b);
		});

		it("should produce different challenges for different verifiers", () => {
			const a = generateCodeChallenge(generateCodeVerifier());
			const b = generateCodeChallenge(generateCodeVerifier());
			expect(a).not.toBe(b);
		});

		it("should match known SHA256 value", () => {
			// RFC 7636 Appendix B test vector
			const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
			const challenge = generateCodeChallenge(verifier);
			expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
		});
	});

	describe("generatePKCE", () => {
		it("should return both verifier and challenge", () => {
			const { codeVerifier, codeChallenge } = generatePKCE();
			expect(codeVerifier).toBeDefined();
			expect(codeChallenge).toBeDefined();
			expect(codeVerifier.length).toBeGreaterThanOrEqual(43);
			expect(codeChallenge).toMatch(BASE64URL_REGEX);
		});

		it("should produce consistent challenge for its verifier", () => {
			const { codeVerifier, codeChallenge } = generatePKCE();
			expect(generateCodeChallenge(codeVerifier)).toBe(codeChallenge);
		});
	});
});
