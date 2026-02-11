/**
 * Tests for OAuth2 service registry.
 */

import { describe, expect, it } from "vitest";

import { getService, listServices } from "../../src/oauth/registry.js";

describe("OAuth2 Registry", () => {
	describe("getService", () => {
		it("should return xtwitter definition", () => {
			const svc = getService("xtwitter");
			expect(svc).toBeDefined();
			expect(svc!.displayName).toBe("X/Twitter");
		});

		it("should return undefined for unknown service", () => {
			expect(getService("unknown")).toBeUndefined();
		});
	});

	describe("listServices", () => {
		it("should return at least one service", () => {
			const services = listServices();
			expect(services.length).toBeGreaterThan(0);
		});

		it("should return a copy (not the original array)", () => {
			const a = listServices();
			const b = listServices();
			expect(a).not.toBe(b);
		});
	});

	describe("structural invariants", () => {
		const services = listServices();

		it.each(services)("$id: token endpoint must be HTTPS", (svc) => {
			expect(svc.tokenEndpoint).toMatch(/^https:\/\//);
		});

		it.each(services)("$id: must have required fields", (svc) => {
			expect(svc.id).toBeTruthy();
			expect(svc.displayName).toBeTruthy();
			expect(svc.authorizationUrl).toMatch(/^https:\/\//);
			expect(svc.defaultScopes.length).toBeGreaterThan(0);
			expect(svc.vaultTarget).toBeTruthy();
			expect(svc.vaultLabel).toBeTruthy();
		});

		it.each(services)("$id: userIdEndpoint must be HTTPS if present", (svc) => {
			if (svc.userIdEndpoint) {
				expect(svc.userIdEndpoint).toMatch(/^https:\/\//);
			}
		});
	});
});
