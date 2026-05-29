import { describe, expect, it } from "vitest";

import { isPathAllowed } from "../../src/relay/http-credential-proxy.js";

describe("http-credential-proxy isPathAllowed", () => {
	it("allows any path when no allowlist is configured", () => {
		expect(isPathAllowed("/anything/goes", undefined)).toBe(true);
		expect(isPathAllowed("/anything/goes", [])).toBe(true);
	});

	describe("path-prefix anchoring (regression)", () => {
		// A prefix-intended pattern like "/v1/images" must only match from the
		// start of the path. Under the old unanchored `new RegExp(pattern).test(path)`
		// these would have substring-matched and been wrongly ALLOWED.
		it("rejects a path that only substring-matches the pattern elsewhere", () => {
			// "/v1/images" appears mid-path; an attacker could smuggle it after a
			// different (disallowed) route segment.
			expect(isPathAllowed("/admin/delete?next=/v1/images", ["/v1/images"])).toBe(false);
			expect(isPathAllowed("/evil/v1/images/generations", ["/v1/images"])).toBe(false);
		});

		it("rejects a path that contains the allowed prefix only as a later segment", () => {
			// "/v1/messages" is the intended prefix; "/proxy/v1/messages" embeds it
			// but does not start with it.
			expect(isPathAllowed("/proxy/v1/messages", ["/v1/messages"])).toBe(false);
		});

		it("still allows the legitimate intended paths", () => {
			expect(isPathAllowed("/v1/images", ["/v1/images"])).toBe(true);
			expect(isPathAllowed("/v1/images/generations", ["/v1/images"])).toBe(true);
			expect(isPathAllowed("/v1/messages", ["/v1/messages"])).toBe(true);
		});

		it("matches against any pattern in a multi-entry allowlist", () => {
			const allow = ["/v1/images", "/v1/audio/speech"];
			expect(isPathAllowed("/v1/audio/speech", allow)).toBe(true);
			expect(isPathAllowed("/v1/images/generations", allow)).toBe(true);
			// Neither prefix anchors this one.
			expect(isPathAllowed("/v1/embeddings", allow)).toBe(false);
		});
	});

	describe("already-anchored patterns are unaffected", () => {
		it("honors a leading ^ without double-anchoring", () => {
			expect(isPathAllowed("/v1/images", ["^/v1/images"])).toBe(true);
			expect(isPathAllowed("/v1/images/generations", ["^/v1/images"])).toBe(true);
		});

		it("still rejects non-prefix matches for anchored patterns", () => {
			expect(isPathAllowed("/proxy/v1/images", ["^/v1/images"])).toBe(false);
		});

		it("supports anchored end constraints", () => {
			// Exact-match pattern: only "/v1/models" passes.
			expect(isPathAllowed("/v1/models", ["^/v1/models$"])).toBe(true);
			expect(isPathAllowed("/v1/models/gpt", ["^/v1/models$"])).toBe(false);
		});
	});

	it("skips invalid regex patterns without throwing", () => {
		// An unparseable pattern is ignored; the legitimate one still matches.
		expect(isPathAllowed("/v1/images", ["(", "/v1/images"])).toBe(true);
		// And an allowlist of only invalid patterns denies everything.
		expect(isPathAllowed("/v1/images", ["("])).toBe(false);
	});
});
