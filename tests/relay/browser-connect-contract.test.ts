import { describe, expect, it } from "vitest";

import {
	buildBrowserOriginScope,
	hostMatchesBrowserOriginScope,
	normalizeBrowserOriginScopeEntry,
} from "../../src/relay/browser-connect-contract.js";

describe("browser origin scope — public-suffix (PSL) rejection", () => {
	it("rejects bare public suffixes as scope entries (no cross-tenant egress)", () => {
		// A multi-label ICANN suffix, a bare TLD, and a private-section suffix —
		// none is a registrable domain, so none may key an egress scope.
		for (const suffix of ["co.uk", "com", "github.io"]) {
			expect(normalizeBrowserOriginScopeEntry(suffix)).toBeNull();
		}
	});

	it("keeps registrable domains and their subdomains", () => {
		expect(normalizeBrowserOriginScopeEntry("google.com")).toBe("google.com");
		expect(normalizeBrowserOriginScopeEntry("mail.google.com")).toBe("mail.google.com");
		expect(normalizeBrowserOriginScopeEntry("bbc.co.uk")).toBe("bbc.co.uk");
		// github.io is a public suffix, so a user's page IS a registrable domain.
		expect(normalizeBrowserOriginScopeEntry("user.github.io")).toBe("user.github.io");
	});

	it("drops public-suffix entries from a built scope, keeping registrable ones", () => {
		expect(buildBrowserOriginScope(["co.uk", "bbc.co.uk", "com", "google.com"])).toEqual([
			"bbc.co.uk",
			"google.com",
		]);
	});

	it("keeps a real catastrophic host so refusal still works (the guard is shared)", () => {
		// normalizeBrowserHost is shared with the catastrophic-domain path. A real
		// catastrophic host is registrable-or-deeper, so it survives the PSL guard and
		// still drives refusal; only a degenerate bare-suffix catastrophic entry drops.
		expect(buildBrowserOriginScope(["myaccount.google.com"])).toEqual(["myaccount.google.com"]);
		expect(buildBrowserOriginScope(["login.tailscale.com"])).toEqual(["login.tailscale.com"]);
	});

	it("a public-suffix scope can never match an arbitrary tenant under it", () => {
		// Before the PSL guard, hostMatchesBrowserOriginScope("evil.co.uk", ["co.uk"])
		// returned true — a session keyed to co.uk would ride cookies onto every
		// *.co.uk tenant. The entry now normalizes to null and is skipped.
		expect(hostMatchesBrowserOriginScope("evil.co.uk", ["co.uk"])).toBe(false);
		expect(hostMatchesBrowserOriginScope("victim.github.io", ["github.io"])).toBe(false);
		// A real registrable scope still matches its own subdomains.
		expect(hostMatchesBrowserOriginScope("mail.google.com", ["google.com"])).toBe(true);
	});
});
