import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { BrowserCookieStore } from "../../src/relay/browser-cookie-store.js";
import { resolveBrowseSession } from "../../src/relay/browser-session-resolver.js";

const KEY = "resolver-test-key-0123456789abcd";

let dir: string;
let store: BrowserCookieStore;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "tc-resolver-"));
	store = new BrowserCookieStore(join(dir, "sessions.json"), KEY);
});

afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

function seedGoogle() {
	store.putSession({
		sessionRef: "sess-google",
		domain: "google.com",
		originScope: ["accounts.google.com", "mail.google.com"],
		storageState: { cookies: [{ name: "SID", value: "v", domain: ".google.com" }], origins: [] },
		createdAt: 1,
		capturedBy: "telegram:default",
	});
}

describe("resolveBrowseSession", () => {
	it("returns the session when a stored login origin covers the host", () => {
		seedGoogle();
		const session = resolveBrowseSession(store, "https://mail.google.com/u/0/");
		expect(session?.originScope).toEqual(["google.com", "accounts.google.com", "mail.google.com"]);
		expect(session?.storageState).toEqual({
			cookies: [{ name: "SID", value: "v", domain: ".google.com" }],
			origins: [],
		});
	});

	it("returns null when no session's registrable domain covers the host (cookie-less browse)", () => {
		seedGoogle();
		expect(resolveBrowseSession(store, "https://example.org/")).toBeNull();
		expect(resolveBrowseSession(store, "https://github.com/")).toBeNull();
	});

	it("resolves any subdomain of the captured registrable domain (cookies are domain-wide)", () => {
		seedGoogle();
		// The login was captured on mail/accounts, but .google.com cookies apply
		// across the registrable domain, so the M1 egress pin (folded to google.com)
		// is correctly domain-wide — a sibling subdomain still resolves.
		expect(resolveBrowseSession(store, "https://docs.google.com/")).not.toBeNull();
		expect(resolveBrowseSession(store, "https://drive.google.com/")).not.toBeNull();
	});

	it("refuses a standing session for a catastrophic surface even if one is stored", () => {
		store.putSession({
			sessionRef: "sess-bank",
			domain: "mybank.example",
			originScope: ["secure.mybank.example"],
			storageState: { cookies: [], origins: [] },
			createdAt: 2,
			capturedBy: "telegram:default",
		});
		expect(
			resolveBrowseSession(store, "https://secure.mybank.example/transfer", {
				catastrophicDomains: ["mybank.example"],
			}),
		).toBeNull();
	});

	it("returns null for an unparseable URL", () => {
		seedGoogle();
		expect(resolveBrowseSession(store, "not a url")).toBeNull();
	});

	it("returns null from an empty store", () => {
		expect(resolveBrowseSession(store, "https://mail.google.com/")).toBeNull();
	});
});
