import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { BrowseRequest, BrowseResult } from "../../src/relay/browser-broker.js";
import { BrowserCookieStore } from "../../src/relay/browser-cookie-store.js";
import {
	createSessionAwareBrowseExecutor,
	resolveBrowseSession,
} from "../../src/relay/browser-session-resolver.js";

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

describe("createSessionAwareBrowseExecutor", () => {
	function recordingRunner() {
		const seen: BrowseRequest[] = [];
		const runner = {
			async browse(request: BrowseRequest): Promise<BrowseResult> {
				seen.push(request);
				return {
					url: request.url,
					finalUrl: request.url,
					httpStatus: 200,
					title: "",
					content: "",
					truncated: false,
				};
			},
		};
		return { runner, seen };
	}

	it("attaches the resolved session for a matching host, none otherwise", async () => {
		seedGoogle();
		const { runner, seen } = recordingRunner();
		const exec = createSessionAwareBrowseExecutor(runner, store);

		await exec.browse({ actor: "a", sessionRef: "s", url: "https://mail.google.com/" });
		await exec.browse({ actor: "a", sessionRef: "s", url: "https://example.org/" });

		expect(seen[0]?.session?.originScope).toEqual([
			"google.com",
			"accounts.google.com",
			"mail.google.com",
		]);
		expect(seen[1]?.session).toBeUndefined();
	});

	it("never attaches a session for a catastrophic surface", async () => {
		store.putSession({
			sessionRef: "sess-bank",
			domain: "mybank.example",
			originScope: ["secure.mybank.example"],
			storageState: { cookies: [], origins: [] },
			createdAt: 1,
			capturedBy: "telegram:default",
		});
		const { runner, seen } = recordingRunner();
		const exec = createSessionAwareBrowseExecutor(runner, store, {
			catastrophicDomains: ["mybank.example"],
		});

		await exec.browse({ actor: "a", sessionRef: "s", url: "https://secure.mybank.example/" });
		expect(seen[0]?.session).toBeUndefined();
	});
});
