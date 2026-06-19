import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { BrowseRequest, BrowseResult } from "../../src/relay/browser-broker.js";
import {
	BrowserCookieStore,
	type BrowserSessionAuthority,
} from "../../src/relay/browser-cookie-store.js";
import {
	createSessionAwareBrowseExecutor,
	resolveBrowseSession,
} from "../../src/relay/browser-session-resolver.js";

const KEY = "resolver-test-key-0123456789abcd";
const PRIV: BrowserSessionAuthority = {
	actorId: "telegram:default",
	profileId: "default",
	authorityDomain: "private",
};

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
		credentialRef: "sess-google",
		actorId: "telegram:default",
		profileId: "default",
		authorityDomain: "private",
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
		const session = resolveBrowseSession(store, "https://mail.google.com/u/0/", PRIV);
		expect(session?.originScope).toEqual(["google.com", "accounts.google.com", "mail.google.com"]);
		expect(session?.storageState).toEqual({
			cookies: [{ name: "SID", value: "v", domain: ".google.com" }],
			origins: [],
		});
	});

	it("returns null when no session's registrable domain covers the host (cookie-less browse)", () => {
		seedGoogle();
		expect(resolveBrowseSession(store, "https://example.org/", PRIV)).toBeNull();
		expect(resolveBrowseSession(store, "https://github.com/", PRIV)).toBeNull();
	});

	it("resolves any subdomain of the captured registrable domain (cookies are domain-wide)", () => {
		seedGoogle();
		expect(resolveBrowseSession(store, "https://docs.google.com/", PRIV)).not.toBeNull();
		expect(resolveBrowseSession(store, "https://drive.google.com/", PRIV)).not.toBeNull();
	});

	it("refuses a standing session for a catastrophic surface even if one is stored", () => {
		store.putSession({
			credentialRef: "sess-bank",
			actorId: "telegram:default",
			profileId: "default",
			authorityDomain: "private",
			domain: "mybank.example",
			originScope: ["secure.mybank.example"],
			storageState: { cookies: [], origins: [] },
			createdAt: 2,
			capturedBy: "telegram:default",
		});
		expect(
			resolveBrowseSession(store, "https://secure.mybank.example/transfer", PRIV, {
				catastrophicDomains: ["mybank.example"],
			}),
		).toBeNull();
	});

	it("refuses a session whose registrable-wide scope can REACH a catastrophic subdomain", () => {
		seedGoogle();
		expect(
			resolveBrowseSession(store, "https://docs.google.com/", PRIV, {
				catastrophicDomains: ["myaccount.google.com"],
			}),
		).toBeNull();
		expect(resolveBrowseSession(store, "https://docs.google.com/", PRIV)).not.toBeNull();
	});

	it("NEVER resolves a private login for a different authority (no cross-persona bleed)", () => {
		seedGoogle(); // captured under {private, default, telegram:default}
		// A social authority requesting the same host gets NO session.
		const social: BrowserSessionAuthority = {
			actorId: "social",
			profileId: "tc-public-social",
			authorityDomain: "public-social",
		};
		expect(resolveBrowseSession(store, "https://mail.google.com/", social)).toBeNull();
		// A different private profile gets nothing.
		expect(
			resolveBrowseSession(store, "https://mail.google.com/", { ...PRIV, profileId: "work" }),
		).toBeNull();
		// A different actor gets nothing.
		expect(
			resolveBrowseSession(store, "https://mail.google.com/", {
				...PRIV,
				actorId: "telegram:other",
			}),
		).toBeNull();
		// Only the exact capturing authority resolves.
		expect(resolveBrowseSession(store, "https://mail.google.com/", PRIV)).not.toBeNull();
	});

	it("returns null for an unparseable URL", () => {
		seedGoogle();
		expect(resolveBrowseSession(store, "not a url", PRIV)).toBeNull();
	});

	it("returns null from an empty store", () => {
		expect(resolveBrowseSession(store, "https://mail.google.com/", PRIV)).toBeNull();
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

	const PRIV_REQ = {
		actor: "telegram:default",
		profileId: "default",
		authorityDomain: "private" as const,
		sessionRef: "s",
	};

	it("attaches the resolved session for a matching host, none otherwise", async () => {
		seedGoogle();
		const { runner, seen } = recordingRunner();
		const exec = createSessionAwareBrowseExecutor(runner, store);

		await exec.browse({ ...PRIV_REQ, url: "https://mail.google.com/" });
		await exec.browse({ ...PRIV_REQ, url: "https://example.org/" });

		expect(seen[0]?.session?.originScope).toEqual([
			"google.com",
			"accounts.google.com",
			"mail.google.com",
		]);
		expect(seen[1]?.session).toBeUndefined();
	});

	it("never attaches a session captured under a different authority", async () => {
		seedGoogle(); // private/default/telegram:default
		const { runner, seen } = recordingRunner();
		const exec = createSessionAwareBrowseExecutor(runner, store);
		await exec.browse({
			actor: "social",
			profileId: "tc-public-social",
			authorityDomain: "public-social",
			sessionRef: "s",
			url: "https://mail.google.com/",
		});
		expect(seen[0]?.session).toBeUndefined();
	});

	it("never attaches a session for a catastrophic surface", async () => {
		store.putSession({
			credentialRef: "sess-bank",
			actorId: "telegram:default",
			profileId: "default",
			authorityDomain: "private",
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

		await exec.browse({ ...PRIV_REQ, url: "https://secure.mybank.example/" });
		expect(seen[0]?.session).toBeUndefined();
	});
});
