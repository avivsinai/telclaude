import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
	BrowserCookieStore,
	browserAuthorityDomainFromMcp,
} from "../../src/relay/browser-cookie-store.js";
import {
	enrollBrowserSession,
	inferBrowserSessionRegistrableDomain,
	normalizeBrowserSessionRegistrableDomain,
} from "../../src/relay/browser-session-capture.js";
import { resolveBrowseSession } from "../../src/relay/browser-session-resolver.js";

const KEY = "session-capture-test-key-0123456789";

let dir: string;
let store: BrowserCookieStore;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "tc-session-capture-"));
	store = new BrowserCookieStore(join(dir, "sessions.json"), KEY);
});

afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

describe("enrollBrowserSession", () => {
	it("stores metadata-only output and resolves for the private Telegram browse authority stamp", () => {
		const actorId = "456";
		const profileId = "ops";
		const authorityDomain = browserAuthorityDomainFromMcp("private");
		const storageState = {
			cookies: [{ name: "SID", value: "secret-cookie-value", domain: ".google.com" }],
			origins: [],
		};

		const meta = enrollBrowserSession(store, {
			url: "https://accounts.google.com/login",
			credentialRef: "google-ops",
			actorId,
			profileId,
			authorityDomain,
			originScope: ["mail.google.com"],
			storageState,
			capturedBy: "456",
			nowMs: 10,
		});

		expect(meta).toEqual({
			credentialRef: "google-ops",
			actorId,
			profileId,
			authorityDomain: "private",
			domain: "google.com",
			originScope: ["google.com", "mail.google.com"],
			createdAt: 10,
			capturedBy: "456",
		});
		expect(JSON.stringify(meta)).not.toContain("secret-cookie-value");
		expect(JSON.stringify(store.listSessions())).not.toContain("secret-cookie-value");

		const tcBrowseAuthority = {
			actorId,
			profileId,
			authorityDomain: browserAuthorityDomainFromMcp("private"),
		};
		expect(
			resolveBrowseSession(store, "https://mail.google.com/u/0/", tcBrowseAuthority)?.storageState,
		).toEqual(storageState);
		expect(
			resolveBrowseSession(store, "https://mail.google.com/u/0/", {
				...tcBrowseAuthority,
				actorId: "telegram:456",
			}),
		).toBeNull();
		expect(
			resolveBrowseSession(store, "https://mail.google.com/u/0/", {
				...tcBrowseAuthority,
				profileId: "other-profile",
			}),
		).toBeNull();
		expect(
			resolveBrowseSession(store, "https://mail.google.com/u/0/", {
				...tcBrowseAuthority,
				authorityDomain: browserAuthorityDomainFromMcp("social"),
			}),
		).toBeNull();
	});

	it("rejects public suffix, IP, and non-registrable capture inputs", () => {
		expect(() => inferBrowserSessionRegistrableDomain("https://github.io/login")).toThrow(
			/registrable domain/,
		);
		expect(() => inferBrowserSessionRegistrableDomain("https://127.0.0.1/login")).toThrow(
			/registrable domain/,
		);
		expect(() => normalizeBrowserSessionRegistrableDomain("accounts.google.com")).toThrow(
			/registrable domain/,
		);
		expect(() =>
			enrollBrowserSession(store, {
				url: "https://accounts.google.com/login",
				credentialRef: "bad-scope",
				actorId: "456",
				profileId: "ops",
				authorityDomain: "private",
				originScope: ["co.uk"],
				storageState: { cookies: [], origins: [] },
			}),
		).toThrow(/origin scope entry/);
	});
});
