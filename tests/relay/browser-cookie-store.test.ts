import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
	BrowserCookieStore,
	type BrowserSessionRecord,
} from "../../src/relay/browser-cookie-store.js";

const KEY = "cookie-store-test-key-0123456789";

let dir: string;
let filePath: string;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "tc-cookie-store-"));
	filePath = join(dir, "sessions.json");
});

afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

function record(overrides: Partial<BrowserSessionRecord> = {}): BrowserSessionRecord {
	return {
		credentialRef: "sess-google-1",
		actorId: "telegram:default",
		profileId: "default",
		authorityDomain: "private",
		domain: "google.com",
		originScope: ["accounts.google.com", "mail.google.com"],
		storageState: {
			cookies: [{ name: "SID", value: "secret-cookie-value", domain: ".google.com" }],
		},
		createdAt: 1_000,
		capturedBy: "telegram:default",
		...overrides,
	};
}

describe("BrowserCookieStore", () => {
	it("round-trips a session and normalizes the origin scope to include the domain", () => {
		const store = new BrowserCookieStore(filePath, KEY);
		store.putSession(record());

		const got = store.getSession("sess-google-1");
		expect(got?.domain).toBe("google.com");
		expect(got?.storageState).toEqual({
			cookies: [{ name: "SID", value: "secret-cookie-value", domain: ".google.com" }],
		});
		// domain is folded into the origin scope, deduped + normalized.
		expect(got?.originScope).toEqual(["google.com", "accounts.google.com", "mail.google.com"]);
		expect(got?.capturedBy).toBe("telegram:default");
	});

	it("encrypts cookies at rest — the file never contains the plaintext", () => {
		const store = new BrowserCookieStore(filePath, KEY);
		store.putSession(record());
		const raw = readFileSync(filePath, "utf8");
		expect(raw).not.toContain("secret-cookie-value");
		expect(raw).not.toContain("SID");
	});

	it("lists metadata only (never storageState), newest first", () => {
		const store = new BrowserCookieStore(filePath, KEY);
		store.putSession(record({ credentialRef: "a", createdAt: 1 }));
		store.putSession(
			record({ credentialRef: "b", domain: "github.com", originScope: [], createdAt: 2 }),
		);

		const list = store.listSessions();
		expect(list.map((m) => m.credentialRef)).toEqual(["b", "a"]);
		expect(JSON.stringify(list)).not.toContain("storageState");
		expect(JSON.stringify(list)).not.toContain("secret-cookie-value");
	});

	it("deletes a session and reports prior existence", () => {
		const store = new BrowserCookieStore(filePath, KEY);
		store.putSession(record());
		expect(store.deleteSession("sess-google-1")).toBe(true);
		expect(store.getSession("sess-google-1")).toBeNull();
		expect(store.deleteSession("sess-google-1")).toBe(false);
	});

	it("returns null for a session encrypted under a different key (GCM auth fails)", () => {
		new BrowserCookieStore(filePath, KEY).putSession(record());
		const wrong = new BrowserCookieStore(filePath, "a-completely-different-key-0123456789");
		expect(wrong.getSession("sess-google-1")).toBeNull();
	});

	it("rejects a key shorter than the entropy floor", () => {
		expect(() => new BrowserCookieStore(filePath, "tooshort")).toThrow(/at least 32/);
	});

	it("binds each record to its sessionRef via AES-GCM AAD — an on-disk swap fails closed", () => {
		const store = new BrowserCookieStore(filePath, KEY);
		store.putSession(record({ credentialRef: "low", domain: "example.org", originScope: [] }));
		store.putSession(
			record({
				credentialRef: "bank",
				domain: "bank.example",
				originScope: [],
				storageState: { cookies: [{ name: "B", value: "bank-cookie", domain: "bank.example" }] },
			}),
		);
		// Swap the two ciphertexts on disk (each now filed under the WRONG sessionRef).
		const file = JSON.parse(readFileSync(filePath, "utf8"));
		[file.sessions.low, file.sessions.bank] = [file.sessions.bank, file.sessions.low];
		writeFileSync(filePath, JSON.stringify(file));
		// AAD (sessionRef) no longer matches → auth fails → null, never the other session's cookies.
		const reopened = new BrowserCookieStore(filePath, KEY);
		expect(reopened.getSession("low")).toBeNull();
		expect(reopened.getSession("bank")).toBeNull();
	});

	it("rejects an empty encryption key and a session without a usable origin scope", () => {
		expect(() => new BrowserCookieStore(filePath, "  ")).toThrow(/encryption key/);
		const store = new BrowserCookieStore(filePath, KEY);
		// domain is a bare IP / single label → no usable registrable-domain scope.
		expect(() => store.putSession(record({ domain: "localhost", originScope: [] }))).toThrow(
			/origin scope/,
		);
	});

	it("persists across store instances (durable)", () => {
		new BrowserCookieStore(filePath, KEY).putSession(record());
		expect(existsSync(filePath)).toBe(true);
		const reopened = new BrowserCookieStore(filePath, KEY);
		expect(reopened.getSession("sess-google-1")?.domain).toBe("google.com");
	});
});
