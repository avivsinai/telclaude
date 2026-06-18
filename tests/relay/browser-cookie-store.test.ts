import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
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
		sessionRef: "sess-google-1",
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
		store.putSession(record({ sessionRef: "a", createdAt: 1 }));
		store.putSession(
			record({ sessionRef: "b", domain: "github.com", originScope: [], createdAt: 2 }),
		);

		const list = store.listSessions();
		expect(list.map((m) => m.sessionRef)).toEqual(["b", "a"]);
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
		const wrong = new BrowserCookieStore(filePath, "a-completely-different-key");
		expect(wrong.getSession("sess-google-1")).toBeNull();
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
