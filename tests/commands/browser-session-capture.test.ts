import { describe, expect, it } from "vitest";

import { browserSessionJsonPayload, formatBrowserSessionRows } from "../../src/commands/browser.js";
import type { BrowserSessionMeta } from "../../src/relay/browser-cookie-store.js";

describe("browser sessions command formatting", () => {
	it("surfaces only browser session metadata", () => {
		const rows: BrowserSessionMeta[] = [
			{
				credentialRef: "google-ops",
				actorId: "456",
				profileId: "ops",
				authorityDomain: "private",
				domain: "google.com",
				originScope: ["google.com"],
				createdAt: 10,
				capturedBy: "456",
			},
		];

		const json = JSON.stringify(browserSessionJsonPayload(rows));
		const table = formatBrowserSessionRows(rows);

		expect(json).toContain("google-ops");
		expect(table).toContain("google.com");
		expect(json).not.toContain("storageState");
		expect(table).not.toContain("storageState");
		expect(json).not.toContain("secret-cookie-value");
		expect(table).not.toContain("secret-cookie-value");
	});
});
