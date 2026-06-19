import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type {
	BrowserActInlineResult,
	BrowserActPrepareResult,
	BrowserActRequest,
} from "../../src/relay/browser-act-executor.js";
import type { BrowseSession } from "../../src/relay/browser-broker.js";
import { BrowserCookieStore } from "../../src/relay/browser-cookie-store.js";
import { createBrowserActExecutorSurface } from "../../src/relay/browser-act-relay-surface.js";

const COOKIE_KEY = "cookie-store-key-thats-at-least-32-chars-long!";

/**
 * A fake executor that records the resolved `BrowserActRequest` (the surface's
 * output) so the test can assert host / originScope / session resolution without
 * a live browser. It echoes a minimal evidence/prepared result.
 */
function fakeExecutor() {
	const actRequests: (BrowserActRequest & { readonly session?: BrowseSession })[] = [];
	const prepareRequests: (BrowserActRequest & {
		readonly session?: BrowseSession;
		readonly actionRef: string;
	})[] = [];
	return {
		actRequests,
		prepareRequests,
		executor: {
			async act(
				request: BrowserActRequest & { readonly session?: BrowseSession },
			): Promise<BrowserActInlineResult> {
				actRequests.push(request);
				return { committing: false, evidence: minimalEvidence() };
			},
			async prepareIntent(
				request: BrowserActRequest & { readonly session?: BrowseSession; readonly actionRef: string },
			): Promise<BrowserActPrepareResult> {
				prepareRequests.push(request);
				return { committing: true, record: "browser-write", prepared: minimalPrepared(request) };
			},
		} as unknown as Parameters<typeof createBrowserActExecutorSurface>[0]["executor"],
	};
}

describe("browser-act relay surface (session + authority resolution)", () => {
	let dir: string;
	let store: BrowserCookieStore;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-act-surface-"));
		store = new BrowserCookieStore(path.join(dir, "sessions.json"), COOKIE_KEY);
	});

	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("derives the host from the url and pins origin to it for a cookie-less act", async () => {
		const fake = fakeExecutor();
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		await surface.act({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "private",
			sessionRef: "endpoint-private",
			url: "https://shop.example.com/cart?step=1",
			verb: "fill",
			target: "#qty",
			submittedValues: "2",
		});

		expect(fake.actRequests).toHaveLength(1);
		const resolved = fake.actRequests[0];
		expect(resolved?.host).toBe("shop.example.com");
		expect(resolved?.originScope).toEqual(["shop.example.com"]);
		expect(resolved?.session).toBeUndefined();
	});

	it("attaches a stored login + its origin scope for a matching authority", async () => {
		store.putSession({
			credentialRef: "cred-shop",
			actorId: "operator",
			profileId: "ops",
			authorityDomain: "private",
			domain: "shop.example.com",
			originScope: ["shop.example.com"],
			storageState: { cookies: [{ name: "sid", value: "x" }] },
			createdAt: Date.now(),
			capturedBy: "operator",
		});
		const fake = fakeExecutor();
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: store,
			catastrophicDomains: [],
		});

		await surface.act({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "private",
			sessionRef: "endpoint-private",
			url: "https://shop.example.com/account",
			verb: "click",
			target: "#open",
		});

		const resolved = fake.actRequests[0];
		expect(resolved?.session).toBeDefined();
		expect(resolved?.originScope).toEqual(["shop.example.com"]);
	});

	it("never resolves a private login for a social/public authority (no cross-persona bleed)", async () => {
		store.putSession({
			credentialRef: "cred-shop",
			actorId: "operator",
			profileId: "ops",
			authorityDomain: "private",
			domain: "shop.example.com",
			originScope: ["shop.example.com"],
			storageState: { cookies: [] },
			createdAt: Date.now(),
			capturedBy: "operator",
		});
		const fake = fakeExecutor();
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: store,
			catastrophicDomains: [],
		});

		// MCP 'social' → browser 'public-social' authority: the private login must NOT attach.
		await surface.act({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "social",
			sessionRef: "endpoint-social",
			url: "https://shop.example.com/account",
			verb: "click",
			target: "#open",
		});

		expect(fake.actRequests[0]?.session).toBeUndefined();
		expect(fake.actRequests[0]?.originScope).toEqual(["shop.example.com"]);
	});

	it("threads the pre-allocated actionRef into prepareIntent for the committing path", async () => {
		const fake = fakeExecutor();
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		await surface.prepareIntent({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "private",
			sessionRef: "endpoint-private",
			url: "https://shop.example.com/cart",
			verb: "click",
			target: "#pay",
			forceConfirm: true,
			actionRef: "effect-abc",
		});

		expect(fake.prepareRequests[0]?.actionRef).toBe("effect-abc");
		expect(fake.prepareRequests[0]?.forceConfirm).toBe(true);
		expect(fake.prepareRequests[0]?.host).toBe("shop.example.com");
	});
});

function minimalEvidence() {
	return {
		schemaVersion: "telclaude.browser.act-evidence.v1" as const,
		evidenceNonce: "n",
		urlHash: "hmac-sha256:u",
		urlOrigin: "https://shop.example.com",
		domDigest: "sha256:d",
		screenshotHash: "sha256:s",
		screenshotRef: "/relay/media/x.png",
		revision: "hmac-sha256:r",
		submittedValuesHash: "hmac-sha256:v",
		commitSignal: { forceConfirm: false, reasons: [], observed: { navigation: false, formSubmit: false, mutatingRequest: false } },
	};
}

function minimalPrepared(request: { readonly actor: string; readonly profileId: string }) {
	return {
		writeRef: "bwrite-1",
		actor: request.actor,
		approver: "operator:approver",
		profile: request.profileId,
		authorityDomain: "private" as const,
		host: "shop.example.com",
		originScope: ["shop.example.com"],
		evidenceRevision: "hmac-sha256:r",
		evidenceNonce: "n",
		bindingHash: `sha256:${"a".repeat(64)}`,
		display: { verb: "click", target: "#pay-origin", urlOrigin: "https://shop.example.com" },
		commitSignal: { forceConfirm: true, reasons: ["action.verb.click"], observed: { navigation: false, formSubmit: true, mutatingRequest: false } },
		createdAtMs: 1,
		expiresAtMs: 2,
	};
}
