import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type {
	BrowserActInlineResult,
	BrowserActPrepareResult,
	BrowserActRequest,
} from "../../src/relay/browser-act-executor.js";
import { createBrowserActExecutorSurface } from "../../src/relay/browser-act-relay-surface.js";
import type { BrowseSession } from "../../src/relay/browser-broker.js";
import { BrowserCookieStore } from "../../src/relay/browser-cookie-store.js";

const COOKIE_KEY = "cookie-store-key-thats-at-least-32-chars-long!";

/**
 * A fake executor that records the resolved `BrowserActRequest` (the surface's
 * output) so the test can assert host / originScope / session resolution without
 * a live browser. It echoes a minimal evidence/prepared result.
 *
 * `landedUrlOrigin` drives the SETTLED `prepared.display.urlOrigin` the executor
 * reports after auto-loading + settling the entry url — the same value the relay's
 * own evidence captures. The surface then re-checks it against the bound origin
 * scope (FIX #2). `null` simulates an opaque/unverifiable landing.
 */
function fakeExecutor(opts: { readonly landedUrlOrigin?: string | null } = {}) {
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
				request: BrowserActRequest & {
					readonly session?: BrowseSession;
					readonly actionRef: string;
				},
			): Promise<BrowserActPrepareResult> {
				prepareRequests.push(request);
				return {
					committing: true,
					record: "browser-write",
					prepared: minimalPrepared(request, opts.landedUrlOrigin),
				};
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

	it("refuses inline acts before reaching the executor, even on a cookie-less public page", async () => {
		const fake = fakeExecutor();
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		await expect(
			surface.act({
				actor: "operator",
				profileId: "ops",
				mcpDomain: "private",
				sessionRef: "endpoint-private",
				url: "https://shop.example.com/cart?step=1",
				verb: "fill",
				target: "#qty",
				submittedValues: "2",
			}),
		).rejects.toMatchObject({ code: "browser_act_inline_disabled" });
		expect(fake.actRequests).toHaveLength(0);
	});

	it("attaches a stored login + its origin scope for a matching authority (via prepareIntent — cookie-bearing acts must prepare)", async () => {
		const createdAt = Date.now();
		store.putSession({
			credentialRef: "cred-shop",
			actorId: "operator",
			profileId: "ops",
			authorityDomain: "private",
			domain: "shop.example.com",
			originScope: ["shop.example.com"],
			storageState: { cookies: [{ name: "sid", value: "x" }] },
			createdAt,
			capturedBy: "operator",
		});
		const fake = fakeExecutor();
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: store,
			catastrophicDomains: [],
		});

		// A cookie-bearing act routes through prepareIntent (human approval); the resolved
		// login + its M1 origin scope are attached to the executor request.
		await surface.prepareIntent({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "private",
			sessionRef: "endpoint-private",
			url: "https://shop.example.com/account",
			verb: "click",
			target: "#open",
			actionRef: "effect-shop-1",
		});

		const resolved = fake.prepareRequests[0];
		expect(resolved?.session).toBeDefined();
		expect(resolved?.session?.credentialRef).toBe("cred-shop");
		expect(resolved?.originScope).toEqual(["shop.example.com"]);
		await expect(
			surface.validatePreparedSession({
				actor: "operator",
				profileId: "ops",
				authorityDomain: "private",
				sessionRef: "endpoint-private",
				host: "shop.example.com",
				originScope: ["shop.example.com"],
				browserCredentialRef: "cred-shop",
				browserCredentialCreatedAt: createdAt,
			}),
		).resolves.toEqual({ ok: true });
		await expect(
			surface.validatePreparedSession({
				actor: "operator",
				profileId: "ops",
				authorityDomain: "private",
				sessionRef: "endpoint-private",
				host: "shop.example.com",
				originScope: ["shop.example.com"],
				browserCredentialRef: "cred-shop",
				browserCredentialCreatedAt: createdAt - 1,
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "browser_write_session_credential_replaced",
		});
		await expect(
			surface.validatePreparedSession({
				actor: "operator",
				profileId: "ops",
				authorityDomain: "private",
				sessionRef: "endpoint-private",
				host: "shop.example.com",
				originScope: ["shop.example.com"],
				browserCredentialRef: "missing-credential",
				browserCredentialCreatedAt: createdAt,
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "browser_write_session_credential_revoked",
		});
	});

	it("refuses an inline act on a resolved logged-in session with the same hard gate", async () => {
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

		await expect(
			surface.act({
				actor: "operator",
				profileId: "ops",
				mcpDomain: "private",
				sessionRef: "endpoint-private",
				url: "https://shop.example.com/settings",
				verb: "fill",
				target: "#notify-email",
				submittedValues: "new@example.com",
			}),
		).rejects.toMatchObject({ code: "browser_act_inline_disabled" });
		expect(fake.actRequests).toHaveLength(0);
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
		await surface.prepareIntent({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "social",
			sessionRef: "endpoint-social",
			url: "https://shop.example.com/account",
			verb: "click",
			target: "#open",
			actionRef: "effect-social",
		});

		expect(fake.prepareRequests[0]?.session).toBeUndefined();
		expect(fake.prepareRequests[0]?.originScope).toEqual(["shop.example.com"]);
		await expect(
			surface.validatePreparedSession({
				actor: "operator",
				profileId: "ops",
				authorityDomain: "public-social",
				sessionRef: "endpoint-social",
				host: "shop.example.com",
				originScope: ["shop.example.com"],
				browserCredentialRef: null,
				browserCredentialCreatedAt: null,
			}),
		).resolves.toEqual({ ok: true });
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

	it("relay-escalates fill/type prepare requests so data entry stages for approval", async () => {
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
			verb: "fill",
			target: "#qty",
			submittedValues: "2",
			actionRef: "effect-fill",
		});

		const resolved = fake.prepareRequests[0];
		expect(resolved?.forceConfirm).toBe(true);
		expect(resolved?.host).toBe("shop.example.com");
		expect(resolved?.originScope).toEqual(["shop.example.com"]);
		expect(resolved?.session).toBeUndefined();
	});
});

describe("browser-act relay surface (FIX #2 — settled landed-origin scope gate)", () => {
	// A cookie-less prepare pins the origin scope to the entry host only
	// (`shop.example.com`). The executor then auto-loads + SETTLES the entry url
	// before capturing evidence, so a tokenized/magic-link redirect could land the
	// live page OFF that scope. The surface re-checks the settled
	// `prepared.display.urlOrigin` against the bound scope and fails closed.

	it("fails closed when the settled landed origin redirected off the bound scope", async () => {
		// Entry url is shop.example.com (scope = [shop.example.com]); the settled
		// page landed on a different registrable domain (an auth/magic-link redirect).
		const fake = fakeExecutor({ landedUrlOrigin: "https://accounts.evil.example.org/session" });
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		await expect(
			surface.prepareIntent({
				actor: "operator",
				profileId: "ops",
				mcpDomain: "private",
				sessionRef: "endpoint-private",
				url: "https://shop.example.com/login",
				verb: "click",
				target: "#submit",
				actionRef: "effect-off-scope",
			}),
		).rejects.toMatchObject({ code: "browser_act_landed_origin_off_scope" });
	});

	it("fails closed when the settled landed origin is opaque/null (unverifiable landing)", async () => {
		// An opaque landing (data:/blob:/about:) reports a null urlOrigin — it can't
		// be matched against the scope, so the gate refuses to bind the write.
		const fake = fakeExecutor({ landedUrlOrigin: null });
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		await expect(
			surface.prepareIntent({
				actor: "operator",
				profileId: "ops",
				mcpDomain: "private",
				sessionRef: "endpoint-private",
				url: "https://shop.example.com/login",
				verb: "click",
				target: "#submit",
				actionRef: "effect-opaque",
			}),
		).rejects.toMatchObject({ code: "browser_act_landed_origin_off_scope" });
	});

	it("fails closed when the settled landed origin is unparseable", async () => {
		// A non-URL settled origin string can't be parsed to a host — same fail-closed.
		const fake = fakeExecutor({ landedUrlOrigin: "not a url" });
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		await expect(
			surface.prepareIntent({
				actor: "operator",
				profileId: "ops",
				mcpDomain: "private",
				sessionRef: "endpoint-private",
				url: "https://shop.example.com/login",
				verb: "click",
				target: "#submit",
				actionRef: "effect-unparseable",
			}),
		).rejects.toMatchObject({ code: "browser_act_landed_origin_off_scope" });
	});

	it("passes an in-origin redirect within the same registrable domain (subdomain)", async () => {
		// A normal in-origin redirect (entry shop.example.com → www.shop.example.com)
		// stays inside the registrable-domain-wide scope and is allowed through.
		const fake = fakeExecutor({ landedUrlOrigin: "https://www.shop.example.com/cart" });
		const surface = createBrowserActExecutorSurface({
			executor: fake.executor,
			cookieStore: null,
			catastrophicDomains: [],
		});

		const staged = await surface.prepareIntent({
			actor: "operator",
			profileId: "ops",
			mcpDomain: "private",
			sessionRef: "endpoint-private",
			url: "https://shop.example.com/cart",
			verb: "click",
			target: "#pay",
			actionRef: "effect-in-scope",
		});

		expect(staged.committing).toBe(true);
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
		commitSignal: {
			forceConfirm: false,
			reasons: [],
			observed: { navigation: false, formSubmit: false, mutatingRequest: false },
		},
	};
}

function minimalPrepared(
	request: { readonly actor: string; readonly profileId: string },
	landedUrlOrigin: string | null = "https://shop.example.com",
) {
	return {
		writeRef: "bwrite-1",
		actor: request.actor,
		approver: "operator:approver",
		profile: request.profileId,
		authorityDomain: "private" as const,
		host: "shop.example.com",
		originScope: ["shop.example.com"],
		browserCredentialRef: null,
		browserCredentialCreatedAt: null,
		evidenceRevision: "hmac-sha256:r",
		evidenceNonce: "n",
		bindingHash: `sha256:${"a".repeat(64)}`,
		evidenceScreenshotHash: `sha256:${"b".repeat(64)}`,
		evidenceScreenshotRef: "/relay/media/x.png",
		display: {
			verb: "click",
			target: "#pay-origin",
			urlOrigin: landedUrlOrigin,
			submittedValues: null,
		},
		commitSignal: {
			forceConfirm: true,
			reasons: ["action.verb.click"],
			observed: { navigation: false, formSubmit: true, mutatingRequest: false },
		},
		createdAtMs: 1,
		expiresAtMs: 2,
	};
}
