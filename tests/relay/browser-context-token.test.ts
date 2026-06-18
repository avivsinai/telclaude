import crypto from "node:crypto";
import type http from "node:http";
import { describe, expect, it } from "vitest";

import {
	buildBrowserOriginScope,
	hostMatchesBrowserOriginScope,
	normalizeBrowserOriginScopeEntry,
} from "../../src/relay/browser-connect-contract.js";
import {
	BROWSER_CONTEXT_TOKEN_MAX_TTL_MS,
	BROWSER_CONTEXT_TOKEN_MIN_TTL_MS,
	BROWSER_CONTEXT_TOKEN_SECRET_ENV,
	createBrowserConnectContextVerifier,
	mintBrowserContextToken,
	resolveBrowserConnectProxyStartup,
	verifyBrowserContextToken,
} from "../../src/relay/browser-context-token.js";

const SECRET = "browser-context-hmac-secret";
const PEER = "198.51.100.11";
const T0 = new Date("2026-06-18T08:00:00.000Z");

function baseMint(overrides: Partial<Parameters<typeof mintBrowserContextToken>[0]> = {}) {
	return mintBrowserContextToken({
		secret: SECRET,
		peerAddress: PEER,
		contextId: "ctx-1",
		sessionRef: "sess-1",
		actor: "telegram:default",
		cookieBearing: false,
		now: T0,
		...overrides,
	});
}

function verifierInput(
	overrides: Partial<{ token: string; targetHost: string; remoteAddress: string }> = {},
): {
	token: string;
	targetHost: string;
	targetPort: number;
	remoteAddress: string;
	headers: http.IncomingHttpHeaders;
} {
	return {
		token: overrides.token ?? "",
		targetHost: overrides.targetHost ?? "example.com",
		targetPort: 443,
		remoteAddress: overrides.remoteAddress ?? PEER,
		headers: {},
	};
}

/** Forge a token directly so we can exercise verifier branches mint refuses to produce. */
function forgeToken(payload: Record<string, unknown>): string {
	const enc = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
	const sig = crypto.createHmac("sha256", SECRET).update(enc).digest("base64url");
	return `tc-browser-context-v1.${enc}.${sig}`;
}

describe("mint/verify browser context token", () => {
	it("round-trips a cookie-less token", () => {
		const token = baseMint();
		const result = verifyBrowserContextToken(token, { secret: SECRET, peerAddress: PEER, now: T0 });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.payload.cookieBearing).toBe(false);
			expect(result.payload.originScope).toEqual([]);
			expect(result.payload.peerAddress).toBe(PEER);
		}
	});

	it("round-trips a cookie-bearing token and normalizes the origin scope", () => {
		const token = baseMint({
			cookieBearing: true,
			originScope: ["https://accounts.google.com/", "GOOGLE.com", "google.com"],
		});
		const result = verifyBrowserContextToken(token, { secret: SECRET, peerAddress: PEER, now: T0 });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.payload.cookieBearing).toBe(true);
			expect(result.payload.originScope).toEqual(["accounts.google.com", "google.com"]);
		}
	});

	it("rejects a wrong-peer presentation", () => {
		const token = baseMint();
		const result = verifyBrowserContextToken(token, {
			secret: SECRET,
			peerAddress: "203.0.113.9",
			now: T0,
		});
		expect(result).toEqual({ ok: false, reason: "peer address mismatch" });
	});

	it("normalizes ::ffff: and ::1 peer forms on both ends", () => {
		const token = mintBrowserContextToken({
			secret: SECRET,
			peerAddress: "::ffff:198.51.100.11",
			contextId: "ctx-1",
			sessionRef: "sess-1",
			actor: "telegram:default",
			cookieBearing: false,
			now: T0,
		});
		const result = verifyBrowserContextToken(token, {
			secret: SECRET,
			peerAddress: "198.51.100.11",
			now: T0,
		});
		expect(result.ok).toBe(true);
	});

	it("rejects an expired token", () => {
		const token = baseMint({ ttlMs: BROWSER_CONTEXT_TOKEN_MIN_TTL_MS });
		const later = new Date(T0.getTime() + BROWSER_CONTEXT_TOKEN_MIN_TTL_MS + 1);
		const result = verifyBrowserContextToken(token, {
			secret: SECRET,
			peerAddress: PEER,
			now: later,
		});
		expect(result).toEqual({ ok: false, reason: "token expired" });
	});

	it("rejects a token issued in the future", () => {
		const token = baseMint();
		const earlier = new Date(T0.getTime() - 10_000);
		const result = verifyBrowserContextToken(token, {
			secret: SECRET,
			peerAddress: PEER,
			now: earlier,
		});
		expect(result).toEqual({ ok: false, reason: "token issued in the future" });
	});

	it("rejects a tampered signature", () => {
		const token = baseMint();
		const tampered = `${token.slice(0, -2)}xy`;
		const result = verifyBrowserContextToken(tampered, {
			secret: SECRET,
			peerAddress: PEER,
			now: T0,
		});
		expect(result).toEqual({ ok: false, reason: "signature mismatch" });
	});

	it("rejects a token whose components are not base64url before any crypto work", () => {
		const result = verifyBrowserContextToken("tc-browser-context-v1.bad payload!.sig", {
			secret: SECRET,
			peerAddress: PEER,
			now: T0,
		});
		expect(result).toEqual({ ok: false, reason: "token components are malformed" });
	});

	it("rejects a token signed with a different secret", () => {
		const token = baseMint();
		const result = verifyBrowserContextToken(token, {
			secret: "other-secret",
			peerAddress: PEER,
			now: T0,
		});
		expect(result).toEqual({ ok: false, reason: "signature mismatch" });
	});

	it("rejects a foreign token prefix and a missing token", () => {
		expect(
			verifyBrowserContextToken("tc-openai-codex-relay-v1.a.b", {
				secret: SECRET,
				peerAddress: PEER,
			}),
		).toEqual({ ok: false, reason: "token is not a browser context token" });
		expect(verifyBrowserContextToken(null, { secret: SECRET, peerAddress: PEER })).toEqual({
			ok: false,
			reason: "missing token",
		});
	});

	it("clamps TTL into [min, max]", () => {
		const tooShort = baseMint({ ttlMs: 1 });
		const justAfterMin = new Date(T0.getTime() + BROWSER_CONTEXT_TOKEN_MIN_TTL_MS - 1);
		expect(
			verifyBrowserContextToken(tooShort, { secret: SECRET, peerAddress: PEER, now: justAfterMin })
				.ok,
		).toBe(true);

		const tooLong = baseMint({ ttlMs: BROWSER_CONTEXT_TOKEN_MAX_TTL_MS * 10 });
		const pastMax = new Date(T0.getTime() + BROWSER_CONTEXT_TOKEN_MAX_TTL_MS + 1);
		expect(
			verifyBrowserContextToken(tooLong, { secret: SECRET, peerAddress: PEER, now: pastMax }).ok,
		).toBe(false);
	});

	it("refuses to mint a cookie-bearing token without an origin scope", () => {
		expect(() => baseMint({ cookieBearing: true })).toThrow(/non-empty origin scope/);
	});

	it("refuses to mint a cookie-less token that carries an origin scope", () => {
		expect(() => baseMint({ cookieBearing: false, originScope: ["google.com"] })).toThrow(
			/must not carry an origin scope/,
		);
	});

	it("refuses to mint without contextId/sessionRef/actor or peer", () => {
		expect(() => baseMint({ contextId: " " })).toThrow(/contextId, sessionRef, and actor/);
		expect(() => baseMint({ peerAddress: "" })).toThrow(/peer address/);
	});
});

describe("createBrowserConnectContextVerifier — M1 origin scope", () => {
	const verify = createBrowserConnectContextVerifier({ secret: SECRET, now: () => T0 });

	it("allows a cookie-less context to any public host", () => {
		const token = baseMint();
		const result = verify(verifierInput({ token, targetHost: "anything.example.org" }));
		expect(result.allowed).toBe(true);
		expect(result.context?.cookieBearing).toBe(false);
		expect(result.context?.hydratedOriginScope).toEqual([]);
	});

	it("allows a cookie-bearing context to its registrable domain and subdomains", () => {
		const token = baseMint({ cookieBearing: true, originScope: ["google.com"] });
		expect(verify(verifierInput({ token, targetHost: "google.com" })).allowed).toBe(true);
		expect(verify(verifierInput({ token, targetHost: "accounts.google.com" })).allowed).toBe(true);
		const ctx = verify(verifierInput({ token, targetHost: "mail.google.com" })).context;
		expect(ctx?.sessionRef).toBe("sess-1");
		expect(ctx?.actor).toBe("telegram:default");
	});

	it("denies a cookie-bearing context egress outside its hydrated origin scope", () => {
		const token = baseMint({ cookieBearing: true, originScope: ["google.com"] });
		const result = verify(verifierInput({ token, targetHost: "evil.com" }));
		expect(result.allowed).toBe(false);
		expect(result.reason).toMatch(/outside hydrated origin scope/);
	});

	it("denies a look-alike sibling domain (boundary safety)", () => {
		const token = baseMint({ cookieBearing: true, originScope: ["google.com"] });
		expect(verify(verifierInput({ token, targetHost: "evilgoogle.com" })).allowed).toBe(false);
		expect(verify(verifierInput({ token, targetHost: "google.com.evil.com" })).allowed).toBe(false);
	});

	it("propagates token-verification failures as denials", () => {
		const token = baseMint();
		const result = verify(verifierInput({ token, remoteAddress: "203.0.113.9" }));
		expect(result).toEqual({ allowed: false, reason: "peer address mismatch" });
	});

	it("denies a forged cookie-bearing token with an empty scope (defense in depth)", () => {
		const forged = forgeToken({
			version: 1,
			contextId: "ctx-1",
			sessionRef: "sess-1",
			actor: "telegram:default",
			peerAddress: PEER,
			cookieBearing: true,
			originScope: [],
			issuedAt: T0.getTime(),
			expiresAt: T0.getTime() + 60_000,
			nonce: "n",
		});
		const result = verify(verifierInput({ token: forged, targetHost: "google.com" }));
		expect(result.allowed).toBe(false);
		expect(result.reason).toMatch(/no origin scope/);
	});
});

describe("origin-scope policy helpers", () => {
	it("matches subdomains and rejects look-alikes", () => {
		expect(hostMatchesBrowserOriginScope("accounts.google.com", ["google.com"])).toBe(true);
		expect(hostMatchesBrowserOriginScope("google.com", ["google.com"])).toBe(true);
		expect(hostMatchesBrowserOriginScope("evilgoogle.com", ["google.com"])).toBe(false);
		expect(hostMatchesBrowserOriginScope("google.com.evil.com", ["google.com"])).toBe(false);
		expect(hostMatchesBrowserOriginScope("notgoogle.com", ["google.com"])).toBe(false);
	});

	it("matches a URL scope entry against its host", () => {
		expect(
			hostMatchesBrowserOriginScope("accounts.google.com", ["https://accounts.google.com/x"]),
		).toBe(true);
		expect(hostMatchesBrowserOriginScope("google.com", ["https://accounts.google.com/x"])).toBe(
			false,
		);
	});

	it("normalizes URL and trailing-dot entries, rejects IPs and single labels", () => {
		expect(normalizeBrowserOriginScopeEntry("HTTPS://Mail.Google.COM/inbox")).toBe(
			"mail.google.com",
		);
		expect(normalizeBrowserOriginScopeEntry("google.com.")).toBe("google.com");
		expect(normalizeBrowserOriginScopeEntry("localhost")).toBeNull();
		expect(normalizeBrowserOriginScopeEntry("203.0.113.4")).toBeNull();
		expect(normalizeBrowserOriginScopeEntry("")).toBeNull();
	});

	it("builds a deduplicated normalized scope and drops invalid entries", () => {
		expect(buildBrowserOriginScope(["google.com", "GOOGLE.com", "bad host", "x.io"])).toEqual([
			"google.com",
			"x.io",
		]);
	});
});

describe("resolveBrowserConnectProxyStartup — fail-closed wiring", () => {
	it("is disabled when the proxy is not enabled", () => {
		expect(resolveBrowserConnectProxyStartup({}).action).toBe("disabled");
		expect(
			resolveBrowserConnectProxyStartup({
				TELCLAUDE_BROWSER_CONNECT_PROXY_ENABLED: "0",
				[BROWSER_CONTEXT_TOKEN_SECRET_ENV]: SECRET,
			}).action,
		).toBe("disabled");
	});

	it("fails closed when enabled without a context-token secret", () => {
		const missing = resolveBrowserConnectProxyStartup({
			TELCLAUDE_BROWSER_CONNECT_PROXY_ENABLED: "1",
		});
		expect(missing.action).toBe("fail-closed");
		if (missing.action === "fail-closed") {
			expect(missing.reason).toContain(BROWSER_CONTEXT_TOKEN_SECRET_ENV);
		}

		const blank = resolveBrowserConnectProxyStartup({
			TELCLAUDE_BROWSER_CONNECT_PROXY_ENABLED: "1",
			[BROWSER_CONTEXT_TOKEN_SECRET_ENV]: "   ",
		});
		expect(blank.action).toBe("fail-closed");
	});

	it("starts with a working verifier when enabled and a secret is present", async () => {
		const decision = resolveBrowserConnectProxyStartup({
			TELCLAUDE_BROWSER_CONNECT_PROXY_ENABLED: "1",
			[BROWSER_CONTEXT_TOKEN_SECRET_ENV]: SECRET,
		});
		expect(decision.action).toBe("start");
		if (decision.action !== "start") throw new Error("expected start");
		// The verifier it hands back must actually validate a token minted with the
		// same secret — proving it was wired with the real secret, not a placeholder.
		// The helper builds the verifier without a `now` override, so it checks
		// against real wall-clock time; mint with the default (real) clock too.
		const token = mintBrowserContextToken({
			secret: SECRET,
			peerAddress: PEER,
			contextId: "ctx-1",
			sessionRef: "sess-1",
			actor: "telegram:default",
			cookieBearing: false,
		});
		const allowed = await decision.contextVerifier({
			token,
			targetHost: "example.org",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(allowed).toMatchObject({ allowed: true });
		// A token minted with a different secret must be rejected.
		const foreign = mintBrowserContextToken({
			secret: "different-secret",
			peerAddress: PEER,
			contextId: "ctx-1",
			sessionRef: "sess-1",
			actor: "telegram:default",
			cookieBearing: false,
		});
		const denied = await decision.contextVerifier({
			token: foreign,
			targetHost: "example.org",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(denied.allowed).toBe(false);
	});
});
