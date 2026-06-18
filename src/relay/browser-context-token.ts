/**
 * Per-context browser proxy token: the credential a relay-issued browser
 * context presents to the S0 CONNECT proxy.
 *
 * The relay is the sole holder of the HMAC signing secret
 * (`TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET`). The broker mints one token per
 * browser context, bound to the observed `tc-browser` peer address plus the
 * relay-stamped `{contextId, sessionRef, actor, cookieBearing, originScope}`.
 * Camoufox presents it on every CONNECT for that context's lifetime; the proxy
 * resolves the context through `createBrowserConnectContextVerifier`.
 *
 * Replay protection is peer-binding plus a finite TTL — the same model as the
 * OpenAI Codex relay token. There is no JTI: the token is a long-lived bearer
 * for one context, not a one-shot side-effect approval. What it cannot do is
 * leave the `tc-browser` peer (peer mismatch), outlive its TTL, or — for a
 * cookie-bearing context — egress outside its hydrated login-origin set (M1,
 * enforced by the verifier and again by the proxy).
 */

import crypto from "node:crypto";

import {
	type BrowserConnectContext,
	type BrowserConnectContextVerification,
	type BrowserConnectContextVerifier,
	buildBrowserOriginScope,
	hostMatchesBrowserOriginScope,
} from "./browser-connect-contract.js";

const BROWSER_CONTEXT_TOKEN_PREFIX = "tc-browser-context-v1";

export const BROWSER_CONTEXT_TOKEN_SECRET_ENV = "TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET";
export const BROWSER_CONTEXT_TOKEN_DEFAULT_TTL_MS = 15 * 60_000;
export const BROWSER_CONTEXT_TOKEN_MIN_TTL_MS = 60_000;
export const BROWSER_CONTEXT_TOKEN_MAX_TTL_MS = 60 * 60_000;

interface BrowserContextTokenPayload {
	readonly version: 1;
	readonly contextId: string;
	readonly sessionRef: string;
	readonly actor: string;
	readonly peerAddress: string;
	readonly cookieBearing: boolean;
	readonly originScope: readonly string[];
	readonly issuedAt: number;
	readonly expiresAt: number;
	// Uniqueness-only marker; replay protection comes from peer binding + expiry.
	readonly nonce: string;
}

export interface MintBrowserContextTokenInput {
	readonly secret: string;
	readonly peerAddress: string;
	readonly contextId: string;
	readonly sessionRef: string;
	readonly actor: string;
	readonly cookieBearing: boolean;
	/** Raw login-origin entries learned at session capture; normalized here. */
	readonly originScope?: readonly string[];
	readonly ttlMs?: number;
	readonly now?: Date;
}

export type VerifiedBrowserContextToken =
	| { readonly ok: true; readonly payload: BrowserContextTokenPayload }
	| { readonly ok: false; readonly reason: string };

/**
 * Mint a per-context browser proxy token. The broker calls this once per
 * context. A cookie-bearing context must carry a non-empty origin scope —
 * minting one without a scope is a relay-side bug and throws.
 */
export function mintBrowserContextToken(input: MintBrowserContextTokenInput): string {
	const now = input.now?.getTime() ?? Date.now();
	const peerAddress = normalizePeerAddress(input.peerAddress);
	if (!peerAddress) {
		throw new Error("browser context token requires a peer address to bind to");
	}
	const contextId = input.contextId.trim();
	const sessionRef = input.sessionRef.trim();
	const actor = input.actor.trim();
	if (!contextId || !sessionRef || !actor) {
		throw new Error("browser context token requires contextId, sessionRef, and actor");
	}
	const originScope = buildBrowserOriginScope(input.originScope ?? []);
	if (input.cookieBearing && originScope.length === 0) {
		throw new Error("cookie-bearing browser context token requires a non-empty origin scope");
	}
	if (!input.cookieBearing && originScope.length > 0) {
		throw new Error("cookie-less browser context token must not carry an origin scope");
	}
	const ttlMs = clampTtl(input.ttlMs ?? BROWSER_CONTEXT_TOKEN_DEFAULT_TTL_MS);
	const payload: BrowserContextTokenPayload = {
		version: 1,
		contextId,
		sessionRef,
		actor,
		peerAddress,
		cookieBearing: input.cookieBearing,
		originScope,
		issuedAt: now,
		expiresAt: now + ttlMs,
		nonce: crypto.randomUUID(),
	};
	const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
	const signature = signBrowserContextToken(encodedPayload, input.secret);
	return `${BROWSER_CONTEXT_TOKEN_PREFIX}.${encodedPayload}.${signature}`;
}

export function verifyBrowserContextToken(
	token: string | null,
	input: { readonly secret: string; readonly peerAddress: string | undefined; readonly now?: Date },
): VerifiedBrowserContextToken {
	if (!token) return { ok: false, reason: "missing token" };
	const parts = token.split(".");
	if (parts.length !== 3 || parts[0] !== BROWSER_CONTEXT_TOKEN_PREFIX) {
		return { ok: false, reason: "token is not a browser context token" };
	}
	const [, encodedPayload, signature] = parts as [string, string, string];
	const expectedSignature = signBrowserContextToken(encodedPayload, input.secret);
	if (!constantTimeEqual(signature, expectedSignature)) {
		return { ok: false, reason: "signature mismatch" };
	}
	let payload: Partial<BrowserContextTokenPayload>;
	try {
		payload = JSON.parse(
			Buffer.from(encodedPayload, "base64url").toString("utf8"),
		) as Partial<BrowserContextTokenPayload>;
	} catch {
		return { ok: false, reason: "payload is not parseable" };
	}
	if (!isValidPayload(payload)) {
		return { ok: false, reason: "payload is invalid" };
	}
	const observedPeer = normalizePeerAddress(input.peerAddress ?? "");
	if (!observedPeer || payload.peerAddress !== observedPeer) {
		return { ok: false, reason: "peer address mismatch" };
	}
	const now = input.now?.getTime() ?? Date.now();
	if (payload.expiresAt <= now) return { ok: false, reason: "token expired" };
	if (payload.issuedAt > now + 5_000) return { ok: false, reason: "token issued in the future" };
	return { ok: true, payload };
}

/**
 * Build the `BrowserConnectContextVerifier` the S0 CONNECT proxy injects. It
 * verifies the per-context token against the proxy-observed peer, then applies
 * M1 origin-scope ALLOW/DENY: a cookie-bearing context may only reach hosts in
 * its hydrated login-origin set; cross-origin targets are denied so the broker
 * forks a fresh cookie-less context.
 */
export function createBrowserConnectContextVerifier(options: {
	readonly secret: string;
	readonly now?: () => Date;
}): BrowserConnectContextVerifier {
	return (input): BrowserConnectContextVerification => {
		const verified = verifyBrowserContextToken(input.token, {
			secret: options.secret,
			peerAddress: input.remoteAddress,
			...(options.now ? { now: options.now() } : {}),
		});
		if (!verified.ok) return { allowed: false, reason: verified.reason };

		const { payload } = verified;
		if (payload.cookieBearing) {
			if (payload.originScope.length === 0) {
				return { allowed: false, reason: "cookie-bearing browser context has no origin scope" };
			}
			if (!hostMatchesBrowserOriginScope(input.targetHost, payload.originScope)) {
				return {
					allowed: false,
					reason: "cookie-bearing browser context cannot egress outside hydrated origin scope",
				};
			}
		}

		const context: BrowserConnectContext = {
			contextId: payload.contextId,
			sessionRef: payload.sessionRef,
			actor: payload.actor,
			hydratedOriginScope: payload.originScope,
			cookieBearing: payload.cookieBearing,
		};
		return { allowed: true, context };
	};
}

function isValidPayload(
	payload: Partial<BrowserContextTokenPayload>,
): payload is BrowserContextTokenPayload {
	return (
		payload.version === 1 &&
		typeof payload.contextId === "string" &&
		payload.contextId.trim().length > 0 &&
		typeof payload.sessionRef === "string" &&
		payload.sessionRef.trim().length > 0 &&
		typeof payload.actor === "string" &&
		payload.actor.trim().length > 0 &&
		typeof payload.peerAddress === "string" &&
		payload.peerAddress.trim().length > 0 &&
		typeof payload.cookieBearing === "boolean" &&
		Array.isArray(payload.originScope) &&
		payload.originScope.every((entry) => typeof entry === "string") &&
		typeof payload.issuedAt === "number" &&
		Number.isFinite(payload.issuedAt) &&
		typeof payload.expiresAt === "number" &&
		Number.isFinite(payload.expiresAt) &&
		typeof payload.nonce === "string" &&
		payload.nonce.trim().length > 0
	);
}

function clampTtl(ttlMs: number): number {
	if (!Number.isFinite(ttlMs)) return BROWSER_CONTEXT_TOKEN_DEFAULT_TTL_MS;
	return Math.min(
		Math.max(ttlMs, BROWSER_CONTEXT_TOKEN_MIN_TTL_MS),
		BROWSER_CONTEXT_TOKEN_MAX_TTL_MS,
	);
}

function signBrowserContextToken(encodedPayload: string, secret: string): string {
	return crypto.createHmac("sha256", secret).update(encodedPayload).digest("base64url");
}

function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function normalizePeerAddress(peerAddress: string): string | undefined {
	const trimmed = peerAddress.trim();
	if (!trimmed) return undefined;
	if (trimmed.startsWith("::ffff:")) return trimmed.slice("::ffff:".length);
	if (trimmed === "::1") return "127.0.0.1";
	return trimmed;
}
