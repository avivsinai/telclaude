/**
 * Relay-side adapter that the served MCP drives for interactive browser acts (S3).
 *
 * This is the production analog to `createSessionAwareBrowseExecutor` for the
 * write path: it takes the server-stamped authority + the runtime-named action
 * (verb/target/values/url) and resolves EVERYTHING the model may not name —
 * the registrable host (from the url), the cookie-bearing session, and the M1
 * origin scope — exactly the way `tc_browse` does (#171 authority scoping, #172
 * PSL/catastrophic refusal). It then drives the relay-owned `BrowserActExecutor`.
 *
 * The contained runtime never reaches this directly; the live MCP server stamps
 * `actor/profileId/mcpDomain/sessionRef` from the peer-bound authority handle and
 * strips any client-supplied authority/session/token fields BEFORE the request
 * arrives here. This surface never trusts a runtime-supplied session, host, or
 * origin scope — it resolves them itself, server-side.
 */

import type { BrowserActJsonValue } from "./browser-act-evidence.js";
import type {
	BrowserActExecutor,
	BrowserActInlineResult,
	BrowserActPrepareResult,
	BrowserActRequest,
	BrowserActVerb,
} from "./browser-act-executor.js";
import type { BrowseSession } from "./browser-broker.js";
import {
	buildBrowserOriginScope,
	hostMatchesBrowserOriginScope,
} from "./browser-connect-contract.js";
import type { BrowserAuthorityDomain, BrowserCookieStore } from "./browser-cookie-store.js";
import { browserAuthorityDomainFromMcp, sessionMatchesAuthority } from "./browser-cookie-store.js";
import {
	parseBrowserCatastrophicDomains,
	resolveBrowseSession,
	sessionScopeReachesCatastrophic,
} from "./browser-session-resolver.js";

/**
 * A server-resolved interactive act request as the relay-clients layer hands it
 * to the surface. Authority (`actor`/`profileId`/`mcpDomain`/`sessionRef`) is
 * stamped by the live MCP server; the runtime supplies only `url`/`verb`/
 * `target`/`submittedValues`/`forceConfirm`/`timeoutMs`. Host + session + origin
 * scope are resolved here, never named by the runtime.
 */
export interface BrowserActSurfaceRequest {
	readonly actor: string;
	readonly profileId: string;
	/** MCP trust domain (`private|social|household|public|specialist`). */
	readonly mcpDomain: string;
	readonly sessionRef: string;
	readonly url: string;
	readonly verb: BrowserActVerb;
	readonly target?: string;
	readonly submittedValues?: BrowserActJsonValue;
	readonly forceConfirm?: boolean;
	readonly settleTimeoutMs?: number;
}

/** The narrow surface the live-relay-clients layer calls for browser acts. */
export interface BrowserActExecutorSurface {
	/** Refuse inline acts; all browser interactions must prepare + approve + execute. */
	act(request: BrowserActSurfaceRequest): Promise<BrowserActInlineResult>;
	/** Stage a COMMITTING act for approval, keyed by the pre-allocated ledger ref. */
	prepareIntent(
		request: BrowserActSurfaceRequest & { readonly actionRef: string },
	): Promise<BrowserActPrepareResult>;
	/** Revalidate the current credential/session binding before an approved execute commits. */
	validatePreparedSession(
		binding: BrowserActPreparedSessionBinding,
	): Promise<BrowserActPreparedSessionValidation>;
}

export interface BrowserActPreparedSessionBinding {
	readonly actor: string;
	readonly profileId: string;
	readonly authorityDomain: BrowserAuthorityDomain;
	readonly sessionRef: string;
	readonly host: string;
	readonly originScope: readonly string[];
	readonly browserCredentialRef: string | null;
	readonly browserCredentialCreatedAt: number | null;
}

export type BrowserActPreparedSessionValidation =
	| { readonly ok: true }
	| { readonly ok: false; readonly code: string; readonly reason: string };

export class BrowserActSurfaceError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.code = code;
		this.name = "BrowserActSurfaceError";
	}
}

export interface CreateBrowserActExecutorSurfaceOptions {
	readonly executor: BrowserActExecutor;
	/**
	 * Relay-owned encrypted cookie store. When null, every act runs cookie-less
	 * (public-only) — there is no privileged act without a resolved login. Mirrors
	 * the browse path: a missing store is not an error, just no session.
	 */
	readonly cookieStore: BrowserCookieStore | null;
	/** Operator-declared catastrophic registrable domains; default from env. */
	readonly catastrophicDomains?: readonly string[];
}

/**
 * Build the production `BrowserActExecutorSurface`. The injected executor must be
 * constructed with the real `createBrowserActDriverFactory` (which reads
 * `request.session` to hydrate the cookie-bearing context). This surface resolves
 * the session ONCE per act and attaches it to the executor request, so the
 * binding's `host`/`originScope` and the driver's `storageState` come from the
 * SAME resolved login.
 */
export function createBrowserActExecutorSurface(
	options: CreateBrowserActExecutorSurfaceOptions,
): BrowserActExecutorSurface {
	const catastrophicDomains = options.catastrophicDomains ?? parseBrowserCatastrophicDomains();
	const forceConfirmVerbs = new Set<BrowserActVerb>(["fill", "type"]);

	const resolved = (
		request: BrowserActSurfaceRequest,
	): { readonly base: BrowserActRequest & { readonly session?: BrowseSession } } => {
		const host = hostFor(request.url);
		const authorityDomain = browserAuthorityDomainFromMcp(request.mcpDomain);
		// Resolve the cookie-bearing login the SAME way tc_browse does — by the
		// request's server-stamped authority (#171) and the url, with PSL +
		// catastrophic refusal (#172). The runtime never names the session.
		const session = options.cookieStore
			? resolveBrowseSession(
					options.cookieStore,
					request.url,
					{ actorId: request.actor, profileId: request.profileId, authorityDomain },
					{ catastrophicDomains },
				)
			: null;
		// originScope is the resolved session's M1 login-origin set; a cookie-less
		// act pins egress to the entry host only.
		const originScope = session
			? buildBrowserOriginScope([...session.originScope])
			: buildBrowserOriginScope([host]);
		const base: BrowserActRequest & { readonly session?: BrowseSession } = {
			actor: request.actor,
			profileId: request.profileId,
			mcpDomain: request.mcpDomain,
			sessionRef: request.sessionRef,
			host,
			originScope,
			// Thread the SERVER-RESOLVED entry url so the driver auto-loads the page to
			// it before capture/dispatch (Option A). This is the same already-validated
			// + secret-preflighted tool `url` that `host`/`originScope` are derived from
			// — never a separate runtime-controlled navigation. An off-scope entry url is
			// denied by the M1 origin-pinned CONNECT proxy at the network layer.
			url: request.url,
			verb: request.verb,
			...(request.target !== undefined ? { target: request.target } : {}),
			...(request.submittedValues !== undefined
				? { submittedValues: request.submittedValues }
				: {}),
			...(request.forceConfirm !== undefined ? { forceConfirm: request.forceConfirm } : {}),
			...(request.settleTimeoutMs !== undefined
				? { settleTimeoutMs: request.settleTimeoutMs }
				: {}),
			...(session ? { session } : {}),
		};
		return { base };
	};

	return {
		async act(request) {
			resolved(request);
			throw new BrowserActSurfaceError(
				"browser_act_inline_disabled",
				"inline browser acts are disabled; use prepareIntent + human approval",
			);
		},
		async prepareIntent(request) {
			const { base } = resolved(request);
			// The pool is keyed by the pre-allocated ledger ref so the committer can
			// resolve the held live page later. We thread the SAME ref into the ledger
			// record (caller-supplied prepare ref).
			const staged = await options.executor.prepareIntent({
				...base,
				...(forceConfirmVerbs.has(base.verb) ? { forceConfirm: true } : {}),
				actionRef: request.actionRef,
			});
			// FIX #2 — the session/authentication classification (host, originScope,
			// cookie-bearing-vs-public) was resolved from the PRE-navigation entry url.
			// The executor then auto-loads the entry url and SETTLES the page before
			// capturing evidence, so a tokenized/magic-link redirect could have landed
			// the live page OFF the resolved origin scope — e.g. a cookie-less browse
			// that becomes authenticated on a different origin after the entry nav.
			// The write was bound under the stale classification. Re-check the SETTLED
			// landed origin (captured by the evidence, not runtime-supplied) against the
			// origin scope the write is bound to: if it escaped, fail closed rather than
			// commit a write bound to the wrong domain/session. A normal in-origin
			// redirect stays within the registrable-domain-wide scope and is allowed.
			assertLandedOriginInScope(staged.prepared.display.urlOrigin, base.originScope);
			return staged;
		},
		async validatePreparedSession(binding) {
			return validateBrowserActPreparedSession(binding, options.cookieStore, catastrophicDomains);
		},
	};
}

function validateBrowserActPreparedSession(
	binding: BrowserActPreparedSessionBinding,
	cookieStore: BrowserCookieStore | null,
	catastrophicDomains: readonly string[],
): BrowserActPreparedSessionValidation {
	const host = binding.host.trim().toLowerCase();
	if (!host || !binding.sessionRef.trim()) {
		return {
			ok: false,
			code: "browser_write_session_binding_invalid",
			reason: "browser-write session binding is missing host or sessionRef",
		};
	}
	const boundScope = buildBrowserOriginScope(binding.originScope);
	const authority = {
		actorId: binding.actor,
		profileId: binding.profileId,
		authorityDomain: binding.authorityDomain,
	};
	if (binding.browserCredentialRef) {
		if (!cookieStore) {
			return {
				ok: false,
				code: "browser_write_session_store_unavailable",
				reason:
					"browser-write was prepared with a stored browser credential but no credential store is configured",
			};
		}
		const session = cookieStore.getSession(binding.browserCredentialRef);
		if (!session) {
			return {
				ok: false,
				code: "browser_write_session_credential_revoked",
				reason: "browser-write credential is no longer present; re-prepare",
			};
		}
		if (binding.browserCredentialCreatedAt === null) {
			return {
				ok: false,
				code: "browser_write_session_binding_invalid",
				reason: "browser-write credential binding is missing its creation timestamp",
			};
		}
		if (session.createdAt !== binding.browserCredentialCreatedAt) {
			return {
				ok: false,
				code: "browser_write_session_credential_replaced",
				reason: "browser-write credential was replaced after approval; re-prepare",
			};
		}
		if (!sessionMatchesAuthority(session, authority)) {
			return {
				ok: false,
				code: "browser_write_session_authority_changed",
				reason: "browser-write credential authority no longer matches the prepared write",
			};
		}
		if (!hostMatchesBrowserOriginScope(host, session.originScope)) {
			return {
				ok: false,
				code: "browser_write_session_host_uncovered",
				reason: "browser-write credential no longer covers the prepared host",
			};
		}
		if (sessionScopeReachesCatastrophic(session.originScope, catastrophicDomains)) {
			return {
				ok: false,
				code: "browser_write_session_catastrophic",
				reason: "browser-write credential can now reach a catastrophic domain; re-prepare",
			};
		}
		if (!sameOriginScope(boundScope, buildBrowserOriginScope(session.originScope))) {
			return {
				ok: false,
				code: "browser_write_session_origin_scope_changed",
				reason: "browser-write credential origin scope changed after approval; re-prepare",
			};
		}
		return { ok: true };
	}

	const currentSession = cookieStore
		? resolveBrowseSession(cookieStore, `https://${host}/`, authority, { catastrophicDomains })
		: null;
	if (currentSession) {
		return {
			ok: false,
			code: "browser_write_session_credential_changed",
			reason:
				"browser-write was prepared cookie-less but a stored credential now applies; re-prepare",
		};
	}
	if (!sameOriginScope(boundScope, buildBrowserOriginScope([host]))) {
		return {
			ok: false,
			code: "browser_write_session_origin_scope_changed",
			reason: "browser-write cookie-less origin scope changed after approval; re-prepare",
		};
	}
	return { ok: true };
}

function sameOriginScope(left: readonly string[], right: readonly string[]): boolean {
	const a = buildBrowserOriginScope(left);
	const b = buildBrowserOriginScope(right);
	return a.length === b.length && a.every((entry, index) => entry === b[index]);
}

/**
 * Fail closed unless the SETTLED landed origin (the page the committing act will
 * actually run on, captured by the relay's own evidence) is still inside the
 * origin scope the prepared write was bound under. This catches an entry
 * navigation that redirected OFF the resolved scope — including a public/
 * cookie-less browse that became authenticated on a different origin via a
 * magic-link or tokenized redirect — so a write is never bound to one domain/
 * session and then committed against another. A normal in-origin redirect lands
 * within the registrable-domain-wide scope and passes.
 *
 * RESIDUAL (accepted, not a gate): this closes OFF-origin redirects only. A
 * SAME-origin magic link that authenticates mid-navigation (e.g. a cookie-less
 * browse that becomes logged-in on the SAME registrable domain) lands in scope
 * and passes the origin check — so we do NOT claim the public-vs-cookie-bearing
 * classification is closed for same-origin auth. That case is backstopped by the
 * two-phase human approval: the operator sees the WYSIWYS binding before any
 * write commits, so a silent in-origin privilege flip can't auto-execute.
 */
function assertLandedOriginInScope(
	landedOrigin: string | null,
	originScope: readonly string[],
): void {
	// An opaque-origin landing (data:/blob:/about:) can't be matched against the
	// scope — treat it as off-scope and fail closed.
	if (!landedOrigin) {
		throw new BrowserActSurfaceError(
			"browser_act_landed_origin_off_scope",
			"entry navigation settled on an unverifiable origin; refusing to bind a browser write",
		);
	}
	let landedHost: string;
	try {
		landedHost = new URL(landedOrigin).hostname.toLowerCase();
	} catch {
		throw new BrowserActSurfaceError(
			"browser_act_landed_origin_off_scope",
			"entry navigation settled on an unparseable origin; refusing to bind a browser write",
		);
	}
	if (!hostMatchesBrowserOriginScope(landedHost, originScope)) {
		throw new BrowserActSurfaceError(
			"browser_act_landed_origin_off_scope",
			"entry navigation redirected off the resolved origin scope; the page the write would run on does not match the classification it was bound under",
		);
	}
}

function hostFor(url: string): string {
	let host: string;
	try {
		host = new URL(url).hostname.toLowerCase();
	} catch {
		throw new BrowserActSurfaceError(
			"browser_act_url_invalid",
			"browser act url is not a valid URL",
		);
	}
	if (!host) {
		throw new BrowserActSurfaceError("browser_act_url_invalid", "browser act url has no host");
	}
	return host;
}
