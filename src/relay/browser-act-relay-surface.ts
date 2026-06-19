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
import { buildBrowserOriginScope } from "./browser-connect-contract.js";
import type { BrowserCookieStore } from "./browser-cookie-store.js";
import { browserAuthorityDomainFromMcp } from "./browser-cookie-store.js";
import {
	parseBrowserCatastrophicDomains,
	resolveBrowseSession,
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
	/** Run a NON-committing act inline (fill/type/select/press/non-committing click/goto). */
	act(request: BrowserActSurfaceRequest): Promise<BrowserActInlineResult>;
	/** Stage a COMMITTING act for approval, keyed by the pre-allocated ledger ref. */
	prepareIntent(
		request: BrowserActSurfaceRequest & { readonly actionRef: string },
	): Promise<BrowserActPrepareResult>;
}

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
			const { base } = resolved(request);
			return options.executor.act(base);
		},
		async prepareIntent(request) {
			const { base } = resolved(request);
			// The pool is keyed by the pre-allocated ledger ref so the committer can
			// resolve the held live page later. We thread the SAME ref into the ledger
			// record (caller-supplied prepare ref).
			return options.executor.prepareIntent({ ...base, actionRef: request.actionRef });
		},
	};
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
