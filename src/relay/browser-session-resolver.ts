/**
 * Relay-side resolution of a persistent login for a browse (S2, M2).
 *
 * The contained runtime only ever supplies a URL through `tc_browse`. The relay
 * — never the model — decides whether a captured session applies: it picks the
 * stored session whose captured login origins cover the requested host, and it
 * refuses to attach any standing session to a catastrophic surface (primary
 * email admin, banking, security settings), which must be a fresh login at use
 * time. The resolved `BrowseSession` is handed to the broker, which hydrates it
 * into a cookie-bearing, origin-pinned (M1), ephemeral (M6) context.
 */

import type { BrowseSession } from "./browser-broker.js";
import {
	buildBrowserOriginScope,
	hostMatchesBrowserOriginScope,
} from "./browser-connect-contract.js";
import type { BrowserCookieStore } from "./browser-cookie-store.js";

export interface ResolveBrowseSessionOptions {
	/**
	 * Registrable domains where a standing session is NEVER used — a fresh login
	 * is required at use time. Matched against the request host like an origin scope.
	 */
	readonly catastrophicDomains?: readonly string[];
}

/**
 * Resolve the persistent login for `url`, or null for a cookie-less browse.
 * Returns null for an unparseable URL, a catastrophic surface, or when no stored
 * session's login origins cover the host.
 */
export function resolveBrowseSession(
	store: BrowserCookieStore,
	url: string,
	options: ResolveBrowseSessionOptions = {},
): BrowseSession | null {
	let host: string;
	try {
		host = new URL(url).hostname.toLowerCase();
	} catch {
		return null;
	}
	if (!host) return null;

	// Catastrophic surfaces never receive a standing session — reuse the same
	// host/origin matcher the per-context token uses, so the policy is consistent.
	const catastrophic = buildBrowserOriginScope(options.catastrophicDomains ?? []);
	if (catastrophic.length > 0 && hostMatchesBrowserOriginScope(host, catastrophic)) {
		return null;
	}

	for (const meta of store.listSessions()) {
		if (!hostMatchesBrowserOriginScope(host, meta.originScope)) continue;
		const record = store.getSession(meta.sessionRef);
		if (record) {
			return { storageState: record.storageState, originScope: record.originScope };
		}
	}
	return null;
}
