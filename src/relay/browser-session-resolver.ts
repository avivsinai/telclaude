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

import type { BrowseRequest, BrowseResult, BrowseSession } from "./browser-broker.js";
import {
	buildBrowserOriginScope,
	hostMatchesBrowserOriginScope,
} from "./browser-connect-contract.js";
import type { BrowserCookieStore } from "./browser-cookie-store.js";

/** Anything that can run a browse — the broker, or a wrapper around it. */
type BrowseRunner = { browse(request: BrowseRequest): Promise<BrowseResult> };

export const BROWSER_CATASTROPHIC_DOMAINS_ENV = "TELCLAUDE_BROWSER_CATASTROPHIC_DOMAINS";

export interface ResolveBrowseSessionOptions {
	/**
	 * Registrable domains where a standing session is NEVER used — a fresh login
	 * is required at use time. Matched against the request host like an origin scope.
	 */
	readonly catastrophicDomains?: readonly string[];
}

/**
 * Parse the operator-declared catastrophic registrable domains (comma- or
 * space-separated) — surfaces like primary email admin or banking that must
 * never run from a standing session.
 */
export function parseBrowserCatastrophicDomains(env: NodeJS.ProcessEnv = process.env): string[] {
	const raw = env[BROWSER_CATASTROPHIC_DOMAINS_ENV]?.trim();
	if (!raw) return [];
	return raw
		.split(/[,\s]+/)
		.map((entry) => entry.trim().toLowerCase())
		.filter(Boolean);
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

/**
 * Wrap a browse runner so every browse first resolves a persistent login from
 * the cookie store. The contained runtime supplies only a URL through
 * `tc_browse`; this wrapper — relay-side — attaches the matching session (or
 * none), so a logged-in browse is never something the model can request or name.
 */
export function createSessionAwareBrowseExecutor(
	runner: BrowseRunner,
	store: BrowserCookieStore,
	options: ResolveBrowseSessionOptions = {},
): BrowseRunner {
	return {
		async browse(request) {
			const session = resolveBrowseSession(store, request.url, options);
			return runner.browse(session ? { ...request, session } : request);
		},
	};
}
