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
import {
	type BrowserCookieStore,
	type BrowserSessionAuthority,
	sessionMatchesAuthority,
} from "./browser-cookie-store.js";

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
	authority: BrowserSessionAuthority,
	options: ResolveBrowseSessionOptions = {},
): BrowseSession | null {
	let host: string;
	try {
		host = new URL(url).hostname.toLowerCase();
	} catch {
		return null;
	}
	if (!host) return null;

	const catastrophicDomains = options.catastrophicDomains ?? [];
	// (a) The entry host itself is a catastrophic surface — never a standing session.
	const catastrophicScope = buildBrowserOriginScope(catastrophicDomains);
	if (catastrophicScope.length > 0 && hostMatchesBrowserOriginScope(host, catastrophicScope)) {
		return null;
	}

	for (const meta of store.listSessions()) {
		// (0) Authority scope: a login resolves ONLY for the same actor/profile/domain
		// it was captured under — a private telegram login never resolves for a
		// social/household/public authority (cross-persona credential bleed).
		if (!sessionMatchesAuthority(meta, authority)) continue;
		if (!hostMatchesBrowserOriginScope(host, meta.originScope)) continue;
		// (b) A session's egress is pinned registrable-domain-wide, so a session whose
		// scope can REACH any catastrophic host (e.g. a google.com session vs a
		// catastrophic myaccount.google.com) would let an in-scope nav/redirect tunnel
		// live cookies onto that surface — the entry-host check (a) alone misses this.
		// Refuse such a session entirely → cookie-less (fresh login at use). Prevention
		// at resolution time is stronger than re-checking finalUrl after cookies flew.
		if (sessionScopeReachesCatastrophic(meta.originScope, catastrophicDomains)) continue;
		const record = store.getSession(meta.credentialRef);
		if (record) {
			return {
				credentialRef: record.credentialRef,
				credentialCreatedAt: record.createdAt,
				storageState: record.storageState,
				originScope: record.originScope,
			};
		}
	}
	return null;
}

/**
 * True if a cookie-bearing context pinned to `sessionScope` could reach any
 * catastrophic host — either the catastrophic host falls within the session's
 * (broader, registrable-domain-wide) scope, or a session origin falls within a
 * catastrophic domain. Either way the session must not be attached.
 */
export function sessionScopeReachesCatastrophic(
	sessionScope: readonly string[],
	catastrophicDomains: readonly string[],
): boolean {
	for (const raw of catastrophicDomains) {
		const domain = raw.trim().toLowerCase();
		if (!domain) continue;
		if (hostMatchesBrowserOriginScope(domain, sessionScope)) return true;
		if (sessionScope.some((origin) => hostMatchesBrowserOriginScope(origin, [domain]))) return true;
	}
	return false;
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
			// The authority is server-stamped on the request (actor/profile/domain);
			// the resolver only attaches a session captured under that same authority.
			const session = resolveBrowseSession(
				store,
				request.url,
				{
					actorId: request.actor,
					profileId: request.profileId,
					authorityDomain: request.authorityDomain,
				},
				options,
			);
			return runner.browse(session ? { ...request, session } : request);
		},
	};
}
