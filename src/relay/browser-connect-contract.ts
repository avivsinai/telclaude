/**
 * Shared contract for the relay-owned browser CONNECT proxy seam.
 *
 * This module is the single source of truth for the wire types exchanged
 * between the S0 CONNECT proxy (`browser-connect-proxy.ts`) and the
 * broker/session layer's per-context verifier (`browser-context-token.ts`).
 * The proxy injects a `BrowserConnectContextVerifier`; the broker mints the
 * per-context tokens that verifier validates. Keeping the types here means
 * neither side has to import the other's implementation file.
 *
 * It also owns the M1 origin-scope policy: while a browser context carries a
 * hydrated login for an approved origin set, the proxy must restrict its
 * CONNECT targets to that set, and a cross-origin navigation forks a fresh
 * cookie-less context. The relay learns the login-origin set at session
 * capture; this module normalizes and matches against it.
 */

import type http from "node:http";

import { getDomain } from "tldts";

/**
 * Resolved identity of a single browser context, as produced by the verifier
 * from a relay-issued per-context token. The contained runtime never names any
 * of these fields — they are server-stamped and bound to the token.
 */
export interface BrowserConnectContext {
	readonly contextId: string;
	readonly sessionRef?: string;
	readonly actor?: string;
	/**
	 * M1 login-origin set for a cookie-bearing context: the approved hosts/
	 * registrable domains this context may egress to while hydrated. Empty for
	 * cookie-less (unauthenticated public) contexts, which egress freely.
	 */
	readonly hydratedOriginScope?: readonly string[];
	readonly cookieBearing?: boolean;
}

export interface BrowserConnectContextVerification {
	readonly allowed: boolean;
	readonly context?: BrowserConnectContext;
	readonly reason?: string;
}

export interface BrowserConnectContextVerificationInput {
	readonly token: string;
	readonly targetHost: string;
	readonly targetPort: number;
	readonly remoteAddress: string;
	readonly headers: http.IncomingHttpHeaders;
}

export type BrowserConnectContextVerifier = (
	input: BrowserConnectContextVerificationInput,
) => BrowserConnectContextVerification | Promise<BrowserConnectContextVerification>;

/**
 * Sentinel proxy username the broker sets on a browser context's proxy
 * credentials. Firefox/Camoufox under Playwright cannot set a Bearer or a
 * custom CONNECT header, so the per-context token rides the proxy *password*
 * field and reaches the proxy as `Proxy-Authorization: Basic b64(user:pass)`.
 * The username is this fixed marker so the proxy can distinguish a relay-minted
 * browser-context credential from any other Basic auth and pull the token from
 * the password component. The username is not a secret — the HMAC token is.
 */
export const BROWSER_CONTEXT_PROXY_BASIC_USERNAME = "tc-browser-context";

/**
 * Normalize a single origin-scope entry to a bare hostname.
 *
 * Accepts either a URL (`https://accounts.google.com/...`) or a bare host
 * (`google.com`). Returns the lowercased hostname, or null if the entry is not
 * a plausible login-origin host. IP literals and single-label names are
 * rejected: login origins are registrable domains, never raw addresses.
 */
export function normalizeBrowserOriginScopeEntry(entry: string): string | null {
	const trimmed = entry.trim().toLowerCase();
	if (!trimmed) return null;
	let host = trimmed;
	if (trimmed.includes("://")) {
		try {
			host = new URL(trimmed).hostname;
		} catch {
			return null;
		}
	}
	return normalizeBrowserHost(host);
}

/**
 * True when `host` falls inside the hydrated origin scope. Each scope entry is
 * treated as a registrable domain: the entry itself and any subdomain match.
 * Boundary-safe — `evilexample.com` does not match scope `example.com`.
 */
export function hostMatchesBrowserOriginScope(host: string, scope: readonly string[]): boolean {
	const normalizedHost = normalizeBrowserHost(host);
	if (!normalizedHost) return false;
	for (const rawEntry of scope) {
		const entry = normalizeBrowserOriginScopeEntry(rawEntry);
		if (!entry) continue;
		if (normalizedHost === entry) return true;
		if (normalizedHost.endsWith(`.${entry}`)) return true;
	}
	return false;
}

/**
 * Build a deduplicated, normalized origin scope from raw entries learned at
 * session capture. Invalid entries are dropped rather than failing the set.
 */
export function buildBrowserOriginScope(entries: readonly string[]): string[] {
	const normalized: string[] = [];
	const seen = new Set<string>();
	for (const entry of entries) {
		const host = normalizeBrowserOriginScopeEntry(entry);
		if (!host || seen.has(host)) continue;
		seen.add(host);
		normalized.push(host);
	}
	return normalized;
}

function normalizeBrowserHost(host: string): string | null {
	const trimmed = host.trim().toLowerCase().replace(/\.$/, "");
	if (!trimmed || trimmed.length > 253) return null;
	if (trimmed.includes("..") || trimmed.startsWith(".")) return null;
	if (!/^[a-z0-9.-]+$/.test(trimmed)) return null;
	if (!trimmed.includes(".")) return null;
	// Reject bare IPv4 literals — origin scopes are registrable domains.
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return null;
	// Reject bare public suffixes (co.uk, com, github.io): a scope/host keyed to an
	// eTLD would match EVERY tenant under it (cross-tenant egress). tldts returns null
	// for a public suffix; a real host resolves to its eTLD+1, and a subdomain resolves
	// to its registrable parent. allowPrivateDomains:true is deliberate — it treats the
	// PSL private section (github.io, herokuapp.com, s3.amazonaws.com) as suffixes too,
	// so a github.io login can't ride cookies onto victim.github.io.
	if (!getDomain(trimmed, { allowPrivateDomains: true })) return null;
	return trimmed;
}
