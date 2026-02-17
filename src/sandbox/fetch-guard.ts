/**
 * DNS-Pinned Fetch Guard
 *
 * Prevents SSRF via DNS rebinding and redirect-based attacks:
 * 1. Resolves hostname via cachedDNSLookup() — validates ALL IPs
 * 2. Creates undici Agent with pinned DNS lookup (TCP uses validated IPs only)
 * 3. Follows redirects manually, re-validating each hop's hostname
 * 4. Caps redirect count and detects loops
 *
 * Backported from OpenClaw's fetch-guard pattern.
 */

import type { LookupAddress, LookupOptions } from "node:dns";
import { Agent } from "undici";
import { getChildLogger } from "../logging.js";
import { cachedDNSLookup, isBlockedIP, isNonOverridableBlock } from "./network-proxy.js";

const logger = getChildLogger({ module: "fetch-guard" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type FetchWithGuardOptions = {
	/** URL to fetch */
	url: string;
	/** Standard fetch RequestInit (headers, method, body, etc.) */
	init?: RequestInit;
	/** Maximum number of redirects to follow (default: 3) */
	maxRedirects?: number;
	/** Timeout in milliseconds */
	timeoutMs?: number;
	/** External abort signal */
	signal?: AbortSignal;
	/** Context string for audit logging */
	auditContext?: string;
};

export type FetchWithGuardResult = {
	/** The final HTTP response */
	response: Response;
	/** The final URL after all redirects */
	finalUrl: string;
	/** Call to release the underlying dispatcher resources */
	release: () => Promise<void>;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Pinned DNS Lookup
// ═══════════════════════════════════════════════════════════════════════════════

type DnsLookupCallback = (
	err: NodeJS.ErrnoException | null,
	address: string | LookupAddress[],
	family?: number,
) => void;

/**
 * Create a DNS lookup function that returns pre-resolved (pinned) IP addresses
 * for a specific hostname. All other hostnames fall through to the system resolver.
 *
 * SECURITY: This ensures the TCP connection uses the exact IPs we validated,
 * preventing TOCTOU races between DNS resolution and connection establishment.
 */
export function createPinnedLookup(
	hostname: string,
	addresses: string[],
): (hostname: string, options: LookupOptions, callback: DnsLookupCallback) => void {
	const pinnedHost = hostname.toLowerCase();
	const records: LookupAddress[] = addresses.map((addr) => ({
		address: addr,
		family: addr.includes(":") ? 6 : 4,
	}));
	let index = 0;

	return (host: string, options: LookupOptions, callback: DnsLookupCallback) => {
		if (host.toLowerCase() !== pinnedHost) {
			// Not our pinned host — reject (we should only see the pinned hostname)
			callback(
				Object.assign(new Error(`Unexpected hostname in lookup: ${host}`), { code: "ENOTFOUND" }),
				"",
			);
			return;
		}

		if (options?.all) {
			callback(null, records);
			return;
		}

		// Round-robin single result
		const chosen = records[index % records.length];
		index += 1;
		callback(null, chosen.address, chosen.family);
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_MAX_REDIRECTS = 3;

function isRedirectStatus(status: number): boolean {
	return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/**
 * Resolve hostname and validate all IPs against blocked ranges.
 * Returns the validated IP addresses, or throws on blocked/unresolvable hosts.
 */
async function resolveAndValidate(hostname: string): Promise<string[]> {
	// Fast-path: literal IP addresses
	if (isNonOverridableBlock(hostname)) {
		throw new FetchGuardError(`Blocked: non-overridable IP (metadata/link-local): ${hostname}`);
	}
	if (isBlockedIP(hostname)) {
		throw new FetchGuardError(`Blocked: private/internal IP address: ${hostname}`);
	}

	const addresses = await cachedDNSLookup(hostname);
	if (!addresses || addresses.length === 0) {
		throw new FetchGuardError(`DNS resolution failed for: ${hostname}`);
	}

	// Validate ALL resolved IPs — a dual-stack hostname with one private
	// IP and one public IP is still dangerous (attacker controls which gets used)
	for (const addr of addresses) {
		if (isNonOverridableBlock(addr)) {
			throw new FetchGuardError(`Blocked: ${hostname} resolves to non-overridable IP: ${addr}`);
		}
		if (isBlockedIP(addr)) {
			throw new FetchGuardError(`Blocked: ${hostname} resolves to private/internal IP: ${addr}`);
		}
	}

	return addresses;
}

/**
 * Create an undici Agent pinned to the given addresses for a hostname.
 */
function createPinnedAgent(hostname: string, addresses: string[]): Agent {
	const lookup = createPinnedLookup(hostname, addresses);
	return new Agent({
		connect: { lookup },
	});
}

/**
 * Safely close an undici dispatcher.
 */
async function closeAgent(agent: Agent | null): Promise<void> {
	if (!agent) return;
	try {
		await agent.close();
	} catch {
		// Ignore cleanup errors
	}
}

/**
 * Build a combined AbortSignal from timeout and external signal.
 */
function buildAbortSignal(opts: { timeoutMs?: number; signal?: AbortSignal }): {
	signal?: AbortSignal;
	cleanup: () => void;
} {
	const { timeoutMs, signal } = opts;

	if (!timeoutMs && !signal) {
		return { signal: undefined, cleanup: () => {} };
	}

	if (!timeoutMs) {
		return { signal, cleanup: () => {} };
	}

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(new Error("fetch timeout")), timeoutMs);

	const onExternalAbort = () => controller.abort(signal?.reason);
	if (signal) {
		if (signal.aborted) {
			controller.abort(signal.reason);
		} else {
			signal.addEventListener("abort", onExternalAbort, { once: true });
		}
	}

	return {
		signal: controller.signal,
		cleanup: () => {
			clearTimeout(timeoutId);
			signal?.removeEventListener("abort", onExternalAbort);
		},
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error class
// ═══════════════════════════════════════════════════════════════════════════════

export class FetchGuardError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "FetchGuardError";
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main entry point
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Fetch a URL with DNS pinning and redirect validation.
 *
 * SECURITY PROPERTIES:
 * - All resolved IPs validated before any TCP connection
 * - DNS lookup pinned so TCP cannot connect to a different IP than validated
 * - Each redirect hop re-resolves and re-validates DNS
 * - Redirect count capped (default 3) with loop detection
 * - Timeout via AbortSignal
 *
 * IMPORTANT: Caller MUST call `release()` on the result when done reading
 * the response body (or on error) to free the underlying dispatcher.
 */
export async function fetchWithGuard(opts: FetchWithGuardOptions): Promise<FetchWithGuardResult> {
	const maxRedirects =
		typeof opts.maxRedirects === "number" && Number.isFinite(opts.maxRedirects)
			? Math.max(0, Math.floor(opts.maxRedirects))
			: DEFAULT_MAX_REDIRECTS;

	const { signal, cleanup: cleanupSignal } = buildAbortSignal({
		timeoutMs: opts.timeoutMs,
		signal: opts.signal,
	});

	let released = false;
	const release = async (agent: Agent | null) => {
		if (released) return;
		released = true;
		cleanupSignal();
		await closeAgent(agent);
	};

	const visited = new Set<string>();
	let currentUrl = opts.url;
	visited.add(currentUrl); // Track initial URL for loop detection
	let redirectCount = 0;

	while (true) {
		// Parse and validate URL
		let parsedUrl: URL;
		try {
			parsedUrl = new URL(currentUrl);
		} catch {
			await release(null);
			throw new FetchGuardError(`Invalid URL: ${currentUrl}`);
		}

		if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
			await release(null);
			throw new FetchGuardError("URL must use http or https protocol");
		}

		let agent: Agent | null = null;
		try {
			// Resolve and validate DNS
			const addresses = await resolveAndValidate(parsedUrl.hostname);

			// Create pinned dispatcher
			agent = createPinnedAgent(parsedUrl.hostname, addresses);

			// Execute fetch with pinned DNS and manual redirect handling
			// Note: undici's Agent type doesn't perfectly align with the
			// Dispatcher type on RequestInit due to dual package versions;
			// the cast is safe since Agent extends Dispatcher at runtime.
			const init: RequestInit = {
				...(opts.init ?? {}),
				redirect: "manual",
				dispatcher: agent as never,
				...(signal ? { signal } : {}),
			};

			const response = await fetch(parsedUrl.toString(), init);

			// Handle redirects
			if (isRedirectStatus(response.status)) {
				const location = response.headers.get("location");
				if (!location) {
					await release(agent);
					throw new FetchGuardError(`Redirect (${response.status}) missing Location header`);
				}

				redirectCount += 1;
				if (redirectCount > maxRedirects) {
					await release(agent);
					throw new FetchGuardError(`Too many redirects (limit: ${maxRedirects})`);
				}

				const nextUrl = new URL(location, parsedUrl).toString();
				if (visited.has(nextUrl)) {
					await release(agent);
					throw new FetchGuardError("Redirect loop detected");
				}

				visited.add(nextUrl);

				// Drain the redirect response body and close the agent for this hop
				try {
					await response.body?.cancel();
				} catch {
					// Ignore body cancel errors
				}
				await closeAgent(agent);

				currentUrl = nextUrl;
				continue;
			}

			// Non-redirect response — return to caller
			return {
				response,
				finalUrl: currentUrl,
				release: () => release(agent),
			};
		} catch (err) {
			if (err instanceof FetchGuardError) {
				const ctx = opts.auditContext ?? "url-fetch";
				logger.warn(
					{
						context: ctx,
						target: `${parsedUrl.origin}${parsedUrl.pathname}`,
						reason: err.message,
					},
					"fetch-guard: blocked URL fetch",
				);
			}
			await release(agent);
			throw err;
		}
	}
}
