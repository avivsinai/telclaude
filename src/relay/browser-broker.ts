/**
 * Relay-owned browser broker (read-only slice).
 *
 * The contained runtime never drives a browser directly. It asks the relay,
 * through the served-MCP `tc_browse` tool, to fetch a page; this broker is what
 * the relay runs. It connects to the hardened `tc-browser` Camoufox
 * BrowserServer, opens a fresh cookie-less context whose egress is pinned to the
 * relay-owned CONNECT proxy with a per-context token, navigates, reads the page
 * text, and discards the context. All security-relevant decisions (egress
 * preflight, per-context identity, ephemeral storage, output redaction +
 * untrusted-content wrapping) stay relay-side; the browser is dumb compute.
 *
 * This slice is read-only: cookie-less contexts only, no persistent logins, no
 * writes, no screenshots. Cookie hydration (M2), persistent sessions, and the
 * write-confirm binding land in later slices. The broker depends on a narrow
 * `BrowserDriver` interface it owns rather than on Playwright directly, so the
 * security logic is unit-testable without a live browser; the production driver
 * (a thin Playwright/Camoufox adapter) is wired where the live endpoint lands.
 */

import crypto from "node:crypto";

import { wrapExternalContent } from "../security/external-content.js";
import { redactSecrets } from "../security/output-filter.js";
import { assertSafeWebEgress } from "../security/web-egress-preflight.js";
import { BROWSER_CONTEXT_PROXY_BASIC_USERNAME } from "./browser-connect-contract.js";
import { mintBrowserContextToken } from "./browser-context-token.js";
import type { BrowserAuthorityDomain } from "./browser-cookie-store.js";

const DEFAULT_NAVIGATION_TIMEOUT_MS = 30_000;
const MIN_NAVIGATION_TIMEOUT_MS = 1_000;
const MAX_NAVIGATION_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_CHARS = 20_000;
const MAX_MAX_CHARS = 200_000;

/** Proxy credentials a context presents to the relay CONNECT proxy. */
export interface BrowserProxyOptions {
	readonly server: string;
	readonly username: string;
	readonly password: string;
}

export interface BrowserNavigation {
	readonly finalUrl: string;
	readonly status: number | null;
}

export interface BrowserDriverPage {
	goto(url: string, options: { readonly timeoutMs: number }): Promise<BrowserNavigation>;
	title(): Promise<string>;
	/** Visible text of the document body. */
	innerText(): Promise<string>;
	close(): Promise<void>;
}

export interface BrowserDriverContext {
	newPage(): Promise<BrowserDriverPage>;
	close(): Promise<void>;
}

/**
 * Playwright `storageState` (cookies + per-origin localStorage) captured at
 * one-time session capture and stored encrypted relay-side. Opaque to the
 * broker — it only forwards it to the driver to hydrate a cookie-bearing context.
 */
export type BrowserStorageState = unknown;

export interface BrowserDriverConnection {
	newContext(options: {
		readonly proxy: BrowserProxyOptions;
		/** M2: captured storageState to hydrate a cookie-bearing (logged-in) context. */
		readonly storageState?: BrowserStorageState;
	}): Promise<BrowserDriverContext>;
	close(): Promise<void>;
}

/**
 * The single seam between the broker and Playwright/Camoufox. A production
 * driver connects `playwright-core`'s `firefox.connect(wsEndpoint)`; tests
 * inject a fake. The broker owns this interface so it never imports Playwright.
 */
export interface BrowserDriver {
	connect(wsEndpoint: string): Promise<BrowserDriverConnection>;
}

export interface BrowserBrokerConfig {
	/** WS endpoint of the tc-browser Camoufox BrowserServer. */
	readonly browserWsEndpoint: string;
	/** CONNECT proxy URL as reachable *from tc-browser* (e.g. http://telclaude:8794). */
	readonly connectProxyUrl: string;
	/** tc-browser's address as the relay CONNECT proxy observes it; the per-context token binds to it. */
	readonly tcBrowserPeerAddress: string;
	/** HMAC secret for minting per-context tokens (relay-only). */
	readonly contextTokenSecret: string;
	readonly navigationTimeoutMs?: number;
	readonly maxChars?: number;
	readonly tokenTtlMs?: number;
}

/**
 * A relay-resolved persistent login for a cookie-bearing browse. The relay
 * resolves this from the encrypted cookie store by the URL's registrable domain
 * — the runtime never names or supplies a session. When present, the browse runs
 * in a cookie-bearing context whose egress is pinned (M1) to `originScope`.
 */
export interface BrowseSession {
	/** Decrypted Playwright storageState (cookies + per-origin localStorage). */
	readonly storageState: BrowserStorageState;
	/** M1 login-origin set; the cookie-bearing context may only egress to these. */
	readonly originScope: readonly string[];
}

export interface BrowseRequest {
	/** Server-resolved actor identity (the runtime never names its own). */
	readonly actor: string;
	/** Server-resolved operator profile (the runtime never names its own). */
	readonly profileId: string;
	/** Server-resolved trust domain — scopes which captured login may attach (M2). */
	readonly authorityDomain: BrowserAuthorityDomain;
	/** Server-resolved session reference for this browse. */
	readonly sessionRef: string;
	readonly url: string;
	/** M2: a relay-resolved persistent login. Absent → cookie-less browse. */
	readonly session?: BrowseSession;
	readonly maxChars?: number;
	readonly timeoutMs?: number;
}

export interface BrowseResult {
	readonly url: string;
	readonly finalUrl: string;
	readonly httpStatus: number | null;
	readonly title: string;
	/** Redacted, untrusted-content-wrapped page text. */
	readonly content: string;
	readonly truncated: boolean;
}

export class BrowserBrokerError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.code = code;
		this.name = "BrowserBrokerError";
	}
}

export class BrowserBroker {
	private readonly driver: BrowserDriver;
	private readonly config: BrowserBrokerConfig;
	private readonly now: () => Date;

	constructor(
		driver: BrowserDriver,
		config: BrowserBrokerConfig,
		options: { readonly now?: () => Date } = {},
	) {
		this.driver = driver;
		this.config = config;
		this.now = options.now ?? (() => new Date());
	}

	async browse(request: BrowseRequest): Promise<BrowseResult> {
		const url = normalizeBrowseUrl(request.url);
		// M5: fail closed before any browser work if the URL itself carries
		// secret-shaped or private-data material outbound.
		assertSafeWebEgress(url, "url");

		const actor = request.actor.trim();
		const sessionRef = request.sessionRef.trim();
		if (!actor || !sessionRef) {
			throw new BrowserBrokerError(
				"browse_identity_missing",
				"browse requires actor and sessionRef",
			);
		}

		const maxChars = clampMaxChars(request.maxChars ?? this.config.maxChars ?? DEFAULT_MAX_CHARS);
		const timeoutMs = clampTimeout(
			request.timeoutMs ?? this.config.navigationTimeoutMs ?? DEFAULT_NAVIGATION_TIMEOUT_MS,
		);

		// M2: a relay-resolved session makes this a cookie-bearing browse whose
		// egress is pinned (M1) to the session's login origins. Absent → a
		// cookie-less context that may reach any public host. Either way the relay
		// CONNECT proxy blocks private/metadata/provider/model targets, and M6
		// discards the context (and any hydrated cookies) after the browse.
		const session = request.session;
		const token = mintBrowserContextToken({
			secret: this.config.contextTokenSecret,
			peerAddress: this.config.tcBrowserPeerAddress,
			contextId: `browse-${crypto.randomUUID()}`,
			sessionRef,
			actor,
			cookieBearing: session !== undefined,
			...(session !== undefined ? { originScope: session.originScope } : {}),
			now: this.now(),
			...(this.config.tokenTtlMs !== undefined ? { ttlMs: this.config.tokenTtlMs } : {}),
		});

		const connection = await this.driver.connect(this.config.browserWsEndpoint);
		try {
			const context = await connection.newContext({
				proxy: {
					server: this.config.connectProxyUrl,
					username: BROWSER_CONTEXT_PROXY_BASIC_USERNAME,
					password: token,
				},
				...(session !== undefined ? { storageState: session.storageState } : {}),
			});
			try {
				const page = await context.newPage();
				try {
					const navigation = await page.goto(url, { timeoutMs });
					const title = await page.title();
					const rawText = await page.innerText();
					const truncated = rawText.length > maxChars;
					const content = wrapExternalContent(redactSecrets(rawText.slice(0, maxChars)), {
						source: "web-browse",
						serviceId: "tc_browse",
						includeRiskAssessment: true,
						maxLength: maxChars,
					});
					return {
						url,
						finalUrl: navigation.finalUrl || url,
						httpStatus: navigation.status,
						title: redactSecrets(title),
						content,
						truncated,
					};
				} finally {
					await safeClose(() => page.close());
				}
			} finally {
				// M6: discard the context (and all of its web storage) every browse.
				await safeClose(() => context.close());
			}
		} finally {
			await safeClose(() => connection.close());
		}
	}
}

function normalizeBrowseUrl(rawUrl: string): string {
	const trimmed = rawUrl.trim();
	if (!trimmed) {
		throw new BrowserBrokerError("browse_url_invalid", "browse url is required");
	}
	let parsed: URL;
	try {
		parsed = new URL(trimmed);
	} catch {
		throw new BrowserBrokerError("browse_url_invalid", "browse url is not a valid URL");
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		throw new BrowserBrokerError(
			"browse_url_scheme_denied",
			`browse url scheme not allowed: ${parsed.protocol}`,
		);
	}
	return parsed.toString();
}

function clampMaxChars(value: number): number {
	if (!Number.isFinite(value) || value <= 0) return DEFAULT_MAX_CHARS;
	return Math.min(Math.floor(value), MAX_MAX_CHARS);
}

function clampTimeout(value: number): number {
	if (!Number.isFinite(value)) return DEFAULT_NAVIGATION_TIMEOUT_MS;
	return Math.min(
		Math.max(Math.floor(value), MIN_NAVIGATION_TIMEOUT_MS),
		MAX_NAVIGATION_TIMEOUT_MS,
	);
}

async function safeClose(close: () => Promise<void>): Promise<void> {
	try {
		await close();
	} catch {
		// Teardown failures must not mask the browse result or leak details; the
		// remote BrowserServer reaps orphaned contexts/pages on disconnect.
	}
}

const PLAYWRIGHT_CONNECT_TIMEOUT_MS = 30_000;

/**
 * Production `BrowserDriver` over `playwright-core`'s `firefox.connect()`. It
 * connects to the contained tc-browser Camoufox BrowserServer (a remote
 * Playwright server) and maps the narrow seam the broker owns onto Playwright.
 * playwright-core is imported dynamically so the heavy dependency loads only
 * when the browser feature is actually wired, and the relay starts fine without
 * a browser configured. Node `playwright-core` and the image's Python Playwright
 * must match major/minor (both pinned ~1.59) — the connect protocol is
 * version-coupled.
 */
export function createPlaywrightBrowserDriver(): BrowserDriver {
	return {
		async connect(wsEndpoint) {
			const { firefox } = await import("playwright-core");
			const browser = await firefox.connect(wsEndpoint, {
				timeout: PLAYWRIGHT_CONNECT_TIMEOUT_MS,
			});
			return {
				async newContext({ proxy, storageState }) {
					const context = await browser.newContext({
						proxy,
						...(storageState !== undefined
							? {
									storageState: storageState as NonNullable<
										Parameters<typeof browser.newContext>[0]
									>["storageState"],
								}
							: {}),
					});
					return {
						async newPage() {
							const page = await context.newPage();
							return {
								async goto(url, { timeoutMs }) {
									const response = await page.goto(url, {
										timeout: timeoutMs,
										waitUntil: "domcontentloaded",
									});
									return { finalUrl: page.url(), status: response ? response.status() : null };
								},
								title: () => page.title(),
								innerText: () => page.innerText("body"),
								close: () => page.close(),
							};
						},
						close: () => context.close(),
					};
				},
				close: () => browser.close(),
			};
		},
	};
}

/**
 * Resolve the broker config from the relay environment (set by the browser
 * overlay compose). Returns null when any required value is missing — the
 * browser feature is then off and tc_browse fails closed
 * (`mcp_tool_not_configured`) rather than half-configured.
 */
export function resolveBrowserBrokerConfig(
	env: NodeJS.ProcessEnv = process.env,
): BrowserBrokerConfig | null {
	const browserWsEndpoint = env.TELCLAUDE_BROWSER_WS_ENDPOINT?.trim();
	const connectProxyUrl = env.TELCLAUDE_BROWSER_CONNECT_PROXY_URL?.trim();
	const tcBrowserPeerAddress = env.TELCLAUDE_BROWSER_PEER_ADDRESS?.trim();
	const contextTokenSecret = env.TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET?.trim();
	if (!browserWsEndpoint || !connectProxyUrl || !tcBrowserPeerAddress || !contextTokenSecret) {
		return null;
	}
	return { browserWsEndpoint, connectProxyUrl, tcBrowserPeerAddress, contextTokenSecret };
}
