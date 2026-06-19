/**
 * Real-Playwright glue for the S3 interactive `BrowserActDriver`.
 *
 * The read-only browse path (`browser-broker.ts`) opens an EPHEMERAL context,
 * fetches one page, and discards the context (M6). An interactive act is
 * different: the live cookie-bearing context+page must PERSIST from
 * `prepareIntent`, through the async human approval, to commit — re-navigating
 * would change the page revision and break the WYSIWYS binding. So this factory
 * opens a context that stays open; the executor's session pool holds it and
 * closes it on eviction (M6).
 *
 * Everything security-relevant is reused, not re-implemented:
 * - M1 origin-pin proxy token: minted by the broker's
 *   `buildBrowserContextProxyOptions`, so the act context presents the exact same
 *   per-context credential (same secret, same peer binding, same origin scope)
 *   as a cookie-bearing browse. The CONNECT proxy enforces egress identically.
 * - M2 storageState hydration: the relay-resolved session's `storageState` flows
 *   to `newContext`, exactly as in `BrowserBroker.browse`.
 * The contained runtime never receives a page handle; this all runs relay-side.
 *
 * The Playwright surface is loaded dynamically (`playwright-core`) so the heavy
 * dependency only loads when the browser feature is wired. The glue itself is
 * THIN: the testable logic (verb→Playwright method mapping, settle-signal
 * classification) lives in the exported pure functions below, unit-tested in
 * `tests/relay/browser-act-driver.test.ts`. The live `firefox.connect` path is
 * exercised only on the deployment target.
 */

import type { BrowserActJsonValue, BrowserActObservedSignals } from "./browser-act-evidence.js";
import type {
	BrowserActDriver,
	BrowserActRequest,
	BrowserActVerb,
} from "./browser-act-executor.js";
import type { BrowserActLiveContext, BrowserActLivePage } from "./browser-act-session-pool.js";
import {
	type BrowserBrokerConfig,
	type BrowserProxyOptions,
	type BrowserStorageState,
	type BrowseSession,
	buildBrowserContextProxyOptions,
} from "./browser-broker.js";

const DEFAULT_NAVIGATION_TIMEOUT_MS = 30_000;
const PLAYWRIGHT_CONNECT_TIMEOUT_MS = 30_000;

/** HTTP methods that signal a server-mutating request observed during settle. */
const MUTATING_HTTP_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * The minimal Playwright `Page` surface the act driver uses. Typed narrowly so
 * this module never depends on the full `playwright-core` type at compile time
 * (it is `import()`ed at runtime). The production seam adapts a real Page; this
 * keeps the glue honest about exactly which methods it touches.
 */
export interface PlaywrightActPage {
	url(): string;
	evaluate<T>(expression: string): Promise<T>;
	screenshot(options: { type: "png"; fullPage: true }): Promise<Buffer | Uint8Array>;
	fill(selector: string, value: string, options?: { timeout?: number }): Promise<void>;
	type(selector: string, text: string, options?: { timeout?: number }): Promise<void>;
	click(selector: string, options?: { timeout?: number }): Promise<void>;
	selectOption(
		selector: string,
		values: string | string[],
		options?: { timeout?: number },
	): Promise<unknown>;
	press(selector: string, key: string, options?: { timeout?: number }): Promise<void>;
	goto(
		url: string,
		options?: { timeout?: number; waitUntil?: "domcontentloaded" | "networkidle" | "load" },
	): Promise<unknown>;
	waitForLoadState(
		state?: "domcontentloaded" | "networkidle" | "load",
		options?: { timeout?: number },
	): Promise<void>;
	on(event: "request", handler: (request: PlaywrightActRequest) => void): void;
	off(event: "request", handler: (request: PlaywrightActRequest) => void): void;
	close(): Promise<void>;
	readonly mainFrame: () => PlaywrightActFrame;
}

/** The slice of a Playwright `Request` the settle listener reads. */
export interface PlaywrightActRequest {
	method(): string;
	frame(): PlaywrightActFrame | null;
}

/** Identity-comparable Playwright frame handle (we only ever check main-frame identity). */
export type PlaywrightActFrame = object;

/** The slice of a Playwright `BrowserContext` the driver retains. */
export interface PlaywrightActContext {
	newPage(): Promise<PlaywrightActPage>;
	on(event: "framenavigated", handler: (frame: PlaywrightActFrame) => void): void;
	close(): Promise<void>;
}

/** The slice of a Playwright `Browser` the driver retains. */
export interface PlaywrightActBrowser {
	newContext(options: {
		proxy: BrowserProxyOptions;
		storageState?: BrowserStorageState;
	}): Promise<PlaywrightActContext>;
	close(): Promise<void>;
}

/**
 * The single seam between this driver and Playwright/Camoufox. A production
 * connector calls `playwright-core`'s `firefox.connect(wsEndpoint)`; tests inject
 * a fake. This module owns the interface so it never statically imports
 * Playwright.
 */
export interface PlaywrightActConnector {
	connect(wsEndpoint: string): Promise<PlaywrightActBrowser>;
}

/**
 * Pure verb→Playwright dispatch. Maps a `BrowserActVerb` to the page method +
 * argument shape, reading any value(s) from the APPROVED `submittedValues` the
 * caller passes (never from page state the runtime controls). Exported and
 * unit-tested independent of a live browser: a fake page records the call shape.
 *
 * For committing verbs (`click`/`submit` map to `click`; a navigating
 * `goto` reads the url from `submittedValues`) the value is the approved one
 * threaded by the executor's commit path.
 */
export async function dispatchActVerb(
	page: Pick<PlaywrightActPage, "fill" | "type" | "click" | "selectOption" | "press" | "goto">,
	input: {
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	},
	options: { readonly timeoutMs: number },
): Promise<void> {
	const timeout = options.timeoutMs;
	switch (input.verb) {
		case "fill": {
			await page.fill(requireTarget(input.verb, input.target), requireStringValue(input), {
				timeout,
			});
			return;
		}
		case "type": {
			await page.type(requireTarget(input.verb, input.target), requireStringValue(input), {
				timeout,
			});
			return;
		}
		case "click": {
			await page.click(requireTarget(input.verb, input.target), { timeout });
			return;
		}
		case "selectOption": {
			await page.selectOption(requireTarget(input.verb, input.target), requireOptionValues(input), {
				timeout,
			});
			return;
		}
		case "press": {
			await page.press(requireTarget(input.verb, input.target), requireStringValue(input), {
				timeout,
			});
			return;
		}
		case "goto": {
			await page.goto(requireStringValue(input), { timeout, waitUntil: "domcontentloaded" });
			return;
		}
		default: {
			// Exhaustiveness guard: a new verb must be wired here explicitly.
			throw new BrowserActDriverError(
				"browser_act_verb_unsupported",
				`unsupported browser act verb: ${String((input as { verb: string }).verb)}`,
			);
		}
	}
}

/**
 * Reduce the raw signals collected during a settle window into the
 * `BrowserActObservedSignals` the evidence layer classifies on. Pure: the live
 * driver feeds it observed navigation + the set of request methods seen in the
 * window; this decides the mutating-request flag and surfaces the methods.
 */
export function classifyObservedSettleSignals(input: {
	readonly navigation: boolean;
	readonly formSubmit: boolean;
	readonly requestMethods: readonly string[];
}): BrowserActObservedSignals {
	const mutatingMethods = dedupeUpper(input.requestMethods).filter((method) =>
		MUTATING_HTTP_METHODS.has(method),
	);
	const signals: {
		navigation?: boolean;
		formSubmit?: boolean;
		mutatingRequest?: boolean;
		mutatingRequestMethods?: readonly string[];
	} = {};
	if (input.navigation) signals.navigation = true;
	if (input.formSubmit) signals.formSubmit = true;
	if (mutatingMethods.length > 0) {
		signals.mutatingRequest = true;
		signals.mutatingRequestMethods = mutatingMethods;
	}
	return signals;
}

function dedupeUpper(methods: readonly string[]): string[] {
	const seen = new Set<string>();
	for (const method of methods) {
		const normalized = method.trim().toUpperCase();
		if (normalized) seen.add(normalized);
	}
	return [...seen];
}

/**
 * The server-resolved entry url the page is auto-loaded to. Fail closed if it is
 * missing or not http(s): the relay always stamps a validated url here, so an
 * empty/non-web value means a wiring bug, never a runtime free-field.
 */
function requireEntryUrl(url: string): string {
	const trimmed = url?.trim();
	if (!trimmed) {
		throw new BrowserActDriverError(
			"browser_act_entry_url_missing",
			"browser act driver requires a server-resolved entry url to load",
		);
	}
	let parsed: URL;
	try {
		parsed = new URL(trimmed);
	} catch {
		throw new BrowserActDriverError(
			"browser_act_entry_url_invalid",
			"browser act entry url is not a valid URL",
		);
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new BrowserActDriverError(
			"browser_act_entry_url_invalid",
			"browser act entry url must be http(s)",
		);
	}
	return trimmed;
}

function requireTarget(verb: BrowserActVerb, target: string | undefined): string {
	const trimmed = target?.trim();
	if (!trimmed) {
		throw new BrowserActDriverError(
			"browser_act_target_required",
			`browser act verb '${verb}' requires a target selector`,
		);
	}
	return trimmed;
}

function requireStringValue(input: { readonly submittedValues?: BrowserActJsonValue }): string {
	const value = input.submittedValues;
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "boolean") return String(value);
	throw new BrowserActDriverError(
		"browser_act_value_required",
		"browser act verb requires a string-coercible approved value",
	);
}

function requireOptionValues(input: {
	readonly submittedValues?: BrowserActJsonValue;
}): string | string[] {
	const value = input.submittedValues;
	if (typeof value === "string") return value;
	if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
		return value as string[];
	}
	throw new BrowserActDriverError(
		"browser_act_value_required",
		"selectOption requires a string or string[] approved value",
	);
}

export class BrowserActDriverError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.code = code;
		this.name = "BrowserActDriverError";
	}
}

/** Config the factory needs: the broker config (token/proxy wiring) + a clock. */
export interface BrowserActDriverFactoryOptions {
	readonly config: BrowserBrokerConfig;
	readonly connector?: PlaywrightActConnector;
	readonly now?: () => Date;
}

/**
 * Build the production `BrowserActDriverFactory`. For each act request it:
 *
 * 1. Resolves the cookie-bearing session (storageState + originScope) the relay
 *    already attached to the request — the runtime never names it.
 * 2. Mints the per-context proxy credential via the broker's shared helper (M1
 *    origin-pin token + cookie-bearing flag), so egress is pinned exactly as a
 *    browse would be. A cookie-less act (no session) is allowed but stays
 *    public-only — there is no privileged act without a resolved login.
 * 3. Opens a PERSISTENT firefox context (with proxy + M2 storageState) + page via
 *    `firefox.connect → newContext → newPage`. The context is NOT closed after
 *    one action; it stays live until the executor's pool evicts it.
 *
 * The returned `BrowserActDriver` adapts the live page to the evidence view and
 * the act verbs, and collects settle signals from page-level Playwright events.
 */
export function createBrowserActDriverFactory(
	options: BrowserActDriverFactoryOptions,
): (request: BrowserActDriverRequest) => Promise<BrowserActDriver> {
	const connector = options.connector ?? createPlaywrightActConnector();
	const now = options.now ?? (() => new Date());
	return async (request) => {
		const actor = request.actor.trim();
		const sessionRef = request.sessionRef.trim();
		if (!actor || !sessionRef) {
			throw new BrowserActDriverError(
				"browser_act_identity_missing",
				"browser act driver requires server-stamped actor and sessionRef",
			);
		}
		const session = request.session;
		const proxy = buildBrowserContextProxyOptions({
			config: options.config,
			contextId: `act-${cryptoRandomUuid()}`,
			sessionRef,
			actor,
			...(session !== undefined ? { session: { originScope: session.originScope } } : {}),
			now: now(),
		});

		const navigationTimeoutMs = clampTimeout(
			request.settleTimeoutMs ??
				options.config.navigationTimeoutMs ??
				DEFAULT_NAVIGATION_TIMEOUT_MS,
		);

		const browser = await connector.connect(options.config.browserWsEndpoint);
		let context: PlaywrightActContext | undefined;
		try {
			context = await browser.newContext({
				proxy,
				...(session !== undefined ? { storageState: session.storageState } : {}),
			});
			const page = await context.newPage();
			// Option A — entry-URL auto-load, M1-scoped; in-scope GET-load is an accepted
			// risk; the committing action is separately human-approved. A blank page would
			// bind the wrong revision (capture/dispatch on about:blank), so we land on the
			// server-resolved entry url BEFORE handing the driver to the executor. This
			// navigation rides the SAME M1 origin-pinned proxy context above (NOT a bypass):
			// an off-scope or RFC1918/metadata entry url is denied by the CONNECT proxy at
			// the network layer, so it cannot escape the session's logged-in origin scope.
			await page.goto(requireEntryUrl(request.url), {
				timeout: navigationTimeoutMs,
				waitUntil: "domcontentloaded",
			});
			return new PlaywrightBrowserActDriver(browser, context, page, {
				navigationTimeoutMs,
			});
		} catch (error) {
			// Persistent context handoff failed before the pool could take custody:
			// close whatever opened so we never leak a live context/browser.
			await safeClose(() => context?.close() ?? Promise.resolve());
			await safeClose(() => browser.close());
			throw error;
		}
	};
}

/**
 * What the factory needs from a server-resolved act. This is `BrowserActRequest`
 * plus the relay-resolved `session` (the same `BrowseSession` the browse path
 * resolves from the cookie store). The executor stamps actor/profile/domain and
 * the relay session resolver attaches `session`; the driver never resolves a
 * login itself.
 */
export type BrowserActDriverRequest = BrowserActRequest & {
	readonly session?: BrowseSession;
};

/**
 * The live Playwright-backed act driver. Holds the browser+context+page open
 * across the async approval; the pool closes them on eviction. `page` adapts the
 * Playwright Page to the evidence view; `dispatch` runs the approved verb;
 * `settle` waits for the load state and reports the signals seen in the window.
 */
class PlaywrightBrowserActDriver implements BrowserActDriver {
	readonly page: BrowserActLivePage;
	readonly context: BrowserActLiveContext;
	private readonly pwPage: PlaywrightActPage;
	private readonly pwContext: PlaywrightActContext;
	private readonly navigationTimeoutMs: number;

	constructor(
		browser: PlaywrightActBrowser,
		context: PlaywrightActContext,
		page: PlaywrightActPage,
		options: { readonly navigationTimeoutMs: number },
	) {
		this.pwContext = context;
		this.pwPage = page;
		this.navigationTimeoutMs = options.navigationTimeoutMs;
		this.page = adaptEvidencePage(page);
		this.context = {
			// M6: the pool closes the context (and its web storage) on eviction, then
			// the underlying browser connection.
			close: async () => {
				await safeClose(() => context.close());
				await safeClose(() => browser.close());
			},
		};
	}

	async dispatch(input: {
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly submittedValues?: BrowserActJsonValue;
	}): Promise<void> {
		await dispatchActVerb(this.pwPage, input, { timeoutMs: this.navigationTimeoutMs });
	}

	async settle(opts: { readonly timeoutMs: number }): Promise<BrowserActObservedSignals> {
		const timeout = clampTimeout(opts.timeoutMs);
		const mainFrame = this.pwPage.mainFrame();
		let navigation = false;
		let formSubmit = false;
		const requestMethods: string[] = [];

		const onNavigated = (frame: PlaywrightActFrame): void => {
			if (frame === mainFrame) navigation = true;
		};
		const onRequest = (request: PlaywrightActRequest): void => {
			const method = request.method().trim().toUpperCase();
			requestMethods.push(method);
			// A main-frame POST is the strongest available form-submit tell from the
			// page layer (Playwright has no first-class form-submit event).
			if (method === "POST" && request.frame() === mainFrame) formSubmit = true;
		};

		this.pwContext.on("framenavigated", onNavigated);
		this.pwPage.on("request", onRequest);
		try {
			await waitForSettle(this.pwPage, timeout);
		} finally {
			this.pwPage.off("request", onRequest);
		}
		return classifyObservedSettleSignals({ navigation, formSubmit, requestMethods });
	}
}

/** Adapt a Playwright Page to the read-only `BrowserActLivePage` evidence view. */
function adaptEvidencePage(page: PlaywrightActPage): BrowserActLivePage {
	return {
		url: () => page.url(),
		evaluate: <T>(expression: string) => page.evaluate<T>(expression),
		screenshot: async (opts) => {
			const bytes = await page.screenshot(opts);
			return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
		},
		close: () => page.close(),
	};
}

/**
 * Wait for the page to quiesce after a dispatched act, bounded by `timeout`.
 * networkidle is best-effort: a long-polling page never goes idle, so a
 * timeout here is normal, not an error — the settle signals are still valid.
 */
async function waitForSettle(page: PlaywrightActPage, timeout: number): Promise<void> {
	try {
		await page.waitForLoadState("networkidle", { timeout });
	} catch {
		// networkidle timed out (long-poll / streaming page). domcontentloaded is
		// already past by the time an act fires; the window's signals stand.
	}
}

function clampTimeout(value: number): number {
	if (!Number.isFinite(value) || value <= 0) return DEFAULT_NAVIGATION_TIMEOUT_MS;
	return Math.min(Math.floor(value), 120_000);
}

function cryptoRandomUuid(): string {
	return globalThis.crypto.randomUUID();
}

/**
 * Production connector over `playwright-core`'s `firefox.connect()`. Loaded
 * dynamically so the relay starts without a browser configured. Node
 * `playwright-core` and the tc-browser image's Playwright must match major/minor
 * — the connect protocol is version-coupled (both pinned ~1.59).
 */
export function createPlaywrightActConnector(): PlaywrightActConnector {
	return {
		async connect(wsEndpoint) {
			const { firefox } = await import("playwright-core");
			const browser = await firefox.connect(wsEndpoint, {
				timeout: PLAYWRIGHT_CONNECT_TIMEOUT_MS,
			});
			return browser as unknown as PlaywrightActBrowser;
		},
	};
}

async function safeClose(close: () => Promise<void>): Promise<void> {
	try {
		await close();
	} catch {
		// Teardown failures must not mask the act result or leak details; the
		// remote BrowserServer reaps orphaned contexts/pages on disconnect.
	}
}
