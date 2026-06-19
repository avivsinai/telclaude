import { describe, expect, it } from "vitest";
import {
	BrowserActDriverError,
	type BrowserActDriverRequest,
	classifyObservedSettleSignals,
	createBrowserActDriverFactory,
	dispatchActVerb,
	type PlaywrightActBrowser,
	type PlaywrightActContext,
	type PlaywrightActFrame,
	type PlaywrightActPage,
	type PlaywrightActRequest,
} from "../../src/relay/browser-act-driver.js";
import type { BrowserActVerb } from "../../src/relay/browser-act-executor.js";
import type { BrowserBrokerConfig, BrowserProxyOptions } from "../../src/relay/browser-broker.js";
import { BROWSER_CONTEXT_PROXY_BASIC_USERNAME } from "../../src/relay/browser-connect-contract.js";
import { createBrowserConnectContextVerifier } from "../../src/relay/browser-context-token.js";

const SECRET = "browser-act-driver-test-secret-32bytes!!";
const PEER = "172.30.94.11";

const CONFIG: BrowserBrokerConfig = {
	browserWsEndpoint: "ws://tc-browser:3006/playwright",
	connectProxyUrl: "http://telclaude:8794",
	tcBrowserPeerAddress: PEER,
	contextTokenSecret: SECRET,
};

const ENTRY_URL = "https://shop.example.com/checkout";

const ACT_REQUEST: BrowserActDriverRequest = {
	actor: "telegram:default:operator",
	profileId: "default",
	mcpDomain: "private",
	sessionRef: "sess-act-1",
	host: "shop.example.com",
	originScope: ["shop.example.com"],
	url: ENTRY_URL,
	verb: "click",
	target: "#submit",
};

// ---------------------------------------------------------------------------
// Pure: verb → Playwright dispatch mapping.
// ---------------------------------------------------------------------------

interface DispatchCall {
	readonly method: string;
	readonly args: readonly unknown[];
}

function recordingPage(): {
	page: Pick<PlaywrightActPage, "fill" | "type" | "click" | "selectOption" | "press" | "goto">;
	calls: DispatchCall[];
} {
	const calls: DispatchCall[] = [];
	const record =
		(method: string) =>
		async (...args: unknown[]) => {
			calls.push({ method, args });
		};
	return {
		page: {
			fill: record("fill"),
			type: record("type"),
			click: record("click"),
			selectOption: record("selectOption") as PlaywrightActPage["selectOption"],
			press: record("press"),
			goto: record("goto") as PlaywrightActPage["goto"],
		},
		calls,
	};
}

describe("dispatchActVerb verb→Playwright mapping", () => {
	const cases: Array<{
		readonly verb: BrowserActVerb;
		readonly target?: string;
		readonly value: unknown;
		readonly expectMethod: string;
		readonly expectArgs: readonly unknown[];
	}> = [
		{
			verb: "fill",
			target: "#email",
			value: "a@b.com",
			expectMethod: "fill",
			expectArgs: ["#email", "a@b.com"],
		},
		{
			verb: "type",
			target: "#bio",
			value: "hi",
			expectMethod: "type",
			expectArgs: ["#bio", "hi"],
		},
		{ verb: "click", target: "#go", value: undefined, expectMethod: "click", expectArgs: ["#go"] },
		{
			verb: "selectOption",
			target: "#country",
			value: "IL",
			expectMethod: "selectOption",
			expectArgs: ["#country", "IL"],
		},
		{
			verb: "press",
			target: "#q",
			value: "Enter",
			expectMethod: "press",
			expectArgs: ["#q", "Enter"],
		},
		{
			verb: "goto",
			target: undefined,
			value: "https://shop.example.com/cart",
			expectMethod: "goto",
			expectArgs: ["https://shop.example.com/cart"],
		},
	];

	for (const c of cases) {
		it(`maps ${c.verb} → page.${c.expectMethod}`, async () => {
			const { page, calls } = recordingPage();
			await dispatchActVerb(
				page,
				{
					verb: c.verb,
					...(c.target ? { target: c.target } : {}),
					...(c.value !== undefined ? { submittedValues: c.value as never } : {}),
				},
				{ timeoutMs: 5_000 },
			);
			expect(calls).toHaveLength(1);
			expect(calls[0]?.method).toBe(c.expectMethod);
			// Positional args (selector/url + value) come from the APPROVED values.
			expect(calls[0]?.args.slice(0, c.expectArgs.length)).toEqual(c.expectArgs);
			// Every verb threads the timeout to Playwright.
			const opts = calls[0]?.args.at(-1) as { timeout?: number };
			expect(opts.timeout).toBe(5_000);
		});
	}

	it("selectOption accepts a string[] approved value", async () => {
		const { page, calls } = recordingPage();
		await dispatchActVerb(
			page,
			{ verb: "selectOption", target: "#multi", submittedValues: ["a", "b"] },
			{ timeoutMs: 1_000 },
		);
		expect(calls[0]?.args[1]).toEqual(["a", "b"]);
	});

	it("requires a target selector for verbs that need one", async () => {
		const { page } = recordingPage();
		await expect(
			dispatchActVerb(page, { verb: "fill", submittedValues: "x" }, { timeoutMs: 1_000 }),
		).rejects.toMatchObject({ code: "browser_act_target_required" });
	});

	it("requires a string-coercible value for fill/type/press/goto", async () => {
		const { page } = recordingPage();
		await expect(
			dispatchActVerb(
				page,
				{ verb: "fill", target: "#x", submittedValues: { not: "a string" } },
				{ timeoutMs: 1_000 },
			),
		).rejects.toMatchObject({ code: "browser_act_value_required" });
	});

	it("rejects an unknown verb (exhaustiveness guard)", async () => {
		const { page } = recordingPage();
		await expect(
			dispatchActVerb(page, { verb: "evil" as BrowserActVerb, target: "#x" }, { timeoutMs: 1_000 }),
		).rejects.toBeInstanceOf(BrowserActDriverError);
	});
});

// ---------------------------------------------------------------------------
// Pure: settle-signal classification.
// ---------------------------------------------------------------------------

describe("classifyObservedSettleSignals", () => {
	it("flags mutating requests and dedupes/uppercases methods", () => {
		const signals = classifyObservedSettleSignals({
			navigation: true,
			formSubmit: false,
			requestMethods: ["get", "POST", "post", "patch"],
		});
		expect(signals.navigation).toBe(true);
		expect(signals.formSubmit).toBeUndefined();
		expect(signals.mutatingRequest).toBe(true);
		expect([...(signals.mutatingRequestMethods ?? [])].sort()).toEqual(["PATCH", "POST"]);
	});

	it("emits no mutating signal for a read-only window", () => {
		const signals = classifyObservedSettleSignals({
			navigation: false,
			formSubmit: false,
			requestMethods: ["GET", "HEAD"],
		});
		expect(signals.mutatingRequest).toBeUndefined();
		expect(signals.mutatingRequestMethods).toBeUndefined();
		expect(signals.navigation).toBeUndefined();
	});

	it("carries the form-submit signal through", () => {
		const signals = classifyObservedSettleSignals({
			navigation: false,
			formSubmit: true,
			requestMethods: [],
		});
		expect(signals.formSubmit).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Factory: M1/M2 wiring + persistent context, via a fake Playwright connector.
// ---------------------------------------------------------------------------

interface FakeCalls {
	connectEndpoints: string[];
	proxyOptions: BrowserProxyOptions[];
	storageStates: unknown[];
	contextClosed: number;
	browserClosed: number;
	pageClosed: number;
	/** Every navigation the factory drove, in order (entry-url auto-load lands here first). */
	gotos: Array<{ url: string; waitUntil?: string }>;
	/** True once newPage() returned — used to prove the entry goto fires AFTER page open. */
	pageCreated: boolean;
}

const MAIN_FRAME: PlaywrightActFrame = { mainFrame: true };

function fakePlaywright(): {
	connector: { connect: (ws: string) => Promise<PlaywrightActBrowser> };
	calls: FakeCalls;
	emitRequest: (method: string, fromMain?: boolean) => void;
	emitNavigation: (fromMain?: boolean) => void;
	releaseLoadState: () => void;
} {
	const calls: FakeCalls = {
		connectEndpoints: [],
		proxyOptions: [],
		storageStates: [],
		contextClosed: 0,
		browserClosed: 0,
		pageClosed: 0,
		gotos: [],
		pageCreated: false,
	};
	const requestHandlers = new Set<(r: PlaywrightActRequest) => void>();
	const navHandlers = new Set<(f: PlaywrightActFrame) => void>();
	// settle's waitForLoadState blocks on this gate so a test can register/emit
	// signals deterministically before the window closes.
	let releaseLoadState!: () => void;
	const loadGate = new Promise<void>((resolve) => {
		releaseLoadState = resolve;
	});

	// Starts blank; the entry-url auto-load navigates it. Capture/evidence reads
	// this, so a missing entry goto would leave it on about:blank.
	let currentUrl = "about:blank";
	const page: PlaywrightActPage = {
		url: () => currentUrl,
		evaluate: async <T>() => "<html></html>" as T,
		screenshot: async () => Buffer.from("png"),
		fill: async () => {},
		type: async () => {},
		click: async () => {},
		selectOption: async () => undefined,
		press: async () => {},
		goto: async (url, opts) => {
			calls.gotos.push({ url, ...(opts?.waitUntil ? { waitUntil: opts.waitUntil } : {}) });
			currentUrl = url;
			return undefined;
		},
		waitForLoadState: async () => {
			await loadGate;
		},
		on: (event, handler) => {
			if (event === "request") requestHandlers.add(handler);
		},
		off: (event, handler) => {
			if (event === "request") requestHandlers.delete(handler);
		},
		close: async () => {
			calls.pageClosed += 1;
		},
		mainFrame: () => MAIN_FRAME,
	};

	const context: PlaywrightActContext = {
		newPage: async () => {
			calls.pageCreated = true;
			return page;
		},
		on: (event, handler) => {
			if (event === "framenavigated") navHandlers.add(handler);
		},
		close: async () => {
			calls.contextClosed += 1;
		},
	};

	const browser: PlaywrightActBrowser = {
		newContext: async (options) => {
			calls.proxyOptions.push(options.proxy);
			calls.storageStates.push(options.storageState);
			return context;
		},
		close: async () => {
			calls.browserClosed += 1;
		},
	};

	return {
		connector: {
			connect: async (ws: string) => {
				calls.connectEndpoints.push(ws);
				return browser;
			},
		},
		calls,
		emitRequest: (method, fromMain = true) => {
			const req: PlaywrightActRequest = {
				method: () => method,
				frame: () => (fromMain ? MAIN_FRAME : {}),
			};
			for (const h of requestHandlers) h(req);
		},
		emitNavigation: (fromMain = true) => {
			for (const h of navHandlers) h(fromMain ? MAIN_FRAME : {});
		},
		releaseLoadState,
	};
}

describe("createBrowserActDriverFactory — M1/M2 wiring + persistence", () => {
	it("mints a cookie-less, public-egress context token for a session-less act", async () => {
		const { connector, calls } = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });

		const driver = await factory(ACT_REQUEST);

		expect(calls.connectEndpoints).toEqual([CONFIG.browserWsEndpoint]);
		const proxy = calls.proxyOptions[0];
		expect(proxy?.server).toBe(CONFIG.connectProxyUrl);
		expect(proxy?.username).toBe(BROWSER_CONTEXT_PROXY_BASIC_USERNAME);
		// No storageState hydrated for a session-less act.
		expect(calls.storageStates[0]).toBeUndefined();

		// The minted token verifies under the SAME proxy verifier as a browse,
		// proving the act path reuses the broker's M1 wiring, not a weaker one.
		const verifier = createBrowserConnectContextVerifier({ secret: SECRET });
		const verification = await verifier({
			token: proxy?.password ?? "",
			targetHost: "shop.example.com",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(verification.allowed).toBe(true);
		expect(verification.context?.cookieBearing).toBe(false);
		expect(verification.context?.actor).toBe(ACT_REQUEST.actor);
		expect(verification.context?.sessionRef).toBe(ACT_REQUEST.sessionRef);

		// Persistent: the context is NOT closed by the factory — the pool owns it.
		expect(calls.contextClosed).toBe(0);
		await driver.context.close();
		expect(calls.contextClosed).toBe(1);
		expect(calls.browserClosed).toBe(1);
	});

	it("auto-loads the ENTRY url after newPage (Option A) so capture lands on the entry page, not blank", async () => {
		const { connector, calls } = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });

		const driver = await factory(ACT_REQUEST);

		// The page was created, THEN navigated to the server-resolved entry url —
		// exactly once, with the domcontentloaded gate.
		expect(calls.pageCreated).toBe(true);
		expect(calls.gotos).toHaveLength(1);
		expect(calls.gotos[0]).toEqual({ url: ENTRY_URL, waitUntil: "domcontentloaded" });
		// The live page (capture/recapture view) reflects the ENTRY url, not about:blank.
		expect(driver.page.url()).toBe(ENTRY_URL);
		await driver.context.close();
	});

	it("fails closed (and closes the browser) if the server-resolved entry url is missing/non-web", async () => {
		const empty = fakePlaywright();
		const emptyFactory = createBrowserActDriverFactory({
			config: CONFIG,
			connector: empty.connector,
		});
		await expect(emptyFactory({ ...ACT_REQUEST, url: "   " })).rejects.toMatchObject({
			code: "browser_act_entry_url_missing",
		});
		// A blank entry url leaks nothing: the context + browser are torn down.
		expect(empty.calls.contextClosed).toBe(1);
		expect(empty.calls.browserClosed).toBe(1);

		const nonWeb = fakePlaywright();
		const nonWebFactory = createBrowserActDriverFactory({
			config: CONFIG,
			connector: nonWeb.connector,
		});
		await expect(
			nonWebFactory({ ...ACT_REQUEST, url: "file:///etc/passwd" }),
		).rejects.toMatchObject({ code: "browser_act_entry_url_invalid" });
		expect(nonWeb.calls.gotos).toHaveLength(0);
		expect(nonWeb.calls.browserClosed).toBe(1);
	});

	it("an OFF-SCOPE entry url is denied by the M1 origin-pinned proxy (network layer, not bypassed)", async () => {
		// The entry navigation rides the SAME per-context proxy token the factory mints.
		// Prove that token refuses an entry host outside the session's origin scope — so
		// even though the executor would 'goto' it, the CONNECT proxy blocks it.
		const { connector, calls } = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });
		const storageState = { cookies: [], origins: [] };

		await factory({
			...ACT_REQUEST,
			url: "https://shop.example.com/account",
			session: { storageState, originScope: ["shop.example.com"] },
		});

		const proxy = calls.proxyOptions[0];
		const verifier = createBrowserConnectContextVerifier({ secret: SECRET });
		// The entry host is in scope → CONNECT allowed.
		const inScope = await verifier({
			token: proxy?.password ?? "",
			targetHost: "shop.example.com",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(inScope.allowed).toBe(true);
		// An off-scope entry host (e.g. an injected redirect target) → CONNECT denied.
		const offScope = await verifier({
			token: proxy?.password ?? "",
			targetHost: "evil.test",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(offScope.allowed).toBe(false);
	});

	it("M2: hydrates storageState and pins egress (M1) to the session origin scope", async () => {
		const { connector, calls } = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });
		const storageState = {
			cookies: [{ name: "SID", value: "secret", domain: ".example.com" }],
			origins: [],
		};

		await factory({
			...ACT_REQUEST,
			session: { storageState, originScope: ["shop.example.com"] },
		});

		expect(calls.storageStates[0]).toEqual(storageState);
		const proxy = calls.proxyOptions[0];
		const verifier = createBrowserConnectContextVerifier({ secret: SECRET });

		const inScope = await verifier({
			token: proxy?.password ?? "",
			targetHost: "shop.example.com",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(inScope.allowed).toBe(true);
		expect(inScope.context?.cookieBearing).toBe(true);

		// A logged-in act context cannot egress outside its hydrated origin scope —
		// the exact same M1 refusal the browse path gets.
		const outOfScope = await verifier({
			token: proxy?.password ?? "",
			targetHost: "evil.test",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(outOfScope.allowed).toBe(false);
	});

	it("the adapted page exposes the evidence view over the live Playwright page", async () => {
		const { connector } = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });
		const driver = await factory(ACT_REQUEST);

		expect(driver.page.url()).toBe("https://shop.example.com/checkout");
		const shot = await driver.page.screenshot({ type: "png", fullPage: true });
		expect(shot).toBeInstanceOf(Uint8Array);
		await driver.page.close();
	});

	it("settle collects main-frame navigation + mutating-request signals in the window", async () => {
		const fake = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector: fake.connector });
		const driver = await factory(ACT_REQUEST);

		// settle registers its framenavigated/request listeners synchronously, then
		// blocks on waitForLoadState (gated). Emit signals while the window is open,
		// then release the gate so settle resolves with what it observed.
		const settlePromise = driver.settle({ timeoutMs: 1_000 });
		fake.emitNavigation(true);
		fake.emitRequest("POST", true);
		fake.emitRequest("GET", true);
		fake.releaseLoadState();

		const signals = await settlePromise;
		expect(signals.navigation).toBe(true);
		expect(signals.formSubmit).toBe(true); // main-frame POST
		expect(signals.mutatingRequest).toBe(true);
		expect(signals.mutatingRequestMethods).toContain("POST");
	});

	it("settle ignores a sub-frame navigation (only the main frame counts)", async () => {
		const fake = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector: fake.connector });
		const driver = await factory(ACT_REQUEST);

		const settlePromise = driver.settle({ timeoutMs: 1_000 });
		fake.emitNavigation(false); // sub-frame nav
		fake.emitRequest("GET", true);
		fake.releaseLoadState();

		const signals = await settlePromise;
		expect(signals.navigation).toBeUndefined();
		expect(signals.formSubmit).toBeUndefined();
		expect(signals.mutatingRequest).toBeUndefined();
	});

	it("fails closed and closes the browser if context handoff throws", async () => {
		const calls = { browserClosed: 0 };
		const connector = {
			connect: async (): Promise<PlaywrightActBrowser> => ({
				newContext: async () => {
					throw new Error("context boom");
				},
				close: async () => {
					calls.browserClosed += 1;
				},
			}),
		};
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });
		await expect(factory(ACT_REQUEST)).rejects.toThrow("context boom");
		expect(calls.browserClosed).toBe(1);
	});

	it("requires server-stamped actor and sessionRef", async () => {
		const { connector } = fakePlaywright();
		const factory = createBrowserActDriverFactory({ config: CONFIG, connector });
		await expect(factory({ ...ACT_REQUEST, actor: "  " })).rejects.toMatchObject({
			code: "browser_act_identity_missing",
		});
	});
});
