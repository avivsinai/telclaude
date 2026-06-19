import { describe, expect, it } from "vitest";
import {
	type BrowseRequest,
	BrowserBroker,
	type BrowserBrokerConfig,
	type BrowserDriver,
	type BrowserDriverConnection,
	type BrowserDriverContext,
	type BrowserDriverPage,
	type BrowserProxyOptions,
	resolveBrowserBrokerConfig,
} from "../../src/relay/browser-broker.js";
import { BROWSER_CONTEXT_PROXY_BASIC_USERNAME } from "../../src/relay/browser-connect-contract.js";
import { createBrowserConnectContextVerifier } from "../../src/relay/browser-context-token.js";

const SECRET = "browser-broker-hmac-secret";
const PEER = "172.30.94.11";

const CONFIG: BrowserBrokerConfig = {
	browserWsEndpoint: "ws://tc-browser:3006/playwright",
	connectProxyUrl: "http://telclaude:8794",
	tcBrowserPeerAddress: PEER,
	contextTokenSecret: SECRET,
};

interface FakePageScript {
	readonly title?: string;
	readonly text?: string;
	readonly finalUrl?: string;
	readonly status?: number | null;
	readonly gotoError?: Error;
}

interface FakeCalls {
	connectEndpoints: string[];
	proxyOptions: BrowserProxyOptions[];
	storageStates: unknown[];
	gotoUrls: string[];
	pageClosed: number;
	contextClosed: number;
	connectionClosed: number;
}

function fakeDriver(script: FakePageScript = {}): { driver: BrowserDriver; calls: FakeCalls } {
	const calls: FakeCalls = {
		connectEndpoints: [],
		proxyOptions: [],
		storageStates: [],
		gotoUrls: [],
		pageClosed: 0,
		contextClosed: 0,
		connectionClosed: 0,
	};

	const page: BrowserDriverPage = {
		async goto(url) {
			calls.gotoUrls.push(url);
			if (script.gotoError) throw script.gotoError;
			return { finalUrl: script.finalUrl ?? url, status: script.status ?? 200 };
		},
		async title() {
			return script.title ?? "Untitled";
		},
		async innerText() {
			return script.text ?? "";
		},
		async close() {
			calls.pageClosed += 1;
		},
	};

	const context: BrowserDriverContext = {
		async newPage() {
			return page;
		},
		async close() {
			calls.contextClosed += 1;
		},
	};

	const connection: BrowserDriverConnection = {
		async newContext(options: { proxy: BrowserProxyOptions; storageState?: unknown }) {
			calls.proxyOptions.push(options.proxy);
			calls.storageStates.push(options.storageState);
			return context;
		},
		async close() {
			calls.connectionClosed += 1;
		},
	};

	const driver: BrowserDriver = {
		async connect(wsEndpoint) {
			calls.connectEndpoints.push(wsEndpoint);
			return connection;
		},
	};

	return { driver, calls };
}

const REQUEST: BrowseRequest = {
	actor: "telegram:default",
	sessionRef: "sess-browse-1",
	url: "https://example.org/article",
};

describe("BrowserBroker — read-only browse", () => {
	it("navigates and returns redacted, untrusted-wrapped page text", async () => {
		const { driver, calls } = fakeDriver({
			title: "Example Article",
			text: "Hello from the public web.",
			finalUrl: "https://example.org/article?ref=1",
			status: 200,
		});
		const broker = new BrowserBroker(driver, CONFIG);

		const result = await broker.browse(REQUEST);

		expect(calls.connectEndpoints).toEqual([CONFIG.browserWsEndpoint]);
		expect(calls.gotoUrls).toEqual(["https://example.org/article"]);
		expect(result.finalUrl).toBe("https://example.org/article?ref=1");
		expect(result.httpStatus).toBe(200);
		expect(result.title).toBe("Example Article");
		expect(result.content).toContain("Hello from the public web.");
		// Untrusted-content wrapping must be present so the model treats it as data.
		expect(result.content).toContain("UNTRUSTED");
	});

	it("presents the per-context token to the proxy as the sentinel Basic credential", async () => {
		const { driver, calls } = fakeDriver({ text: "ok" });
		const broker = new BrowserBroker(driver, CONFIG);

		await broker.browse(REQUEST);

		const proxy = calls.proxyOptions[0];
		expect(proxy?.server).toBe(CONFIG.connectProxyUrl);
		expect(proxy?.username).toBe(BROWSER_CONTEXT_PROXY_BASIC_USERNAME);

		// The minted token must verify under the same secret + peer as a cookie-less
		// context allowed to any public host — proving end-to-end wiring with the proxy verifier.
		const verifier = createBrowserConnectContextVerifier({ secret: SECRET });
		const verification = await verifier({
			token: proxy?.password ?? "",
			targetHost: "example.org",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(verification.allowed).toBe(true);
		expect(verification.context?.cookieBearing).toBe(false);
		expect(verification.context?.actor).toBe("telegram:default");
		expect(verification.context?.sessionRef).toBe("sess-browse-1");
	});

	it("M2: hydrates a relay-resolved session into a cookie-bearing, origin-pinned context", async () => {
		const { driver, calls } = fakeDriver({ text: "logged-in dashboard" });
		const broker = new BrowserBroker(driver, CONFIG);
		const storageState = {
			cookies: [{ name: "SID", value: "secret", domain: ".example.org" }],
			origins: [],
		};

		await broker.browse({
			...REQUEST,
			url: "https://example.org/account",
			session: { storageState, originScope: ["example.org"] },
		});

		// The captured storageState reaches the driver so the context is logged in.
		expect(calls.storageStates[0]).toEqual(storageState);

		const proxy = calls.proxyOptions[0];
		const verifier = createBrowserConnectContextVerifier({ secret: SECRET });
		// The token is cookie-bearing AND its egress is pinned (M1) to the login origin.
		const inScope = await verifier({
			token: proxy?.password ?? "",
			targetHost: "example.org",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(inScope.allowed).toBe(true);
		expect(inScope.context?.cookieBearing).toBe(true);
		// A host outside the session's origin scope is refused by the same token —
		// a hijacked logged-in session cannot exfiltrate cookies to another host.
		const outOfScope = await verifier({
			token: proxy?.password ?? "",
			targetHost: "evil.test",
			targetPort: 443,
			remoteAddress: PEER,
			headers: {},
		});
		expect(outOfScope.allowed).toBe(false);
	});

	it("redacts secret-shaped material that appears in page text", async () => {
		const awsKey = "AKIAIOSFODNN7EXAMPLE";
		const { driver } = fakeDriver({ text: `page leak: ${awsKey} trailing` });
		const broker = new BrowserBroker(driver, CONFIG);

		const result = await broker.browse(REQUEST);
		expect(result.content).not.toContain(awsKey);
	});

	it("fails closed on a secret-shaped URL before connecting (M5 preflight)", async () => {
		const { driver, calls } = fakeDriver();
		const broker = new BrowserBroker(driver, CONFIG);

		await expect(
			broker.browse({
				...REQUEST,
				url: "https://example.org/?token=AKIAIOSFODNN7EXAMPLE",
			}),
		).rejects.toMatchObject({ code: "mcp_outbound_secret_blocked" });
		expect(calls.connectEndpoints).toEqual([]);
	});

	it("rejects non-http(s) URL schemes", async () => {
		const { driver, calls } = fakeDriver();
		const broker = new BrowserBroker(driver, CONFIG);

		await expect(broker.browse({ ...REQUEST, url: "file:///etc/passwd" })).rejects.toMatchObject({
			code: "browse_url_scheme_denied",
		});
		expect(calls.connectEndpoints).toEqual([]);
	});

	it("requires actor and sessionRef", async () => {
		const { driver } = fakeDriver();
		const broker = new BrowserBroker(driver, CONFIG);
		await expect(broker.browse({ ...REQUEST, actor: "  " })).rejects.toMatchObject({
			code: "browse_identity_missing",
		});
	});

	it("discards the context and connection every browse (M6 ephemeral), even on navigation failure", async () => {
		const { driver, calls } = fakeDriver({ gotoError: new Error("nav boom") });
		const broker = new BrowserBroker(driver, CONFIG);

		await expect(broker.browse(REQUEST)).rejects.toThrow("nav boom");
		expect(calls.pageClosed).toBe(1);
		expect(calls.contextClosed).toBe(1);
		expect(calls.connectionClosed).toBe(1);
	});
});

describe("resolveBrowserBrokerConfig", () => {
	const fullEnv = {
		TELCLAUDE_BROWSER_WS_ENDPOINT: "ws://tc-browser:3006/playwright",
		TELCLAUDE_BROWSER_CONNECT_PROXY_URL: "http://telclaude:8794",
		TELCLAUDE_BROWSER_PEER_ADDRESS: "172.30.94.11",
		TELCLAUDE_BROWSER_CONTEXT_TOKEN_SECRET: "secret",
	};

	it("returns the config when all browser overlay env vars are present", () => {
		expect(resolveBrowserBrokerConfig(fullEnv)).toEqual({
			browserWsEndpoint: "ws://tc-browser:3006/playwright",
			connectProxyUrl: "http://telclaude:8794",
			tcBrowserPeerAddress: "172.30.94.11",
			contextTokenSecret: "secret",
		});
	});

	it("returns null (browser off → tc_browse fails closed) when any var is missing or blank", () => {
		expect(resolveBrowserBrokerConfig({})).toBeNull();
		for (const key of Object.keys(fullEnv)) {
			expect(resolveBrowserBrokerConfig({ ...fullEnv, [key]: "" })).toBeNull();
			const { [key]: _omitted, ...partial } = fullEnv;
			expect(resolveBrowserBrokerConfig(partial)).toBeNull();
		}
	});
});
