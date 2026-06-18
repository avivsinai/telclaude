import { once } from "node:events";
import net from "node:net";
import { describe, expect, it } from "vitest";
import {
	BROWSER_CONTEXT_PROXY_BASIC_USERNAME,
	hostMatchesBrowserOriginScope,
} from "../../src/relay/browser-connect-contract.js";
import {
	addBrowserConnectClientBytes,
	normalizeIpForBlocking,
	parseConnectAuthority,
	readBrowserConnectProxyConfigFromEnv,
	startBrowserConnectProxy,
	type ValidatedConnectTarget,
	validateBrowserConnectContext,
	validateBrowserConnectTarget,
} from "../../src/relay/browser-connect-proxy.js";

describe("browser CONNECT proxy target validation", () => {
	it("parses domain and bracketed IPv6 CONNECT authorities", () => {
		expect(parseConnectAuthority("example.com:443")).toEqual({
			host: "example.com",
			port: 443,
		});
		expect(parseConnectAuthority("[2606:2800:220:1:248:1893:25c8:1946]:443")).toEqual({
			host: "2606:2800:220:1:248:1893:25c8:1946",
			port: 443,
		});
	});

	it("rejects malformed authorities and internal single-label hosts", () => {
		expect(parseConnectAuthority("https://example.com:443")).toBeNull();
		expect(parseConnectAuthority("user@example.com:443")).toBeNull();
		expect(parseConnectAuthority("vault:443")).toBeNull();
		expect(parseConnectAuthority("example.com:0")).toBeNull();
		expect(parseConnectAuthority("example.com:65536")).toBeNull();
	});

	it("allows a public target and returns the validated IP to dial", async () => {
		const result = await validateBrowserConnectTarget("example.com:443", {
			resolveHost: async () => ["93.184.216.34"],
		});

		expect(result).toEqual({
			allowed: true,
			target: {
				authority: { host: "example.com", port: 443 },
				validatedIp: "93.184.216.34",
				resolvedIps: ["93.184.216.34"],
			},
		});
	});

	it("denies non-CONNECT ports and metadata names before dialing", async () => {
		await expect(
			validateBrowserConnectTarget("example.com:22", {
				resolveHost: async () => ["93.184.216.34"],
			}),
		).resolves.toMatchObject({
			allowed: false,
			failure: { code: "port-denied" },
		});
		await expect(
			validateBrowserConnectTarget("metadata.google.internal:443", {
				resolveHost: async () => ["93.184.216.34"],
			}),
		).resolves.toMatchObject({
			allowed: false,
			failure: { code: "blocked-host" },
		});
	});

	it("denies private, IPv4-mapped, and well-known NAT64 private targets", async () => {
		await expect(
			validateBrowserConnectTarget("private.example.com:443", {
				resolveHost: async () => ["10.0.0.12"],
			}),
		).resolves.toMatchObject({
			allowed: false,
			failure: { code: "blocked-ip" },
		});
		await expect(validateBrowserConnectTarget("[::ffff:192.168.1.5]:443")).resolves.toMatchObject({
			allowed: false,
			failure: { code: "blocked-ip" },
		});
		await expect(validateBrowserConnectTarget("[64:ff9b::a00:1]:443")).resolves.toMatchObject({
			allowed: false,
			failure: { code: "blocked-ip" },
		});
		expect(normalizeIpForBlocking("64:ff9b::c000:201")).toBe("192.0.2.1");
	});
});

describe("browser CONNECT proxy context policy", () => {
	const target = {
		authority: { host: "accounts.google.com", port: 443 },
		validatedIp: "142.250.190.13",
		resolvedIps: ["142.250.190.13"],
	} satisfies ValidatedConnectTarget;

	it("fails closed when context identity is required and no token is present", async () => {
		const config = readBrowserConnectProxyConfigFromEnv({
			requireContextIdentity: true,
		});

		await expect(
			validateBrowserConnectContext({}, target, "198.51.100.11", config),
		).resolves.toEqual({
			allowed: false,
			reason: "relay-issued browser context token required",
		});
	});

	it("fails closed when a token is present before the verifier interface is wired", async () => {
		const config = readBrowserConnectProxyConfigFromEnv({
			requireContextIdentity: true,
		});

		await expect(
			validateBrowserConnectContext(
				{ "proxy-authorization": "Bearer ctx-test" },
				target,
				"198.51.100.11",
				config,
			),
		).resolves.toEqual({
			allowed: false,
			reason: "browser context verifier is not configured",
		});
	});

	it("allows unauthenticated relay-issued context tokens to reach public hosts", async () => {
		const config = readBrowserConnectProxyConfigFromEnv({
			requireContextIdentity: true,
			contextVerifier: ({ token }) => ({
				allowed: true,
				context: { contextId: token },
			}),
		});

		await expect(
			validateBrowserConnectContext(
				{ "proxy-authorization": "Bearer ctx-public" },
				target,
				"198.51.100.11",
				config,
			),
		).resolves.toMatchObject({
			allowed: true,
			context: { contextId: "ctx-public" },
		});
	});

	it("binds cookie-bearing contexts to the hydrated origin scope", async () => {
		const config = readBrowserConnectProxyConfigFromEnv({
			requireContextIdentity: true,
			contextVerifier: ({ token }) => ({
				allowed: true,
				context: {
					contextId: token,
					cookieBearing: true,
					hydratedOriginScope: ["google.com"],
				},
			}),
		});

		await expect(
			validateBrowserConnectContext(
				{ "proxy-authorization": "Bearer ctx-cookie" },
				target,
				"198.51.100.11",
				config,
			),
		).resolves.toMatchObject({ allowed: true });

		await expect(
			validateBrowserConnectContext(
				{ "proxy-authorization": "Bearer ctx-cookie" },
				{ ...target, authority: { host: "evil-google.example", port: 443 } },
				"198.51.100.11",
				config,
			),
		).resolves.toEqual({
			allowed: false,
			reason: "cookie-bearing browser context cannot egress outside hydrated origin scope",
		});
		expect(hostMatchesBrowserOriginScope("accounts.google.com", ["google.com"])).toBe(true);
	});

	it("accepts the per-context token from Proxy-Authorization: Basic with the sentinel username", async () => {
		const config = readBrowserConnectProxyConfigFromEnv({
			requireContextIdentity: true,
			contextVerifier: ({ token }) => ({ allowed: true, context: { contextId: token } }),
		});
		const basic = Buffer.from(`${BROWSER_CONTEXT_PROXY_BASIC_USERNAME}:ctx-basic`, "utf8").toString(
			"base64",
		);

		await expect(
			validateBrowserConnectContext(
				{ "proxy-authorization": `Basic ${basic}` },
				target,
				"198.51.100.11",
				config,
			),
		).resolves.toMatchObject({ allowed: true, context: { contextId: "ctx-basic" } });
	});

	it("ignores a Basic credential whose username is not the sentinel (token not extracted)", async () => {
		const config = readBrowserConnectProxyConfigFromEnv({
			requireContextIdentity: true,
			contextVerifier: ({ token }) => ({ allowed: true, context: { contextId: token } }),
		});
		const basic = Buffer.from("someone-else:ctx-basic", "utf8").toString("base64");

		// Wrong username ⇒ no token extracted ⇒ requireContextIdentity fails closed.
		await expect(
			validateBrowserConnectContext(
				{ "proxy-authorization": `Basic ${basic}` },
				target,
				"198.51.100.11",
				config,
			),
		).resolves.toEqual({
			allowed: false,
			reason: "relay-issued browser context token required",
		});
	});

	it("challenges CONNECT clients with Basic proxy auth when context identity is missing", async () => {
		const handle = startBrowserConnectProxy({
			host: "127.0.0.1",
			port: 0,
			requireContextIdentity: true,
			resolveHost: async () => ["93.184.216.34"],
		});
		try {
			if (!handle.server.listening) {
				await once(handle.server, "listening");
			}
			const address = handle.server.address();
			if (!address || typeof address === "string") {
				throw new Error("expected TCP listener");
			}

			const response = await new Promise<string>((resolve, reject) => {
				const client = net.connect(address.port, "127.0.0.1", () => {
					client.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
				});
				let data = "";
				client.setEncoding("utf8");
				client.on("data", (chunk) => {
					data += chunk;
				});
				client.on("error", reject);
				client.on("end", () => resolve(data));
			});

			expect(response).toContain("HTTP/1.1 407 Proxy Authentication Required");
			expect(response).toContain('Proxy-Authenticate: Basic realm="telclaude-browser"');
			expect(response).toContain("relay-issued browser context token required");
		} finally {
			await handle.stop();
		}
	});
});

describe("browser CONNECT proxy byte budget", () => {
	it("tracks client-to-upstream byte budgets", () => {
		expect(addBrowserConnectClientBytes(0, 512, 1024)).toEqual({
			allowed: true,
			totalBytes: 512,
		});
		expect(addBrowserConnectClientBytes(512, 512, 1024)).toEqual({
			allowed: true,
			totalBytes: 1024,
		});
		expect(addBrowserConnectClientBytes(1024, 1, 1024)).toEqual({
			allowed: false,
			totalBytes: 1025,
		});
	});
});
