import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
	defaultTrustedBrokerProxies,
	isTrustedBrokerProxy,
	lookupTailscaleWhois,
	normalizeBrokerRemoteAddress,
	parseForwardedClientAddress,
	parseSingleClientAddress,
	readDefaultIpv4Gateway,
	tailscaleLoginsMatch,
} from "../../src/relay/tailscale-whois.js";

describe("Tailscale WhoIs helpers", () => {
	it("strips IPv4-mapped prefixes", () => {
		expect(normalizeBrokerRemoteAddress("::ffff:172.17.0.1")).toBe("172.17.0.1");
		expect(normalizeBrokerRemoteAddress("127.0.0.1")).toBe("127.0.0.1");
		expect(normalizeBrokerRemoteAddress(null)).toBeNull();
	});

	it("takes the first X-Forwarded-For hop and rejects junk", () => {
		expect(parseForwardedClientAddress("100.64.1.10, 172.17.0.1")).toBe("100.64.1.10");
		expect(parseForwardedClientAddress("100.64.1.10:443")).toBe("100.64.1.10");
		expect(parseForwardedClientAddress("[fd7a:115c:a1e0::1]:443")).toBe("fd7a:115c:a1e0::1");
		expect(parseSingleClientAddress("not-an-ip")).toBeNull();
		expect(parseForwardedClientAddress(undefined)).toBeNull();
	});

	it("parses the default IPv4 gateway from a route table", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-route-"));
		const routeTable = path.join(dir, "route");
		fs.writeFileSync(
			routeTable,
			[
				"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
				"eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0",
				"",
			].join("\n"),
		);
		try {
			expect(readDefaultIpv4Gateway(routeTable)).toBe("172.17.0.1");
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("trusts loopback and configured proxies, not Hermes", () => {
		const trusted = defaultTrustedBrokerProxies({
			TELCLAUDE_BROKER_TRUSTED_PROXIES: "172.17.0.1",
		});
		expect(isTrustedBrokerProxy("127.0.0.1", trusted)).toBe(true);
		expect(isTrustedBrokerProxy("172.17.0.1", trusted)).toBe(true);
		expect(isTrustedBrokerProxy("172.30.92.11", trusted)).toBe(false);
		expect(isTrustedBrokerProxy("172.30.93.11", ["127.0.0.1"])).toBe(false);
	});

	it("compares Tailscale logins case-insensitively", () => {
		expect(tailscaleLoginsMatch("Aviv@example", "aviv@example")).toBe(true);
		expect(tailscaleLoginsMatch("aviv@example", "other@example")).toBe(false);
	});
});

describe("Tailscale WhoIs lookup", () => {
	let server: http.Server | null = null;
	let socketPath = "";

	afterEach(async () => {
		if (!server) return;
		await new Promise<void>((resolve, reject) => {
			server?.close((error) => (error ? reject(error) : resolve()));
		});
		server = null;
		if (socketPath && fs.existsSync(socketPath)) fs.unlinkSync(socketPath);
	});

	it("reads LoginName from the localapi unix socket", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-whois-"));
		socketPath = path.join(dir, "tailscaled.sock");
		server = http.createServer((req, res) => {
			expect(req.url).toContain("addr=100.64.1.10");
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ UserProfile: { LoginName: "aviv@example" } }));
		});
		await new Promise<void>((resolve, reject) => {
			server?.once("error", reject);
			server?.listen(socketPath, resolve);
		});

		const result = await lookupTailscaleWhois("100.64.1.10", {
			TELCLAUDE_TAILSCALED_SOCKET: socketPath,
		});
		expect(result).toEqual({ loginName: "aviv@example" });
		fs.rmSync(dir, { recursive: true, force: true });
		socketPath = "";
	});
});
