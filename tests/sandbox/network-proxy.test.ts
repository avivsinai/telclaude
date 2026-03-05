import { describe, expect, it } from "vitest";

import {
	clearDNSCache,
	getDNSCacheStats,
	isBlockedIP,
	isPrivateIP,
} from "../../src/sandbox/network-proxy.js";

describe("isBlockedIP", () => {
	it("blocks IPv6 link-local addresses (fe80::/10)", () => {
		expect(isBlockedIP("fe80::1")).toBe(true);
		expect(isBlockedIP("fe9f:abcd::1234")).toBe(true);
	});

	it("blocks IPv6 unique-local addresses (fc00::/7)", () => {
		expect(isBlockedIP("fc00::1")).toBe(true);
		expect(isBlockedIP("fd12:3456:789a::1")).toBe(true);
	});

	it("blocks IPv4-mapped IPv6 private addresses", () => {
		expect(isBlockedIP("::ffff:192.168.1.1")).toBe(true);
		expect(isBlockedIP("::ffff:10.0.0.1")).toBe(true);
	});

	it("blocks CGNAT range (100.64.0.0/10)", () => {
		expect(isBlockedIP("100.64.0.1")).toBe(true);
		expect(isBlockedIP("100.127.255.254")).toBe(true);
		expect(isBlockedIP("100.128.0.1")).toBe(false);
	});

	it("allows public IPv6/IPv4 addresses", () => {
		expect(isBlockedIP("2001:4860:4860::8888")).toBe(false);
		expect(isBlockedIP("::ffff:8.8.8.8")).toBe(false);
		expect(isBlockedIP("8.8.8.8")).toBe(false);
	});

	it("blocks all RFC1918 IPv4 ranges", () => {
		expect(isBlockedIP("10.0.0.1")).toBe(true);
		expect(isBlockedIP("172.16.0.1")).toBe(true);
		expect(isBlockedIP("172.31.255.254")).toBe(true);
		expect(isBlockedIP("192.168.0.1")).toBe(true);
		expect(isBlockedIP("127.0.0.1")).toBe(true);
		expect(isBlockedIP("169.254.1.1")).toBe(true);
	});

	it("allows public IPv4 outside private ranges", () => {
		expect(isBlockedIP("172.32.0.1")).toBe(false);
		expect(isBlockedIP("100.128.0.1")).toBe(false);
		expect(isBlockedIP("1.1.1.1")).toBe(false);
	});
});

describe("isPrivateIP", () => {
	it("classifies RFC1918 addresses as private", () => {
		expect(isPrivateIP("10.0.0.1")).toBe(true);
		expect(isPrivateIP("172.16.0.1")).toBe(true);
		expect(isPrivateIP("192.168.1.1")).toBe(true);
		expect(isPrivateIP("127.0.0.1")).toBe(true);
	});

	it("classifies CGNAT as private", () => {
		expect(isPrivateIP("100.64.0.1")).toBe(true);
		expect(isPrivateIP("100.127.255.254")).toBe(true);
	});

	it("excludes non-overridable blocks (link-local)", () => {
		// link-local is handled by isNonOverridableBlock, not isPrivateIP
		expect(isPrivateIP("169.254.1.1")).toBe(false);
	});

	it("allows public addresses", () => {
		expect(isPrivateIP("8.8.8.8")).toBe(false);
		expect(isPrivateIP("1.1.1.1")).toBe(false);
	});
});

describe("DNS cache", () => {
	it("reports maxEntries in stats", () => {
		const stats = getDNSCacheStats();
		expect(stats.maxEntries).toBe(1000);
		expect(stats.ttlMs).toBe(60_000);
	});

	it("clears cache entries", () => {
		clearDNSCache();
		expect(getDNSCacheStats().size).toBe(0);
	});
});
