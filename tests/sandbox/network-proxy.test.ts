import { describe, expect, it } from "vitest";

import { isBlockedIP } from "../../src/sandbox/network-proxy.js";

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

	it("allows public IPv6/IPv4 addresses", () => {
		expect(isBlockedIP("2001:4860:4860::8888")).toBe(false);
		expect(isBlockedIP("::ffff:8.8.8.8")).toBe(false);
		expect(isBlockedIP("8.8.8.8")).toBe(false);
	});
});
