/**
 * Tests for private network endpoint allowlisting.
 *
 * These tests verify:
 * - CIDR matching with ip-num library
 * - Port enforcement (no service probing)
 * - Non-overridable blocks (metadata, link-local)
 * - DNS resolution with all-IPs-must-match policy
 * - Bypass attempt prevention
 */

import { describe, expect, it } from "vitest";

import type { PrivateEndpoint } from "../../src/config/config.js";
import {
	checkPrivateNetworkAccess,
	findMatchingPrivateEndpoint,
	isNonOverridableBlock,
	isPortAllowedByEndpoint,
	isPrivateIP,
} from "../../src/sandbox/network-proxy.js";

describe("isNonOverridableBlock", () => {
	it("blocks AWS metadata endpoint", () => {
		expect(isNonOverridableBlock("169.254.169.254")).toBe(true);
	});

	it("blocks AWS ECS metadata endpoint", () => {
		expect(isNonOverridableBlock("169.254.170.2")).toBe(true);
	});

	it("blocks AWS IMDSv6 metadata endpoint", () => {
		expect(isNonOverridableBlock("fd00:ec2::254")).toBe(true);
		expect(isNonOverridableBlock("fd00:0ec2:0:0:0:0:0:0254")).toBe(true);
	});

	it("blocks AWS EKS Pod Identity IPv6 credential endpoint", () => {
		expect(isNonOverridableBlock("fd00:ec2::23")).toBe(true);
		expect(isNonOverridableBlock("fd00:0ec2:0:0:0:0:0:0023")).toBe(true);
	});

	it("blocks GCP IMDSv6 metadata endpoint", () => {
		expect(isNonOverridableBlock("fd20:ce::254")).toBe(true);
		expect(isNonOverridableBlock("fd20:00ce:0:0:0:0:0:0254")).toBe(true);
	});

	it("blocks link-local range (169.254.x.x)", () => {
		expect(isNonOverridableBlock("169.254.0.1")).toBe(true);
		expect(isNonOverridableBlock("169.254.255.255")).toBe(true);
		expect(isNonOverridableBlock("::ffff:a9fe:0001")).toBe(true);
		expect(isNonOverridableBlock("::ffff:a9fe:a9fe")).toBe(true);
		expect(isNonOverridableBlock("::169.254.0.1")).toBe(true);
		expect(isNonOverridableBlock("::169.254.255.255")).toBe(true);
	});

	it("blocks Alibaba Cloud metadata", () => {
		expect(isNonOverridableBlock("100.100.100.200")).toBe(true);
		expect(isNonOverridableBlock("::ffff:6464:64c8")).toBe(true);
		expect(isNonOverridableBlock("::100.100.100.200")).toBe(true);
	});

	it("blocks unspecified IPv4 addresses", () => {
		expect(isNonOverridableBlock("0.0.0.0")).toBe(true);
		expect(isNonOverridableBlock("0.255.255.255")).toBe(true);
	});

	it("blocks IPv6 unspecified address", () => {
		expect(isNonOverridableBlock("::")).toBe(true);
		expect(isNonOverridableBlock("0:0:0:0:0:0:0:0")).toBe(true);
	});

	it("blocks IPv6 link-local (fe80::/10)", () => {
		expect(isNonOverridableBlock("fe80::1")).toBe(true);
		expect(isNonOverridableBlock("fe9f::1234")).toBe(true);
		expect(isNonOverridableBlock("fea0::1")).toBe(true);
		expect(isNonOverridableBlock("febf::1")).toBe(true);
		expect(isNonOverridableBlock("fe80::8.8.8.8")).toBe(true);
	});

	it("does NOT block regular private IPs (those are allowlistable)", () => {
		expect(isNonOverridableBlock("192.168.1.1")).toBe(false);
		expect(isNonOverridableBlock("10.0.0.1")).toBe(false);
		expect(isNonOverridableBlock("172.16.0.1")).toBe(false);
	});

	it("does NOT block public IPs", () => {
		expect(isNonOverridableBlock("8.8.8.8")).toBe(false);
		expect(isNonOverridableBlock("1.1.1.1")).toBe(false);
	});
});

describe("isPrivateIP", () => {
	it("identifies RFC1918 addresses", () => {
		expect(isPrivateIP("192.168.1.1")).toBe(true);
		expect(isPrivateIP("10.0.0.1")).toBe(true);
		expect(isPrivateIP("172.16.0.1")).toBe(true);
		expect(isPrivateIP("172.31.255.255")).toBe(true);
	});

	it("identifies loopback", () => {
		expect(isPrivateIP("127.0.0.1")).toBe(true);
		expect(isPrivateIP("127.255.255.255")).toBe(true);
		expect(isPrivateIP("::1")).toBe(true);
	});

	it("identifies IPv6 ULA (fc00::/7)", () => {
		expect(isPrivateIP("fc00::1")).toBe(true);
		expect(isPrivateIP("fd12:3456:789a::1")).toBe(true);
	});

	it("identifies IPv4-mapped IPv6 private addresses", () => {
		expect(isPrivateIP("::ffff:192.168.1.1")).toBe(true);
		expect(isPrivateIP("::ffff:10.0.0.1")).toBe(true);
	});

	it("identifies IPv4-compatible IPv6 private addresses", () => {
		expect(isPrivateIP("::192.168.1.1")).toBe(true);
		expect(isPrivateIP("::10.0.0.1")).toBe(true);
	});

	it("does NOT identify link-local as private (handled by non-overridable)", () => {
		expect(isPrivateIP("::")).toBe(false);
		expect(isPrivateIP("0:0:0:0:0:0:0:0")).toBe(false);
		expect(isPrivateIP("169.254.1.1")).toBe(false);
		expect(isPrivateIP("fe80::1")).toBe(false);
		expect(isPrivateIP("::169.254.1.1")).toBe(false);
	});

	it("does NOT identify AWS IMDSv6 as private because it is non-overridable", () => {
		expect(isPrivateIP("fd00:ec2::254")).toBe(false);
		expect(isPrivateIP("fd00:0ec2:0:0:0:0:0:0254")).toBe(false);
	});

	it("does NOT identify AWS EKS Pod Identity IPv6 as private because it is non-overridable", () => {
		expect(isPrivateIP("fd00:ec2::23")).toBe(false);
		expect(isPrivateIP("fd00:0ec2:0:0:0:0:0:0023")).toBe(false);
	});

	it("does NOT identify GCP IMDSv6 as private because it is non-overridable", () => {
		expect(isPrivateIP("fd20:ce::254")).toBe(false);
		expect(isPrivateIP("fd20:00ce:0:0:0:0:0:0254")).toBe(false);
	});

	it("does NOT identify public IPs as private", () => {
		expect(isPrivateIP("8.8.8.8")).toBe(false);
		expect(isPrivateIP("2001:4860:4860::8888")).toBe(false);
	});
});

describe("findMatchingPrivateEndpoint", () => {
	const endpoints: PrivateEndpoint[] = [
		{ label: "home-assistant", host: "192.168.1.100", ports: [8123] },
		{ label: "homelab", cidr: "192.168.1.0/24" },
		{ label: "plex", host: "10.0.0.50", ports: [32400] },
	];

	it("matches exact IP", () => {
		const result = findMatchingPrivateEndpoint("192.168.1.100", endpoints);
		expect(result.matched).toBe(true);
		expect(result.endpoint?.label).toBe("home-assistant");
	});

	it("matches IP within CIDR range", () => {
		const result = findMatchingPrivateEndpoint("192.168.1.200", endpoints);
		expect(result.matched).toBe(true);
		expect(result.endpoint?.label).toBe("homelab");
	});

	it("does NOT match IP outside CIDR range", () => {
		const result = findMatchingPrivateEndpoint("192.168.2.1", endpoints);
		expect(result.matched).toBe(false);
	});

	it("does NOT match different private network", () => {
		const result = findMatchingPrivateEndpoint("172.16.0.1", endpoints);
		expect(result.matched).toBe(false);
	});
});

describe("isPortAllowedByEndpoint", () => {
	it("allows explicitly listed ports", () => {
		const endpoint: PrivateEndpoint = {
			label: "test",
			host: "192.168.1.1",
			ports: [8123, 8080],
		};
		expect(isPortAllowedByEndpoint(8123, endpoint)).toBe(true);
		expect(isPortAllowedByEndpoint(8080, endpoint)).toBe(true);
	});

	it("blocks non-listed ports", () => {
		const endpoint: PrivateEndpoint = {
			label: "test",
			host: "192.168.1.1",
			ports: [8123],
		};
		expect(isPortAllowedByEndpoint(22, endpoint)).toBe(false);
		expect(isPortAllowedByEndpoint(3389, endpoint)).toBe(false);
	});

	it("defaults to 80/443 when no ports specified", () => {
		const endpoint: PrivateEndpoint = {
			label: "test",
			host: "192.168.1.1",
		};
		expect(isPortAllowedByEndpoint(80, endpoint)).toBe(true);
		expect(isPortAllowedByEndpoint(443, endpoint)).toBe(true);
		expect(isPortAllowedByEndpoint(8123, endpoint)).toBe(false);
	});
});

describe("checkPrivateNetworkAccess", () => {
	const endpoints: PrivateEndpoint[] = [
		{ label: "home-assistant", host: "192.168.1.100", ports: [8123] },
		{ label: "homelab-http", cidr: "192.168.1.0/24", ports: [80, 443] },
	];

	it("allows access to configured endpoint with correct port", async () => {
		const result = await checkPrivateNetworkAccess("192.168.1.100", 8123, endpoints);
		expect(result.allowed).toBe(true);
		expect(result.matchedEndpoint?.label).toBe("home-assistant");
	});

	it("blocks access to configured endpoint with wrong port", async () => {
		const result = await checkPrivateNetworkAccess("192.168.1.100", 22, endpoints);
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("Port 22 is not allowed");
	});

	it("allows access to IP in CIDR range with correct port", async () => {
		const result = await checkPrivateNetworkAccess("192.168.1.200", 443, endpoints);
		expect(result.allowed).toBe(true);
	});

	it("blocks access to private IP not in allowlist", async () => {
		const result = await checkPrivateNetworkAccess("192.168.2.1", 80, endpoints);
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("not in the allowlist");
	});

	it("ALWAYS blocks metadata endpoint (non-overridable)", async () => {
		// Even if someone tries to add it to the allowlist, it should be blocked
		const endpointsWithMetadata: PrivateEndpoint[] = [
			...endpoints,
			{ label: "fake-metadata", host: "169.254.169.254", ports: [80] },
		];
		const result = await checkPrivateNetworkAccess("169.254.169.254", 80, endpointsWithMetadata);
		expect(result.allowed).toBe(false);
		// Blocked by metadata check OR non-overridable check
		expect(
			result.reason?.includes("Metadata endpoint") || result.reason?.includes("Non-overridable"),
		).toBe(true);
	});

	it("ALWAYS blocks link-local range (non-overridable)", async () => {
		const result = await checkPrivateNetworkAccess("169.254.1.1", 80, endpoints);
		expect(result.allowed).toBe(false);
	});

	it("ALWAYS blocks IPv6 unspecified addresses after canonicalization", async () => {
		for (const host of ["::", "0:0:0:0:0:0:0:0"]) {
			const result = await checkPrivateNetworkAccess(host, 443, [
				...endpoints,
				{ label: "fake-unspecified", host, ports: [443] },
			]);
			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("Non-overridable");
		}
	});

	it("ALWAYS blocks AWS IMDSv6 after canonicalization even when allowlisted", async () => {
		for (const host of ["fd00:ec2::254", "fd00:0ec2:0:0:0:0:0:0254"]) {
			const result = await checkPrivateNetworkAccess(host, 80, [
				...endpoints,
				{ label: "fake-imdsv6", host, ports: [80] },
			]);
			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("Non-overridable");
		}
	});

	it("ALWAYS blocks AWS EKS Pod Identity IPv6 after canonicalization even when allowlisted", async () => {
		for (const host of ["fd00:ec2::23", "fd00:0ec2:0:0:0:0:0:0023"]) {
			const result = await checkPrivateNetworkAccess(host, 80, [
				...endpoints,
				{ label: "fake-eks-pod-identity", host, ports: [80] },
			]);
			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("Non-overridable");
		}
	});

	it("ALWAYS blocks GCP IMDSv6 after canonicalization even when allowlisted", async () => {
		for (const host of ["fd20:ce::254", "fd20:00ce:0:0:0:0:0:0254"]) {
			const result = await checkPrivateNetworkAccess(host, 80, [
				...endpoints,
				{ label: "fake-gcp-imdsv6", host, ports: [80] },
			]);
			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("Non-overridable");
		}
	});

	it("blocks IPv6 loopback addresses after canonicalization unless allowlisted", async () => {
		for (const host of ["::1", "0:0:0:0:0:0:0:1"]) {
			const result = await checkPrivateNetworkAccess(host, 443, endpoints);
			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("not in the allowlist");
		}
	});

	it("allows access to public IPs (handled by domain allowlist)", async () => {
		// Public IPs are not blocked by private network check
		// They should be handled by the domain allowlist
		const result = await checkPrivateNetworkAccess("8.8.8.8", 443, endpoints);
		expect(result.allowed).toBe(true);
		expect(result.matchedEndpoint).toBeUndefined(); // No private endpoint matched
	});
});

describe("Security bypass prevention", () => {
	const endpoints: PrivateEndpoint[] = [{ label: "test", host: "192.168.1.100", ports: [8123] }];

	it("blocks metadata domain name lookup attempts", async () => {
		const result = await checkPrivateNetworkAccess("metadata.google.internal", 80, endpoints);
		expect(result.allowed).toBe(false);
	});

	it("blocks loopback (127.0.0.1) even if not in allowlist", async () => {
		const result = await checkPrivateNetworkAccess("127.0.0.1", 80, endpoints);
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("not in the allowlist");
	});
});
