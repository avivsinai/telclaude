import { afterEach, describe, expect, it, vi } from "vitest";

const cachedDNSLookupImpl = vi.hoisted(() => vi.fn());
const isNonOverridableBlockImpl = vi.hoisted(() =>
	vi.fn((ip: string) => ip === "169.254.169.254"),
);
const isPrivateIPImpl = vi.hoisted(() =>
	vi.fn((ip: string) =>
		/^10\./.test(ip) ||
		/^127\./.test(ip) ||
		/^192\.168\./.test(ip) ||
		/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip),
	),
);

vi.mock("../../src/sandbox/network-proxy.js", () => ({
	cachedDNSLookup: (...args: unknown[]) => cachedDNSLookupImpl(...args),
	checkPrivateNetworkAccess: vi.fn(),
	isNonOverridableBlock: (...args: unknown[]) => isNonOverridableBlockImpl(...args),
	isPrivateIP: (...args: unknown[]) => isPrivateIPImpl(...args),
}));

import { validateProviderBaseUrlInput } from "../../src/providers/provider-validation.js";

describe("validateProviderBaseUrlInput", () => {
	afterEach(() => {
		cachedDNSLookupImpl.mockReset();
	});

	it("rejects raw private IPs", async () => {
		await expect(validateProviderBaseUrlInput("http://10.0.0.5:3001")).rejects.toThrow(
			/raw private, metadata, or CGNAT IP/i,
		);
	});

	it("rejects metadata IPs", async () => {
		await expect(validateProviderBaseUrlInput("http://169.254.169.254")).rejects.toThrow(
			/raw private, metadata, or CGNAT IP/i,
		);
	});

	it("rejects plain-http public hostnames", async () => {
		await expect(validateProviderBaseUrlInput("http://example.com")).rejects.toThrow(/must use https/i);
	});

	it("allows container hostnames over http", async () => {
		cachedDNSLookupImpl.mockResolvedValueOnce([]);
		await expect(validateProviderBaseUrlInput("http://google-services:3001")).resolves.toMatchObject({
			hostname: "google-services",
			protocol: "http:",
		});
	});

	it("allows loopback addresses over http", async () => {
		await expect(validateProviderBaseUrlInput("http://127.0.0.1:3001")).resolves.toMatchObject({
			hostname: "127.0.0.1",
			protocol: "http:",
		});
	});

	it("rejects public hostnames that resolve to blocked private targets", async () => {
		cachedDNSLookupImpl.mockResolvedValueOnce(["10.0.0.5"]);
		await expect(validateProviderBaseUrlInput("https://provider.example.com")).rejects.toThrow(
			/resolves to blocked private IPs/i,
		);
	});
});
