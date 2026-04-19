import { afterEach, describe, expect, it, vi } from "vitest";

const relayProviderProxyImpl = vi.hoisted(() => vi.fn());
const relayRefreshProvidersImpl = vi.hoisted(() => vi.fn());
const clearProviderSkillStateImpl = vi.hoisted(() => vi.fn());
const refreshExternalProviderSkillImpl = vi.hoisted(() => vi.fn());
const fetchProviderSchemaImpl = vi.hoisted(() => vi.fn());
const buildSchemaMarkdownImpl = vi.hoisted(() => vi.fn());

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayProviderProxy: (...args: unknown[]) => relayProviderProxyImpl(...args),
	relayRefreshProviders: (...args: unknown[]) => relayRefreshProvidersImpl(...args),
}));

vi.mock("../../src/providers/provider-skill.js", () => ({
	buildSchemaMarkdown: (...args: unknown[]) => buildSchemaMarkdownImpl(...args),
	clearProviderSkillState: (...args: unknown[]) => clearProviderSkillStateImpl(...args),
	fetchProviderSchema: (...args: unknown[]) => fetchProviderSchemaImpl(...args),
	refreshExternalProviderSkill: (...args: unknown[]) => refreshExternalProviderSkillImpl(...args),
}));

import { refreshConfiguredProviders } from "../../src/commands/providers.js";

const ORIGINAL_CAPABILITIES_URL = process.env.TELCLAUDE_CAPABILITIES_URL;

describe("refreshConfiguredProviders", () => {
	afterEach(() => {
		relayProviderProxyImpl.mockReset();
		relayRefreshProvidersImpl.mockReset();
		clearProviderSkillStateImpl.mockReset();
		refreshExternalProviderSkillImpl.mockReset();
		fetchProviderSchemaImpl.mockReset();
		buildSchemaMarkdownImpl.mockReset();
		if (ORIGINAL_CAPABILITIES_URL === undefined) {
			delete process.env.TELCLAUDE_CAPABILITIES_URL;
		} else {
			process.env.TELCLAUDE_CAPABILITIES_URL = ORIGINAL_CAPABILITIES_URL;
		}
	});

	it("uses the relay runtime refresh when capabilities are available", async () => {
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay.test";
		relayRefreshProvidersImpl.mockResolvedValueOnce({
			ok: true,
			providers: [
				{
					id: "israel-services",
					baseUrl: "http://israel-services.local:3001",
					services: ["gov-api"],
					description: "Citizen services",
				},
			],
			schemaMarkdown: "# refreshed schema",
			providersEpoch: "epoch-1",
		});

		const result = await refreshConfiguredProviders([
			{
				id: "israel-services",
				baseUrl: "http://israel-services.local:3001",
				services: ["gov-api"],
				description: "Citizen services",
			},
		]);

		expect(result).toEqual({ providerCount: 1, cleared: false });
		expect(relayRefreshProvidersImpl).toHaveBeenCalledTimes(1);
		expect(refreshExternalProviderSkillImpl).not.toHaveBeenCalled();
		expect(clearProviderSkillStateImpl).not.toHaveBeenCalled();
	});

	it("falls back to local refresh when the relay refresh fails", async () => {
		process.env.TELCLAUDE_CAPABILITIES_URL = "http://relay.test";
		relayRefreshProvidersImpl.mockRejectedValueOnce(new Error("relay unavailable"));

		const providers = [
			{
				id: "israel-services",
				baseUrl: "http://israel-services.local:3001",
				services: ["gov-api"],
				description: "Citizen services",
			},
		];

		const result = await refreshConfiguredProviders(providers);

		expect(result).toEqual({ providerCount: 1, cleared: false });
		expect(relayRefreshProvidersImpl).toHaveBeenCalledTimes(1);
		expect(refreshExternalProviderSkillImpl).toHaveBeenCalledWith(providers);
	});
});
