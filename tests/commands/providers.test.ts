import { describe, expect, it } from "vitest";
import {
	buildCatalogProviderInput,
	buildCustomProviderInput,
	removeConfiguredProvider,
	upsertConfiguredProvider,
	upsertProviderPrivateEndpoint,
} from "../../src/commands/providers.js";
import { getProviderCatalogEntry } from "../../src/providers/catalog.js";

describe("providers config helpers", () => {
	it("adds a configured provider from the catalog", () => {
		const rawConfig: Record<string, unknown> = {};
		const entry = getProviderCatalogEntry("google");
		expect(entry).toBeDefined();

		upsertConfiguredProvider(
			rawConfig,
			buildCatalogProviderInput(entry!, "http://google-services:3001/"),
		);

		expect(rawConfig.providers).toEqual([
			{
				id: "google",
				baseUrl: "http://google-services:3001",
				services: ["gmail", "calendar", "drive", "contacts"],
				description: "Google Services sidecar for Gmail, Calendar, Drive, and Contacts.",
			},
		]);
	});

	it.each([
		["bank", "http://bank-provider:3001", ["bank"], "Banking Provider"],
		["clalit", "http://clalit-provider:3001", ["clalit"], "Clalit Provider"],
		["government", "http://government-provider:3001", ["government"], "Government Provider"],
	] as const)("adds the %s provider-domain sidecar from the catalog", (providerId, baseUrl, services, displayName) => {
		const rawConfig: Record<string, unknown> = {};
		const entry = getProviderCatalogEntry(providerId);
		if (!entry) throw new Error(`missing provider catalog entry ${providerId}`);
		expect(entry).toMatchObject({
			id: providerId,
			displayName,
			services,
			defaultBaseUrl: baseUrl,
		});

		upsertConfiguredProvider(rawConfig, buildCatalogProviderInput(entry, `${baseUrl}/`));
		upsertProviderPrivateEndpoint(rawConfig, buildCatalogProviderInput(entry, baseUrl));

		expect(rawConfig.providers).toEqual([
			expect.objectContaining({
				id: providerId,
				baseUrl,
				services,
			}),
		]);
		expect(rawConfig.security).toEqual({
			network: {
				privateEndpoints: [
					expect.objectContaining({
						label: `provider-${providerId}`,
						ports: [3001],
					}),
				],
			},
		});
	});

	it("replaces an existing provider entry by id", () => {
		const rawConfig: Record<string, unknown> = {
			providers: [
				{
					id: "google",
					baseUrl: "http://old-host:3001",
					services: ["gmail"],
					description: "old",
				},
			],
		};
		const entry = getProviderCatalogEntry("google");
		expect(entry).toBeDefined();

		upsertConfiguredProvider(
			rawConfig,
			buildCatalogProviderInput(entry!, "http://google-services:3001"),
		);

		expect(rawConfig.providers).toEqual([
			{
				id: "google",
				baseUrl: "http://google-services:3001",
				services: ["gmail", "calendar", "drive", "contacts"],
				description: "Google Services sidecar for Gmail, Calendar, Drive, and Contacts.",
			},
		]);
	});

	it("adds a private endpoint keyed by provider label", () => {
		const rawConfig: Record<string, unknown> = {};
		const entry = getProviderCatalogEntry("google");
		expect(entry).toBeDefined();

		upsertProviderPrivateEndpoint(
			rawConfig,
			buildCatalogProviderInput(entry!, "http://google-services:3001"),
		);

		expect(rawConfig.security).toEqual({
			network: {
				privateEndpoints: [
					{
						label: "provider-google",
						host: "google-services",
						ports: [3001],
						description: "Google Services provider sidecar",
					},
				],
			},
		});
	});

	it("adds a custom provider without requiring a catalog entry", () => {
		const rawConfig: Record<string, unknown> = {};
		const input = buildCustomProviderInput({
			id: "israel-services",
			baseUrl: "http://israel-services.local:3001/",
			services: ["gov-api", "health-api"],
			description: "Private citizen-services sidecar",
		});

		upsertConfiguredProvider(rawConfig, input);
		upsertProviderPrivateEndpoint(rawConfig, input);

		expect(rawConfig.providers).toEqual([
			{
				id: "israel-services",
				baseUrl: "http://israel-services.local:3001",
				services: ["gov-api", "health-api"],
				description: "Private citizen-services sidecar",
			},
		]);
		expect(rawConfig.security).toEqual({
			network: {
				privateEndpoints: [
					{
						label: "provider-israel-services",
						host: "israel-services.local",
						ports: [3001],
						description: "Private citizen-services sidecar",
					},
				],
			},
		});
	});

	it("removes a provider and its matching private endpoint label", () => {
		const rawConfig: Record<string, unknown> = {
			providers: [
				{
					id: "google",
					baseUrl: "http://google-services:3001",
					services: ["gmail"],
					description: "Google",
				},
				{
					id: "israel-services",
					baseUrl: "http://israel-services.local:3001",
					services: ["gov-api"],
					description: "Citizen",
				},
			],
			security: {
				network: {
					privateEndpoints: [
						{
							label: "provider-google",
							host: "google-services",
							ports: [3001],
						},
						{
							label: "provider-israel-services",
							host: "israel-services.local",
							ports: [3001],
						},
					],
				},
			},
		};

		const result = removeConfiguredProvider(rawConfig, "israel-services");

		expect(result).toEqual({ removedProvider: true, removedPrivateEndpoint: true });
		expect(rawConfig.providers).toEqual([
			{
				id: "google",
				baseUrl: "http://google-services:3001",
				services: ["gmail"],
				description: "Google",
			},
		]);
		expect((rawConfig.security as any).network.privateEndpoints).toEqual([
			{
				label: "provider-google",
				host: "google-services",
				ports: [3001],
			},
		]);
	});
});
