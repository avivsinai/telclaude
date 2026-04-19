import { describe, expect, it } from "vitest";
import { getProviderCatalogEntry } from "../../src/providers/catalog.js";
import {
	buildCatalogProviderInput,
	buildCustomProviderInput,
	removeConfiguredProvider,
	upsertConfiguredProvider,
	upsertProviderPrivateEndpoint,
} from "../../src/commands/providers.js";

describe("providers config helpers", () => {
	it("adds a configured provider from the catalog", () => {
		const rawConfig: Record<string, unknown> = {};
		const entry = getProviderCatalogEntry("google");
		expect(entry).toBeDefined();

		upsertConfiguredProvider(rawConfig, buildCatalogProviderInput(entry!, "http://google-services:3001/"));

		expect(rawConfig.providers).toEqual([
			{
				id: "google",
				baseUrl: "http://google-services:3001",
				services: ["gmail", "calendar", "drive", "contacts"],
				description: "Google Services sidecar for Gmail, Calendar, Drive, and Contacts.",
			},
		]);
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

		upsertConfiguredProvider(rawConfig, buildCatalogProviderInput(entry!, "http://google-services:3001"));

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
