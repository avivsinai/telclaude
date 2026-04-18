import { describe, expect, it } from "vitest";
import { getProviderCatalogEntry } from "../../src/providers/catalog.js";
import {
	upsertConfiguredProvider,
	upsertProviderPrivateEndpoint,
} from "../../src/commands/providers.js";

describe("providers config helpers", () => {
	it("adds a configured provider from the catalog", () => {
		const rawConfig: Record<string, unknown> = {};
		const entry = getProviderCatalogEntry("google");
		expect(entry).toBeDefined();

		upsertConfiguredProvider(rawConfig, entry!, "http://google-services:3001/");

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

		upsertConfiguredProvider(rawConfig, entry!, "http://google-services:3001");

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

		upsertProviderPrivateEndpoint(rawConfig, entry!, "http://google-services:3001");

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
});
