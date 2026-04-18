import { z } from "zod";
import catalogJson from "./catalog.json" with { type: "json" };

const OAuthServiceCatalogSchema = z.object({
	id: z.string().min(1),
	displayName: z.string().min(1),
	authorizationUrl: z.string().url(),
	tokenEndpoint: z.string().url(),
	defaultScopes: z.array(z.string().min(1)).min(1),
	confidentialClient: z.boolean().default(true),
	vaultTarget: z.string().min(1),
	vaultLabel: z.string().min(1),
	vaultAllowedPaths: z.array(z.string()).optional(),
	userIdEndpoint: z.string().url().optional(),
	userIdJsonPath: z.string().optional(),
	userIdEnvVar: z.string().optional(),
});

const ProviderCatalogEntrySchema = z.object({
	id: z.string().min(1),
	displayName: z.string().min(1),
	description: z.string().min(1),
	services: z.array(z.string().min(1)).default([]),
	oauthServiceId: z.string().min(1).optional(),
	setupCommand: z.string().min(1).optional(),
	defaultBaseUrl: z.string().url().optional(),
});

const ProviderCatalogSchema = z.object({
	oauthServices: z.array(OAuthServiceCatalogSchema).default([]),
	providers: z.array(ProviderCatalogEntrySchema).default([]),
});

type ProviderCatalog = z.infer<typeof ProviderCatalogSchema>;
export type CatalogOAuthService = z.infer<typeof OAuthServiceCatalogSchema>;
export type ProviderCatalogEntry = z.infer<typeof ProviderCatalogEntrySchema>;

const parsedCatalog: ProviderCatalog = ProviderCatalogSchema.parse(catalogJson);

export function listCatalogOAuthServices(): CatalogOAuthService[] {
	return [...parsedCatalog.oauthServices];
}

export function getCatalogOAuthService(id: string): CatalogOAuthService | undefined {
	return parsedCatalog.oauthServices.find((service) => service.id === id);
}

export function listProviderCatalogEntries(): ProviderCatalogEntry[] {
	return [...parsedCatalog.providers];
}

export function getProviderCatalogEntry(id: string): ProviderCatalogEntry | undefined {
	return parsedCatalog.providers.find((provider) => provider.id === id);
}
