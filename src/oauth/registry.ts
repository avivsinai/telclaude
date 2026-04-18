/**
 * Static registry of known OAuth2 service definitions.
 *
 * Each entry provides endpoints, default scopes, vault target,
 * and optional user-ID extraction after authorization.
 */

import { getCatalogOAuthService, listCatalogOAuthServices } from "../providers/catalog.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface OAuth2ServiceDefinition {
	/** Service identifier (matches socialServices[].id in config) */
	id: string;
	/** Human-readable name */
	displayName: string;
	/** Browser redirect target for authorization */
	authorizationUrl: string;
	/** Token exchange endpoint (must be HTTPS) */
	tokenEndpoint: string;
	/** Default OAuth2 scopes to request */
	defaultScopes: string[];
	/** Whether to use HTTP Basic auth for client credentials (confidential client) */
	confidentialClient: boolean;
	/** Vault target host for credential storage */
	vaultTarget: string;
	/** Vault credential label */
	vaultLabel: string;
	/** Optional: regex patterns for allowed API paths in vault */
	vaultAllowedPaths?: string[];
	/** Optional: GET endpoint to fetch user ID with new token */
	userIdEndpoint?: string;
	/** JSON path to extract user ID from userIdEndpoint response */
	userIdJsonPath?: string;
	/** Env var name for user ID (shown in "next steps" output) */
	userIdEnvVar?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════════════════════

const SERVICES: OAuth2ServiceDefinition[] = listCatalogOAuthServices();

/**
 * Look up a service definition by ID.
 */
export function getService(id: string): OAuth2ServiceDefinition | undefined {
	return getCatalogOAuthService(id);
}

/**
 * List all known service IDs.
 */
export function listServices(): OAuth2ServiceDefinition[] {
	return [...SERVICES];
}
