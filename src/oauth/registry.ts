/**
 * Static registry of known OAuth2 service definitions.
 *
 * Each entry provides endpoints, default scopes, vault target,
 * and optional user-ID extraction after authorization.
 */

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

const SERVICES: OAuth2ServiceDefinition[] = [
	{
		id: "google",
		displayName: "Google",
		authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
		tokenEndpoint: "https://oauth2.googleapis.com/token",
		defaultScopes: [
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/calendar.events.readonly",
			"https://www.googleapis.com/auth/calendar.calendarlist.readonly",
			"https://www.googleapis.com/auth/calendar.freebusy",
			"https://www.googleapis.com/auth/drive.metadata.readonly",
			"https://www.googleapis.com/auth/contacts.readonly",
		],
		confidentialClient: false,
		vaultTarget: "googleapis.com",
		vaultLabel: "Google OAuth2",
		userIdEndpoint: "https://www.googleapis.com/oauth2/v2/userinfo",
		userIdJsonPath: "email",
		userIdEnvVar: "GOOGLE_USER_EMAIL",
	},
	{
		id: "xtwitter",
		displayName: "X/Twitter",
		authorizationUrl: "https://twitter.com/i/oauth2/authorize",
		tokenEndpoint: "https://api.x.com/2/oauth2/token",
		defaultScopes: ["tweet.read", "tweet.write", "users.read", "offline.access"],
		confidentialClient: false,
		vaultTarget: "api.x.com",
		vaultLabel: "X/Twitter OAuth2",
		vaultAllowedPaths: ["/2/.*"],
		userIdEndpoint: "https://api.x.com/2/users/me",
		userIdJsonPath: "data.id",
		userIdEnvVar: "X_USER_ID",
	},
];

/**
 * Look up a service definition by ID.
 */
export function getService(id: string): OAuth2ServiceDefinition | undefined {
	return SERVICES.find((s) => s.id === id);
}

/**
 * List all known service IDs.
 */
export function listServices(): OAuth2ServiceDefinition[] {
	return [...SERVICES];
}
