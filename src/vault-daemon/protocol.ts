/**
 * Credential Vault daemon IPC protocol types.
 *
 * Uses Zod for runtime validation of messages.
 * Protocol is newline-delimited JSON over Unix socket.
 *
 * The vault stores credentials keyed by (protocol, target) and injects them
 * into protocol-specific connectors (HTTP proxy, etc). The agent never sees
 * raw credentials.
 *
 * Supported protocols:
 * - http: REST/GraphQL APIs (bearer, api-key, basic, oauth2)
 * - postgres: PostgreSQL databases (future)
 * - mysql: MySQL databases (future)
 * - ssh: SSH servers (future)
 */

import { z } from "zod";

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol Types
// ═══════════════════════════════════════════════════════════════════════════════

export const ProtocolSchema = z.enum(["http", "postgres", "mysql", "ssh"]);
export type Protocol = z.infer<typeof ProtocolSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Credential Types
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * HTTP credentials - for REST/GraphQL APIs
 */
export const HttpBearerCredentialSchema = z.object({
	type: z.literal("bearer"),
	token: z.string().min(1),
});

// RFC7230 token: only safe characters for HTTP header field names
// Prevents header injection attacks
const RFC7230_TOKEN_REGEX = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

export const HttpApiKeyCredentialSchema = z.object({
	type: z.literal("api-key"),
	token: z.string().min(1),
	header: z
		.string()
		.min(1)
		.regex(RFC7230_TOKEN_REGEX, "Header name must be a valid RFC7230 token"), // e.g., "X-API-Key", "x-api-key"
});

export const HttpBasicCredentialSchema = z.object({
	type: z.literal("basic"),
	username: z.string().min(1),
	password: z.string(),
});

// Safe query parameter name: alphanumeric, underscore, hyphen only
// Prevents query string injection attacks
const SAFE_QUERY_PARAM_REGEX = /^[A-Za-z0-9_-]+$/;

export const HttpQueryCredentialSchema = z.object({
	type: z.literal("query"),
	token: z.string().min(1),
	param: z
		.string()
		.min(1)
		.regex(SAFE_QUERY_PARAM_REGEX, "Query param must be alphanumeric with _ or - only"), // e.g., "api_key", "key"
});

export const HttpCredentialSchema = z.discriminatedUnion("type", [
	HttpBearerCredentialSchema,
	HttpApiKeyCredentialSchema,
	HttpBasicCredentialSchema,
	HttpQueryCredentialSchema,
]);

export type HttpCredential = z.infer<typeof HttpCredentialSchema>;

/**
 * OAuth2 credentials - vault handles token refresh internally
 */
export const OAuth2CredentialSchema = z.object({
	type: z.literal("oauth2"),
	clientId: z.string().min(1),
	clientSecret: z.string().min(1),
	refreshToken: z.string().min(1),
	tokenEndpoint: z.string().url(),
	scope: z.string().optional(),
});

export type OAuth2Credential = z.infer<typeof OAuth2CredentialSchema>;

/**
 * Database credentials (future)
 */
export const DbCredentialSchema = z.object({
	type: z.literal("db"),
	username: z.string().min(1),
	password: z.string(),
	database: z.string().optional(),
});

export type DbCredential = z.infer<typeof DbCredentialSchema>;

/**
 * SSH credentials (future)
 */
export const SshKeyCredentialSchema = z.object({
	type: z.literal("ssh-key"),
	username: z.string().min(1),
	privateKey: z.string().min(1),
	passphrase: z.string().optional(),
});

export const SshPasswordCredentialSchema = z.object({
	type: z.literal("ssh-password"),
	username: z.string().min(1),
	password: z.string(),
});

export const SshCredentialSchema = z.discriminatedUnion("type", [
	SshKeyCredentialSchema,
	SshPasswordCredentialSchema,
]);

export type SshCredential = z.infer<typeof SshCredentialSchema>;

/**
 * All credential types
 */
export const CredentialSchema = z.union([
	HttpCredentialSchema,
	OAuth2CredentialSchema,
	DbCredentialSchema,
	SshCredentialSchema,
]);

export type Credential = z.infer<typeof CredentialSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Credential Entry (stored in vault)
// ═══════════════════════════════════════════════════════════════════════════════

export const CredentialEntrySchema = z.object({
	protocol: ProtocolSchema,
	target: z.string().min(1), // host or host:port
	label: z.string().optional(),
	credential: CredentialSchema,
	allowedPaths: z.array(z.string()).optional(), // For HTTP: path regex allowlist
	rateLimitPerMinute: z.number().positive().optional(),
	createdAt: z.string().datetime(),
	expiresAt: z.string().datetime().optional(),
});

export type CredentialEntry = z.infer<typeof CredentialEntrySchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Request Types
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get a credential by protocol and target
 */
export const GetRequestSchema = z.object({
	type: z.literal("get"),
	protocol: ProtocolSchema,
	target: z.string().min(1),
});

/**
 * Get an OAuth2 access token (vault handles refresh)
 */
export const GetTokenRequestSchema = z.object({
	type: z.literal("get-token"),
	protocol: z.literal("http"),
	target: z.string().min(1),
});

/**
 * Store a credential
 */
export const StoreRequestSchema = z.object({
	type: z.literal("store"),
	protocol: ProtocolSchema,
	target: z.string().min(1),
	label: z.string().optional(),
	credential: CredentialSchema,
	allowedPaths: z.array(z.string()).optional(),
	rateLimitPerMinute: z.number().positive().optional(),
	expiresAt: z.string().datetime().optional(),
});

/**
 * Delete a credential
 */
export const DeleteRequestSchema = z.object({
	type: z.literal("delete"),
	protocol: ProtocolSchema,
	target: z.string().min(1),
});

/**
 * List credentials (without exposing secrets)
 */
export const ListRequestSchema = z.object({
	type: z.literal("list"),
	protocol: ProtocolSchema.optional(), // Optional filter
});

/**
 * Ping (health check)
 */
export const PingRequestSchema = z.object({
	type: z.literal("ping"),
});

export const VaultRequestSchema = z.discriminatedUnion("type", [
	GetRequestSchema,
	GetTokenRequestSchema,
	StoreRequestSchema,
	DeleteRequestSchema,
	ListRequestSchema,
	PingRequestSchema,
]);

export type VaultRequest = z.infer<typeof VaultRequestSchema>;
export type GetRequest = z.infer<typeof GetRequestSchema>;
export type GetTokenRequest = z.infer<typeof GetTokenRequestSchema>;
export type StoreRequest = z.infer<typeof StoreRequestSchema>;
export type DeleteRequest = z.infer<typeof DeleteRequestSchema>;
export type ListRequest = z.infer<typeof ListRequestSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Response Types
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get response - returns credential with injection config
 */
export const GetSuccessResponseSchema = z.object({
	type: z.literal("get"),
	ok: z.literal(true),
	entry: CredentialEntrySchema,
});

export const GetNotFoundResponseSchema = z.object({
	type: z.literal("get"),
	ok: z.literal(false),
	error: z.literal("not_found"),
});

export const GetResponseSchema = z.union([GetSuccessResponseSchema, GetNotFoundResponseSchema]);

export type GetSuccessResponse = z.infer<typeof GetSuccessResponseSchema>;
export type GetNotFoundResponse = z.infer<typeof GetNotFoundResponseSchema>;
export type GetResponse = z.infer<typeof GetResponseSchema>;

/**
 * Get-token response - returns current valid access token
 */
export const GetTokenSuccessResponseSchema = z.object({
	type: z.literal("get-token"),
	ok: z.literal(true),
	token: z.string().min(1),
	expiresAt: z.number(), // Unix timestamp in MILLISECONDS (Date.now() compatible)
});

export const GetTokenErrorResponseSchema = z.object({
	type: z.literal("get-token"),
	ok: z.literal(false),
	error: z.string(),
});

export const GetTokenResponseSchema = z.union([
	GetTokenSuccessResponseSchema,
	GetTokenErrorResponseSchema,
]);

export type GetTokenSuccessResponse = z.infer<typeof GetTokenSuccessResponseSchema>;
export type GetTokenErrorResponse = z.infer<typeof GetTokenErrorResponseSchema>;
export type GetTokenResponse = z.infer<typeof GetTokenResponseSchema>;

/**
 * Store response
 */
export const StoreResponseSchema = z.object({
	type: z.literal("store"),
	ok: z.literal(true),
});

export type StoreResponse = z.infer<typeof StoreResponseSchema>;

/**
 * Delete response
 */
export const DeleteSuccessResponseSchema = z.object({
	type: z.literal("delete"),
	ok: z.literal(true),
	deleted: z.literal(true),
});

export const DeleteNotFoundResponseSchema = z.object({
	type: z.literal("delete"),
	ok: z.literal(true),
	deleted: z.literal(false),
});

export const DeleteResponseSchema = z.union([
	DeleteSuccessResponseSchema,
	DeleteNotFoundResponseSchema,
]);

export type DeleteResponse = z.infer<typeof DeleteResponseSchema>;

/**
 * List response - returns metadata only (no credentials)
 */
export const ListEntrySchema = z.object({
	protocol: ProtocolSchema,
	target: z.string(),
	label: z.string().optional(),
	credentialType: z.string(), // e.g., "bearer", "oauth2", "ssh-key"
	createdAt: z.string().datetime(),
	expiresAt: z.string().datetime().optional(),
});

export type ListEntry = z.infer<typeof ListEntrySchema>;

export const ListResponseSchema = z.object({
	type: z.literal("list"),
	ok: z.literal(true),
	entries: z.array(ListEntrySchema),
});

export type ListResponse = z.infer<typeof ListResponseSchema>;

/**
 * Pong response
 */
export const PongResponseSchema = z.object({
	type: z.literal("pong"),
});

export type PongResponse = z.infer<typeof PongResponseSchema>;

/**
 * Error response
 */
export const ErrorResponseSchema = z.object({
	type: z.literal("error"),
	error: z.string(),
});

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;

/**
 * All response types
 */
export const VaultResponseSchema = z.union([
	GetResponseSchema,
	GetTokenResponseSchema,
	StoreResponseSchema,
	DeleteResponseSchema,
	ListResponseSchema,
	PongResponseSchema,
	ErrorResponseSchema,
]);

export type VaultResponse = z.infer<typeof VaultResponseSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Socket Path
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get the default socket path for the vault daemon.
 * Uses ~/.telclaude/vault.sock
 */
export function getDefaultSocketPath(): string {
	const home = process.env.HOME || "/tmp";
	return `${home}/.telclaude/vault.sock`;
}

/**
 * Generate a storage key for a credential entry.
 */
export function makeStorageKey(protocol: Protocol, target: string): string {
	return `${protocol}:${target}`;
}

/**
 * Parse a storage key back into protocol and target.
 */
export function parseStorageKey(key: string): { protocol: Protocol; target: string } | null {
	const colonIndex = key.indexOf(":");
	if (colonIndex === -1) return null;

	const protocol = key.slice(0, colonIndex);
	const target = key.slice(colonIndex + 1);

	const result = ProtocolSchema.safeParse(protocol);
	if (!result.success) return null;

	return { protocol: result.data, target };
}
