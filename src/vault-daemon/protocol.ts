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

export const ProtocolSchema = z.enum(["http", "postgres", "mysql", "ssh", "signing", "secret"]);
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
	header: z.string().min(1).regex(RFC7230_TOKEN_REGEX, "Header name must be a valid RFC7230 token"), // e.g., "X-API-Key", "x-api-key"
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
 * SECURITY: tokenEndpoint must be HTTPS to prevent credential transmission over plaintext
 */
export const OAuth2CredentialSchema = z.object({
	type: z.literal("oauth2"),
	clientId: z.string().min(1),
	clientSecret: z.string().min(1),
	refreshToken: z.string().min(1),
	tokenEndpoint: z
		.string()
		.url()
		.refine((url) => url.startsWith("https://"), {
			message: "Token endpoint must use HTTPS to protect credentials in transit",
		}),
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
 * Signing credentials - Ed25519 keypair for token signing/verification
 */
export const SigningCredentialSchema = z.object({
	type: z.literal("ed25519"),
	privateKey: z.string().min(1), // base64-encoded DER (pkcs8)
	publicKey: z.string().min(1), // base64-encoded DER (spki)
});

export type SigningCredential = z.infer<typeof SigningCredentialSchema>;

/**
 * Opaque secret - arbitrary values (bot tokens, app configs, etc.)
 */
export const OpaqueSecretCredentialSchema = z.object({
	type: z.literal("opaque"),
	value: z.string().min(1),
});

export type OpaqueSecretCredential = z.infer<typeof OpaqueSecretCredentialSchema>;

/**
 * All credential types
 */
export const CredentialSchema = z.union([
	HttpCredentialSchema,
	OAuth2CredentialSchema,
	DbCredentialSchema,
	SshCredentialSchema,
	SigningCredentialSchema,
	OpaqueSecretCredentialSchema,
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
 * Sign a session token with the vault's Ed25519 master key.
 * Auto-generates keypair if not present.
 */
export const SignTokenRequestSchema = z.object({
	type: z.literal("sign-token"),
	scope: z.string().min(1), // e.g., "telegram", "social"
	sessionId: z.string().min(1),
	ttlMs: z.number().positive(), // token lifetime in milliseconds
});

/**
 * Verify a session token signature.
 */
export const VerifyTokenRequestSchema = z.object({
	type: z.literal("verify-token"),
	token: z.string().min(1), // full token string: v3:{scope}:{sessionId}:{createdAt}:{expiresAt}:{signature}
});

/**
 * Get the Ed25519 public key for local token verification.
 */
export const GetPublicKeyRequestSchema = z.object({
	type: z.literal("get-public-key"),
});

/**
 * Get an opaque secret value.
 */
export const GetSecretRequestSchema = z.object({
	type: z.literal("get-secret"),
	target: z.string().min(1), // e.g., "telegram-bot-token"
});

/**
 * Sign an arbitrary payload with the vault's Ed25519 key.
 * Prefix is prepended before signing to prevent cross-context replay.
 */
export const SignPayloadRequestSchema = z.object({
	type: z.literal("sign-payload"),
	payload: z.string().min(1),
	prefix: z.string().min(1),
});

/**
 * Verify a signature over an arbitrary payload.
 */
export const VerifyPayloadRequestSchema = z.object({
	type: z.literal("verify-payload"),
	payload: z.string().min(1),
	signature: z.string().min(1),
	prefix: z.string().min(1),
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
	SignTokenRequestSchema,
	VerifyTokenRequestSchema,
	GetPublicKeyRequestSchema,
	GetSecretRequestSchema,
	SignPayloadRequestSchema,
	VerifyPayloadRequestSchema,
	PingRequestSchema,
]);

export type VaultRequest = z.infer<typeof VaultRequestSchema>;
export type GetRequest = z.infer<typeof GetRequestSchema>;
export type GetTokenRequest = z.infer<typeof GetTokenRequestSchema>;
export type StoreRequest = z.infer<typeof StoreRequestSchema>;
export type DeleteRequest = z.infer<typeof DeleteRequestSchema>;
export type ListRequest = z.infer<typeof ListRequestSchema>;
export type SignTokenRequest = z.infer<typeof SignTokenRequestSchema>;
export type VerifyTokenRequest = z.infer<typeof VerifyTokenRequestSchema>;
export type GetPublicKeyRequest = z.infer<typeof GetPublicKeyRequestSchema>;
export type GetSecretRequest = z.infer<typeof GetSecretRequestSchema>;
export type SignPayloadRequest = z.infer<typeof SignPayloadRequestSchema>;
export type VerifyPayloadRequest = z.infer<typeof VerifyPayloadRequestSchema>;

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
 * Sign-token response
 */
export const SignTokenResponseSchema = z.object({
	type: z.literal("sign-token"),
	ok: z.literal(true),
	token: z.string().min(1), // full token: v3:{scope}:{sessionId}:{createdAt}:{expiresAt}:{signature}
	expiresAt: z.number(), // Unix timestamp ms
});

export type SignTokenResponse = z.infer<typeof SignTokenResponseSchema>;

/**
 * Verify-token response
 */
export const VerifyTokenSuccessResponseSchema = z.object({
	type: z.literal("verify-token"),
	ok: z.literal(true),
	scope: z.string(),
	sessionId: z.string(),
	createdAt: z.number(),
	expiresAt: z.number(),
});

export const VerifyTokenFailureResponseSchema = z.object({
	type: z.literal("verify-token"),
	ok: z.literal(false),
	error: z.string(),
});

export const VerifyTokenResponseSchema = z.union([
	VerifyTokenSuccessResponseSchema,
	VerifyTokenFailureResponseSchema,
]);

export type VerifyTokenResponse = z.infer<typeof VerifyTokenResponseSchema>;

/**
 * Get-public-key response
 */
export const GetPublicKeyResponseSchema = z.object({
	type: z.literal("get-public-key"),
	ok: z.literal(true),
	publicKey: z.string().min(1), // base64-encoded DER (spki)
});

export type GetPublicKeyResponse = z.infer<typeof GetPublicKeyResponseSchema>;

/**
 * Get-secret response
 */
export const GetSecretSuccessResponseSchema = z.object({
	type: z.literal("get-secret"),
	ok: z.literal(true),
	value: z.string(),
});

export const GetSecretNotFoundResponseSchema = z.object({
	type: z.literal("get-secret"),
	ok: z.literal(false),
	error: z.literal("not_found"),
});

export const GetSecretResponseSchema = z.union([
	GetSecretSuccessResponseSchema,
	GetSecretNotFoundResponseSchema,
]);

export type GetSecretResponse = z.infer<typeof GetSecretResponseSchema>;

/**
 * Sign-payload response
 */
export const SignPayloadResponseSchema = z.object({
	type: z.literal("sign-payload"),
	signature: z.string(),
});

export type SignPayloadResponse = z.infer<typeof SignPayloadResponseSchema>;

/**
 * Verify-payload response
 */
export const VerifyPayloadResponseSchema = z.object({
	type: z.literal("verify-payload"),
	valid: z.boolean(),
});

export type VerifyPayloadResponse = z.infer<typeof VerifyPayloadResponseSchema>;

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
	SignTokenResponseSchema,
	VerifyTokenResponseSchema,
	GetPublicKeyResponseSchema,
	GetSecretResponseSchema,
	SignPayloadResponseSchema,
	VerifyPayloadResponseSchema,
	PongResponseSchema,
	ErrorResponseSchema,
]);

export type VaultResponse = z.infer<typeof VaultResponseSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Socket Path
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get the default socket path for the vault daemon.
 *
 * Resolution order:
 * 1) TELCLAUDE_VAULT_SOCKET (recommended for Docker / sidecar setups)
 * 2) ~/.telclaude/vault.sock
 */
export function getDefaultSocketPath(): string {
	const configured = process.env.TELCLAUDE_VAULT_SOCKET?.trim();
	if (configured) return configured;
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
