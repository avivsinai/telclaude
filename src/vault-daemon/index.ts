/**
 * Credential Vault Daemon
 *
 * A secure sidecar service for storing and managing credentials.
 * Agents never see raw credentials - they interact through protocol connectors
 * (HTTP proxy, etc) that inject credentials transparently.
 *
 * Architecture:
 * - Vault sidecar: No network, Unix socket only, stores encrypted credentials
 * - Protocol connectors: HTTP proxy (in relay) injects auth headers
 * - Agent: Makes normal HTTP requests through proxy, never sees credentials
 */

// Client
export {
	getVaultClient,
	isVaultAvailable,
	resetVaultClient,
	VaultClient,
	type VaultClientOptions,
} from "./client.js";
// OAuth
export {
	clearTokenCache,
	getAccessToken,
	invalidateToken,
	startCleanupTimer,
	stopCleanupTimer,
} from "./oauth.js";
// Protocol types
export {
	type Credential,
	type CredentialEntry,
	CredentialEntrySchema,
	CredentialSchema,
	type DbCredential,
	DbCredentialSchema,
	type DeleteRequest,
	type DeleteResponse,
	type ErrorResponse,
	type GetRequest,
	type GetResponse,
	type GetTokenRequest,
	type GetTokenResponse,
	getDefaultSocketPath,
	type HttpCredential,
	HttpCredentialSchema,
	type ListEntry,
	type ListRequest,
	type ListResponse,
	makeStorageKey,
	type OAuth2Credential,
	OAuth2CredentialSchema,
	type PongResponse,
	type Protocol,
	ProtocolSchema,
	parseStorageKey,
	type SshCredential,
	SshCredentialSchema,
	type StoreRequest,
	type StoreResponse,
	type VaultRequest,
	VaultRequestSchema,
	type VaultResponse,
	VaultResponseSchema,
} from "./protocol.js";
// Server
export { type ServerHandle, type ServerOptions, startServer } from "./server.js";
// Store
export { getVaultStore, resetVaultStore, VaultStore, type VaultStoreOptions } from "./store.js";
