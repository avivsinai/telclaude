/**
 * Vault daemon client.
 *
 * Used by the relay to communicate with the vault sidecar.
 * Uses newline-delimited JSON over Unix socket.
 */

import { createConnection } from "node:net";
import {
	type DeleteResponse,
	type GetPublicKeyResponse,
	type GetResponse,
	type GetSecretResponse,
	type GetTokenResponse,
	getDefaultSocketPath,
	type ListResponse,
	type Protocol,
	type SignTokenResponse,
	type StoreRequest,
	type VaultRequest,
	type VaultResponse,
	VaultResponseSchema,
	type VerifyTokenResponse,
} from "./protocol.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Client Options
// ═══════════════════════════════════════════════════════════════════════════════

export interface VaultClientOptions {
	socketPath?: string;
	timeout?: number; // ms
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vault Client
// ═══════════════════════════════════════════════════════════════════════════════

export class VaultClient {
	private socketPath: string;
	private timeout: number;

	constructor(options: VaultClientOptions = {}) {
		this.socketPath = options.socketPath ?? getDefaultSocketPath();
		this.timeout = options.timeout ?? 30000; // 30 seconds default
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Public API
	// ═══════════════════════════════════════════════════════════════════════════

	/**
	 * Get a credential by protocol and target.
	 */
	async get(protocol: Protocol, target: string): Promise<GetResponse> {
		return (await this.send({ type: "get", protocol, target })) as GetResponse;
	}

	/**
	 * Get an OAuth2 access token (vault handles refresh).
	 */
	async getToken(target: string): Promise<GetTokenResponse> {
		return (await this.send({
			type: "get-token",
			protocol: "http",
			target,
		})) as GetTokenResponse;
	}

	/**
	 * Store a credential.
	 */
	async store(request: Omit<StoreRequest, "type">): Promise<{ type: "store"; ok: true }> {
		return (await this.send({ type: "store", ...request })) as { type: "store"; ok: true };
	}

	/**
	 * Delete a credential.
	 */
	async delete(protocol: Protocol, target: string): Promise<DeleteResponse> {
		return (await this.send({ type: "delete", protocol, target })) as DeleteResponse;
	}

	/**
	 * List credentials (without secrets).
	 */
	async list(protocol?: Protocol): Promise<ListResponse> {
		return (await this.send({ type: "list", protocol })) as ListResponse;
	}

	/**
	 * Ping the vault daemon.
	 */
	async ping(): Promise<boolean> {
		try {
			const response = await this.send({ type: "ping" });
			return response.type === "pong";
		} catch {
			return false;
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Token Signing
	// ═══════════════════════════════════════════════════════════════════════════

	/**
	 * Sign a session token. Auto-generates Ed25519 keypair on first use.
	 */
	async signToken(
		scope: string,
		sessionId: string,
		ttlMs: number,
		options?: { timeout?: number },
	): Promise<SignTokenResponse> {
		return (await this.send(
			{ type: "sign-token", scope, sessionId, ttlMs },
			options?.timeout,
		)) as SignTokenResponse;
	}

	/**
	 * Verify a session token signature and check expiry.
	 */
	async verifyToken(token: string, options?: { timeout?: number }): Promise<VerifyTokenResponse> {
		return (await this.send(
			{ type: "verify-token", token },
			options?.timeout,
		)) as VerifyTokenResponse;
	}

	/**
	 * Get the Ed25519 public key for local token verification.
	 */
	async getPublicKey(options?: { timeout?: number }): Promise<GetPublicKeyResponse> {
		return (await this.send({ type: "get-public-key" }, options?.timeout)) as GetPublicKeyResponse;
	}

	/**
	 * Get an opaque secret value.
	 */
	async getSecret(target: string, options?: { timeout?: number }): Promise<GetSecretResponse> {
		return (await this.send({ type: "get-secret", target }, options?.timeout)) as GetSecretResponse;
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// Socket Communication
	// ═══════════════════════════════════════════════════════════════════════════

	private async send(request: VaultRequest, timeoutOverride?: number): Promise<VaultResponse> {
		const effectiveTimeout = timeoutOverride ?? this.timeout;
		return new Promise((resolve, reject) => {
			const socket = createConnection({ path: this.socketPath });
			let buffer = "";
			let resolved = false;

			// Set timeout
			const timeoutId = setTimeout(() => {
				if (!resolved) {
					resolved = true;
					socket.destroy();
					reject(new Error(`Vault request timed out after ${effectiveTimeout}ms`));
				}
			}, effectiveTimeout);

			socket.on("connect", () => {
				socket.write(`${JSON.stringify(request)}\n`);
			});

			socket.on("data", (data) => {
				buffer += data.toString();

				// Look for complete response (newline-delimited)
				const newlineIndex = buffer.indexOf("\n");
				if (newlineIndex !== -1) {
					const line = buffer.slice(0, newlineIndex);
					resolved = true;
					clearTimeout(timeoutId);
					socket.end();

					try {
						const parsed = JSON.parse(line);
						const response = VaultResponseSchema.parse(parsed);
						resolve(response);
					} catch (err) {
						reject(new Error(`Invalid response from vault: ${String(err)}`));
					}
				}
			});

			socket.on("error", (err) => {
				if (!resolved) {
					resolved = true;
					clearTimeout(timeoutId);
					reject(new Error(`Vault connection error: ${String(err)}`));
				}
			});

			socket.on("close", () => {
				if (!resolved) {
					resolved = true;
					clearTimeout(timeoutId);
					reject(new Error("Vault connection closed before response"));
				}
			});
		});
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Singleton
// ═══════════════════════════════════════════════════════════════════════════════

let cachedClient: VaultClient | null = null;

/**
 * Get the vault client singleton.
 */
export function getVaultClient(options?: VaultClientOptions): VaultClient {
	if (!cachedClient) {
		cachedClient = new VaultClient(options);
	}
	return cachedClient;
}

/**
 * Reset the vault client (for testing).
 */
export function resetVaultClient(): void {
	cachedClient = null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Convenience Functions
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if the vault daemon is running.
 */
export async function isVaultAvailable(options?: VaultClientOptions): Promise<boolean> {
	try {
		const client = new VaultClient(options);
		return await client.ping();
	} catch {
		return false;
	}
}
