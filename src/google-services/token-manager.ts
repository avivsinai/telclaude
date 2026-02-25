/**
 * Token manager — thin wrapper around vault client for Google OAuth tokens.
 * Handles error classification and health state tracking.
 */

import type { VaultClient } from "../vault-daemon/client.js";
import type { HealthStore } from "./health.js";

const VAULT_TARGET = "googleapis.com";

export class TokenManager {
	private vault: VaultClient;
	private health: HealthStore;
	private cachedPublicKey: string | null = null;

	constructor(vault: VaultClient, health: HealthStore) {
		this.vault = vault;
		this.health = health;
	}

	/**
	 * Get a fresh Google OAuth access token.
	 * @param service - The requesting service (for per-service health tracking)
	 */
	async getAccessToken(
		service?: string,
	): Promise<
		| { ok: true; token: string; expiresAt: number }
		| { ok: false; error: string; errorClass: string }
	> {
		try {
			const result = await this.vault.getToken(VAULT_TARGET);
			if (result.ok) {
				if (service) this.health.recordSuccess(service);
				return { ok: true, token: result.token, expiresAt: result.expiresAt };
			}

			// Classify error
			const errorClass = classifyTokenError(result.error);
			if (service) {
				if (errorClass === "auth_expired") {
					this.health.recordAuthExpired(service);
				} else {
					this.health.recordFailure(service);
				}
			}

			return { ok: false, error: result.error, errorClass };
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			if (service) this.health.recordFailure(service);
			return { ok: false, error: msg, errorClass: "transient" };
		}
	}

	/**
	 * Get the vault's Ed25519 public key for approval token verification.
	 * Cached after first fetch.
	 */
	async getPublicKey(): Promise<string> {
		if (this.cachedPublicKey) return this.cachedPublicKey;
		const result = await this.vault.getPublicKey();
		if (!result.ok) throw new Error("Failed to get vault public key");
		this.cachedPublicKey = result.publicKey;
		return result.publicKey;
	}
}

/**
 * Classify a token error into an error category.
 */
function classifyTokenError(error: string): string {
	const lower = error.toLowerCase();
	if (lower.includes("invalid_client")) {
		return "config_error";
	}
	if (lower.includes("invalid_grant") || lower.includes("revoked")) {
		return "auth_expired";
	}
	if (lower.includes("rate") || lower.includes("429")) {
		return "rate_limited";
	}
	return "transient";
}
