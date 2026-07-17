import crypto from "node:crypto";

import type { ExternalProviderConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getVaultClient } from "../vault-daemon/client.js";

const logger = getChildLogger({ module: "provider-sidecar-auth" });

export const PROVIDER_SIDECAR_HMAC_SECRET_ENV = "TELCLAUDE_ISRAEL_SIDECAR_HMAC_KEY";
export const PROVIDER_SIDECAR_HMAC_VAULT_TARGET_ENV = "TELCLAUDE_ISRAEL_SIDECAR_HMAC_VAULT_TARGET";
export const PROVIDER_SIDECAR_HMAC_DEFAULT_VAULT_TARGET = "israel-services/relay-hmac/v1";

const DEFAULT_KEY_ID = "v1";
const MIN_SECRET_BYTES = 32;
const VAULT_LOOKUP_TIMEOUT_MS = 2_000;
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000;
const NEGATIVE_CACHE_TTL_MS = 30 * 1000;

type ProviderSidecarHmacHeadersOptions = {
	keyId: string;
	method: string;
	path: string;
	rawBody: string;
	secret: string;
	actorUserId?: string;
	timestampMs?: number;
	nonce?: string;
};

type ProviderSidecarRelayAuthOptions = {
	provider: ExternalProviderConfig;
	method: string;
	path: string;
	rawBody: string;
	actorUserId?: string;
};

type SecretCache = {
	value?: string;
	expiresAt: number;
};

let vaultSecretCache: SecretCache | null = null;

export function buildProviderSidecarHmacHeaders(
	options: ProviderSidecarHmacHeadersOptions,
): Record<string, string> {
	const timestamp = String(options.timestampMs ?? Date.now());
	const nonce = options.nonce ?? crypto.randomBytes(16).toString("base64url");
	const bodyHash = crypto.createHash("sha256").update(options.rawBody).digest("hex");
	const canonical = [options.method.toUpperCase(), options.path, bodyHash, timestamp, nonce].join(
		"\n",
	);
	const signature = crypto
		.createHmac("sha256", options.secret)
		.update(canonical)
		.digest("base64url");
	const actorUserId = options.actorUserId?.trim();
	const actorSignature = actorUserId
		? crypto
				.createHmac("sha256", options.secret)
				.update(`${canonical}\nACTOR\n${actorUserId}`)
				.digest("base64url")
		: undefined;

	return {
		"x-relay-key-id": options.keyId,
		"x-relay-timestamp": timestamp,
		"x-relay-nonce": nonce,
		"x-relay-signature": signature,
		...(actorSignature ? { "x-relay-actor-signature": actorSignature } : {}),
	};
}

export async function buildProviderSidecarRelayAuthHeaders(
	options: ProviderSidecarRelayAuthOptions,
): Promise<Record<string, string>> {
	if (!shouldSignProviderSidecarRequest(options.provider)) {
		return {};
	}

	const secret = await resolveProviderSidecarHmacSecret();
	if (!secret) {
		return {};
	}

	return buildProviderSidecarHmacHeaders({
		keyId: DEFAULT_KEY_ID,
		method: options.method,
		path: options.path,
		rawBody: options.rawBody,
		secret,
		actorUserId: options.actorUserId,
	});
}

export async function buildRequiredProviderSidecarRelayAuthHeaders(
	options: ProviderSidecarRelayAuthOptions,
): Promise<Record<string, string>> {
	if (!shouldSignProviderSidecarRequest(options.provider)) {
		throw new Error(`Provider '${options.provider.id}' does not support relay HMAC signing`);
	}

	const secret = await resolveProviderSidecarHmacSecret();
	if (!secret) {
		throw new Error("Provider sidecar HMAC secret is not configured");
	}

	return buildProviderSidecarHmacHeaders({
		keyId: DEFAULT_KEY_ID,
		method: options.method,
		path: options.path,
		rawBody: options.rawBody,
		secret,
		actorUserId: options.actorUserId,
	});
}

export function shouldSignProviderSidecarRequest(provider: ExternalProviderConfig): boolean {
	return provider.id === "israel-services";
}

export function resetProviderSidecarHmacSecretCacheForTests(): void {
	vaultSecretCache = null;
}

async function resolveProviderSidecarHmacSecret(): Promise<string | undefined> {
	const envSecret = normalizeSecret(
		process.env[PROVIDER_SIDECAR_HMAC_SECRET_ENV],
		`env:${PROVIDER_SIDECAR_HMAC_SECRET_ENV}`,
	);
	if (envSecret) {
		return envSecret;
	}

	const now = Date.now();
	if (vaultSecretCache && vaultSecretCache.expiresAt > now) {
		return vaultSecretCache.value;
	}

	const vaultTarget =
		process.env[PROVIDER_SIDECAR_HMAC_VAULT_TARGET_ENV]?.trim() ||
		PROVIDER_SIDECAR_HMAC_DEFAULT_VAULT_TARGET;
	try {
		const response = await getVaultClient().getSecret(vaultTarget, {
			timeout: VAULT_LOOKUP_TIMEOUT_MS,
		});
		const vaultSecret =
			response.ok && response.type === "get-secret"
				? normalizeSecret(response.value, `vault-secret:${vaultTarget}`)
				: undefined;
		vaultSecretCache = {
			value: vaultSecret,
			expiresAt: now + (vaultSecret ? SECRET_CACHE_TTL_MS : NEGATIVE_CACHE_TTL_MS),
		};
		return vaultSecret;
	} catch (error) {
		vaultSecretCache = { expiresAt: now + NEGATIVE_CACHE_TTL_MS };
		logger.debug({ error: String(error), vaultTarget }, "provider sidecar HMAC secret unavailable");
		return undefined;
	}
}

function normalizeSecret(value: string | undefined, source: string): string | undefined {
	const trimmed = value?.trim();
	if (!trimmed) return undefined;
	if (Buffer.byteLength(trimmed, "utf8") < MIN_SECRET_BYTES) {
		logger.warn({ source }, "provider sidecar HMAC secret is too short; skipping signing");
		return undefined;
	}
	return trimmed;
}
