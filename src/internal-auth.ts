import crypto from "node:crypto";
import type http from "node:http";

const HEADER_TIMESTAMP = "x-telclaude-timestamp";
const HEADER_NONCE = "x-telclaude-nonce";
const HEADER_SIGNATURE = "x-telclaude-signature";
const HEADER_AUTH_TYPE = "x-telclaude-auth-type";
const HEADER_SESSION_TOKEN = "x-telclaude-session-token";
const SIGNING_VERSION_ASYMMETRIC = "v2";

const TELEGRAM_RPC_PRIVATE_KEY_ENV = "TELEGRAM_RPC_PRIVATE_KEY";
const TELEGRAM_RPC_PUBLIC_KEY_ENV = "TELEGRAM_RPC_PUBLIC_KEY";
const MOLTBOOK_RPC_PRIVATE_KEY_ENV = "MOLTBOOK_RPC_PRIVATE_KEY";
const MOLTBOOK_RPC_PUBLIC_KEY_ENV = "MOLTBOOK_RPC_PUBLIC_KEY";

const RAW_SKEW_MS = Number(process.env.TELCLAUDE_INTERNAL_RPC_SKEW_MS ?? 5 * 60 * 1000);
const RAW_NONCE_TTL_MS = Number(process.env.TELCLAUDE_INTERNAL_RPC_NONCE_TTL_MS ?? 10 * 60 * 1000);
const DEFAULT_SKEW_MS = Number.isFinite(RAW_SKEW_MS) ? RAW_SKEW_MS : 5 * 60 * 1000;
const DEFAULT_NONCE_TTL_MS = Number.isFinite(RAW_NONCE_TTL_MS) ? RAW_NONCE_TTL_MS : 10 * 60 * 1000;
const PRUNE_INTERVAL_MS = 30_000;

const nonceCache = new Map<string, number>();
let lastPrune = 0;

type SignatureInput = {
	timestamp: string;
	nonce: string;
	method: string;
	path: string;
	body: string;
};

export type InternalAuthScope = "telegram" | "moltbook";

export type InternalAuthResult =
	| { ok: true; scope: InternalAuthScope }
	| { ok: false; status: number; error: string; reason: string };

export function isInternalAuthScope(value: string): value is InternalAuthScope {
	return value === "telegram" || value === "moltbook";
}

type InternalAuthOptions = {
	scope?: InternalAuthScope;
};

function getHeader(req: http.IncomingMessage, name: string): string | undefined {
	const value = req.headers[name];
	if (Array.isArray(value)) return value[0];
	return value;
}

/**
 * Sign payload with Ed25519 private key (asymmetric).
 * Returns base64-encoded signature.
 * Scope is included in the signed payload to bind signatures to their intended scope.
 */
function signAsymmetric(privateKeyBase64: string, input: SignatureInput, scope: string): string {
	const privateKey = Buffer.from(privateKeyBase64, "base64");
	const payload = Buffer.from(
		[
			SIGNING_VERSION_ASYMMETRIC,
			scope,
			input.timestamp,
			input.nonce,
			input.method.toUpperCase(),
			input.path,
			input.body,
		].join("\n"),
	);
	const signature = crypto.sign(null, payload, {
		key: privateKey,
		format: "der",
		type: "pkcs8",
	});
	return signature.toString("base64");
}

/**
 * Verify Ed25519 signature (asymmetric).
 * Agent only needs public key - cannot forge signatures.
 * Scope is included in the verified payload to ensure scope-bound signatures.
 */
function verifyAsymmetric(
	publicKeyBase64: string,
	signature: string,
	input: SignatureInput,
	scope: string,
): boolean {
	try {
		const publicKey = Buffer.from(publicKeyBase64, "base64");
		const payload = Buffer.from(
			[
				SIGNING_VERSION_ASYMMETRIC,
				scope,
				input.timestamp,
				input.nonce,
				input.method.toUpperCase(),
				input.path,
				input.body,
			].join("\n"),
		);
		const signatureBuffer = Buffer.from(signature, "base64");
		return crypto.verify(
			null,
			payload,
			{ key: publicKey, format: "der", type: "spki" },
			signatureBuffer,
		);
	} catch {
		return false;
	}
}

/**
 * Load asymmetric keys from environment for the given scope.
 */
function loadAsymmetricKeys(scope: "telegram" | "moltbook"): {
	privateKey?: string;
	publicKey?: string;
} {
	if (scope === "telegram") {
		return {
			privateKey: process.env[TELEGRAM_RPC_PRIVATE_KEY_ENV],
			publicKey: process.env[TELEGRAM_RPC_PUBLIC_KEY_ENV],
		};
	}
	return {
		privateKey: process.env[MOLTBOOK_RPC_PRIVATE_KEY_ENV],
		publicKey: process.env[MOLTBOOK_RPC_PUBLIC_KEY_ENV],
	};
}

/**
 * Generate Ed25519 key pair for asymmetric RPC auth.
 * Returns base64-encoded keys in DER format.
 *
 * Usage:
 *   const { privateKey, publicKey } = generateKeyPair();
 *   // Relay gets: <SCOPE>_RPC_PRIVATE_KEY=<privateKey>
 *   // Agent gets: <SCOPE>_RPC_PUBLIC_KEY=<publicKey>
 */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
	const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
		privateKeyEncoding: { type: "pkcs8", format: "der" },
		publicKeyEncoding: { type: "spki", format: "der" },
	});
	return {
		privateKey: privateKey.toString("base64"),
		publicKey: publicKey.toString("base64"),
	};
}

function pruneNonces(now: number): void {
	if (now - lastPrune < PRUNE_INTERVAL_MS) return;
	lastPrune = now;
	for (const [nonce, expiresAt] of nonceCache.entries()) {
		if (expiresAt <= now) {
			nonceCache.delete(nonce);
		}
	}
}

export function buildInternalAuthHeaders(
	method: string,
	path: string,
	body: string,
	options?: InternalAuthOptions,
): Record<string, string> {
	const timestamp = Date.now().toString();
	const nonce = crypto.randomBytes(16).toString("hex");
	const input: SignatureInput = { timestamp, nonce, method, path, body };
	const scope = options?.scope ?? "telegram";

	const { privateKey } = loadAsymmetricKeys(scope);
	if (privateKey) {
		const signature = signAsymmetric(privateKey, input, scope);
		return {
			"X-Telclaude-Timestamp": timestamp,
			"X-Telclaude-Nonce": nonce,
			"X-Telclaude-Signature": signature,
			"X-Telclaude-Auth-Type": "asymmetric",
		};
	}

	const envVar = scope === "telegram" ? TELEGRAM_RPC_PRIVATE_KEY_ENV : MOLTBOOK_RPC_PRIVATE_KEY_ENV;
	throw new Error(
		`Missing RPC credentials for ${scope}. Set ${envVar} (relay). Run \`telclaude keygen ${scope}\` to generate keys.`,
	);
}

/**
 * Verify a v3 session token.
 * Returns null if no session token header present (fall through to v2 asymmetric).
 * Requires a public key for Ed25519 verification.
 */
export function verifySessionToken(
	token: string,
	publicKeyBase64: string,
): InternalAuthResult | null {
	// Parse token: v3:{scope}:{sessionId}:{createdAt}:{expiresAt}:{signature}
	const parts = token.split(":");
	if (parts.length !== 6) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Invalid session token format.",
		};
	}

	const [version, scope, sessionId, createdAtStr, expiresAtStr, signatureB64url] = parts;
	if (version !== "v3") {
		return { ok: false, status: 401, error: "Unauthorized.", reason: "Invalid token version." };
	}
	if (!scope || !sessionId || !signatureB64url) {
		return { ok: false, status: 401, error: "Unauthorized.", reason: "Missing token fields." };
	}

	const expiresAt = Number(expiresAtStr);
	if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) {
		return { ok: false, status: 401, error: "Unauthorized.", reason: "Token expired." };
	}

	// Verify Ed25519 signature
	const payload = `v3:${scope}:${sessionId}:${createdAtStr}:${expiresAtStr}`;
	try {
		const publicKey = Buffer.from(publicKeyBase64, "base64");
		const signature = Buffer.from(signatureB64url, "base64url");
		const valid = crypto.verify(
			null,
			Buffer.from(payload),
			{ key: publicKey, format: "der", type: "spki" },
			signature,
		);
		if (!valid) {
			return {
				ok: false,
				status: 401,
				error: "Unauthorized.",
				reason: "Invalid session token signature.",
			};
		}
	} catch {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Session token verification failed.",
		};
	}

	if (!isInternalAuthScope(scope)) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Invalid session token scope.",
		};
	}

	return { ok: true, scope };
}

/**
 * Try v3 session token from request headers.
 * Returns null if no session token, allowing fall-through to v2 asymmetric.
 */
export function trySessionTokenFromRequest(
	req: http.IncomingMessage,
	publicKeyBase64: string | null,
): InternalAuthResult | null {
	const authType = getHeader(req, HEADER_AUTH_TYPE);
	const sessionToken = getHeader(req, HEADER_SESSION_TOKEN);

	if (authType !== "session" && !sessionToken) {
		return null; // No v3 token, fall through
	}

	if (!sessionToken) {
		return null;
	}

	if (!publicKeyBase64) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Session token auth not configured.",
		};
	}

	return verifySessionToken(sessionToken, publicKeyBase64);
}

export function verifyInternalAuth(req: http.IncomingMessage, body: string): InternalAuthResult {
	const timestamp = getHeader(req, HEADER_TIMESTAMP);
	const nonce = getHeader(req, HEADER_NONCE);
	const signature = getHeader(req, HEADER_SIGNATURE);
	const authType = getHeader(req, HEADER_AUTH_TYPE);

	if (!timestamp || !nonce || !signature) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Missing internal auth headers.",
		};
	}

	if (nonce.length > 128) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Nonce too long.",
		};
	}

	const timestampMs = Number.parseInt(timestamp, 10);
	if (!Number.isFinite(timestampMs)) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Invalid timestamp.",
		};
	}

	const now = Date.now();
	if (Math.abs(now - timestampMs) > DEFAULT_SKEW_MS) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Timestamp outside allowed window.",
		};
	}

	pruneNonces(now);
	if (nonceCache.has(nonce)) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Nonce replayed.",
		};
	}

	const method = req.method ?? "POST";
	const path = req.url ?? "";
	const input: SignatureInput = { timestamp, nonce, method, path, body };

	// Load asymmetric keys for both scopes
	const telegramKeys = loadAsymmetricKeys("telegram");
	const moltbookKeys = loadAsymmetricKeys("moltbook");

	if (authType !== "asymmetric") {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Only asymmetric auth is supported. Set X-Telclaude-Auth-Type: asymmetric.",
		};
	}

	// Try telegram public key
	if (
		telegramKeys.publicKey &&
		verifyAsymmetric(telegramKeys.publicKey, signature, input, "telegram")
	) {
		nonceCache.set(nonce, now + DEFAULT_NONCE_TTL_MS);
		return { ok: true, scope: "telegram" };
	}

	// Try moltbook public key
	if (
		moltbookKeys.publicKey &&
		verifyAsymmetric(moltbookKeys.publicKey, signature, input, "moltbook")
	) {
		nonceCache.set(nonce, now + DEFAULT_NONCE_TTL_MS);
		return { ok: true, scope: "moltbook" };
	}

	// No matching key configured
	if (!telegramKeys.publicKey && !moltbookKeys.publicKey) {
		return {
			ok: false,
			status: 500,
			error: "Internal auth misconfigured.",
			reason: `Missing RPC credentials. Set ${TELEGRAM_RPC_PRIVATE_KEY_ENV}/${TELEGRAM_RPC_PUBLIC_KEY_ENV} or ${MOLTBOOK_RPC_PRIVATE_KEY_ENV}/${MOLTBOOK_RPC_PUBLIC_KEY_ENV}.`,
		};
	}

	return {
		ok: false,
		status: 401,
		error: "Unauthorized.",
		reason: "Invalid asymmetric signature.",
	};
}
