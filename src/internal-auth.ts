import crypto from "node:crypto";
import type http from "node:http";

const HEADER_TIMESTAMP = "x-telclaude-timestamp";
const HEADER_NONCE = "x-telclaude-nonce";
const HEADER_SIGNATURE = "x-telclaude-signature";
const HEADER_AUTH_TYPE = "x-telclaude-auth-type";
const SIGNING_VERSION = "v1";
const SIGNING_VERSION_ASYMMETRIC = "v2";

const TELEGRAM_RPC_SECRET_ENV = "TELEGRAM_RPC_SECRET";
const MOLTBOOK_RPC_SECRET_ENV = "MOLTBOOK_RPC_SECRET";
const MOLTBOOK_RPC_PRIVATE_KEY_ENV = "MOLTBOOK_RPC_PRIVATE_KEY";
const MOLTBOOK_RPC_PUBLIC_KEY_ENV = "MOLTBOOK_RPC_PUBLIC_KEY";
const LEGACY_RPC_SECRET_ENV = "TELCLAUDE_INTERNAL_RPC_SECRET";

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

export type InternalAuthScope = "telegram" | "moltbook" | "legacy";

export type InternalAuthResult =
	| { ok: true; scope: InternalAuthScope }
	| { ok: false; status: number; error: string; reason: string };

type InternalAuthOptions = {
	scope?: InternalAuthScope;
	secret?: string;
};

function loadInternalRpcSecrets(): Array<{ scope: InternalAuthScope; secret: string }> {
	const secrets: Array<{ scope: InternalAuthScope; secret: string }> = [];
	const telegram = process.env[TELEGRAM_RPC_SECRET_ENV];
	if (telegram) {
		secrets.push({ scope: "telegram", secret: telegram });
	}
	const moltbook = process.env[MOLTBOOK_RPC_SECRET_ENV];
	if (moltbook) {
		secrets.push({ scope: "moltbook", secret: moltbook });
	}
	const legacy = process.env[LEGACY_RPC_SECRET_ENV];
	if (legacy) {
		secrets.push({ scope: "legacy", secret: legacy });
	}
	return secrets;
}

function resolveInternalRpcSecret(options?: InternalAuthOptions): {
	scope: InternalAuthScope;
	secret: string;
} {
	if (options?.secret) {
		return { scope: options.scope ?? "legacy", secret: options.secret };
	}

	const telegram = process.env[TELEGRAM_RPC_SECRET_ENV];
	const moltbook = process.env[MOLTBOOK_RPC_SECRET_ENV];
	const legacy = process.env[LEGACY_RPC_SECRET_ENV];

	const scope = options?.scope ?? "telegram";

	if (scope === "telegram") {
		const secret = telegram ?? legacy;
		if (!secret) {
			throw new Error(`${TELEGRAM_RPC_SECRET_ENV} is not configured`);
		}
		return { scope: telegram ? "telegram" : "legacy", secret };
	}

	if (scope === "moltbook") {
		const secret = moltbook ?? legacy;
		if (!secret) {
			throw new Error(`${MOLTBOOK_RPC_SECRET_ENV} is not configured`);
		}
		return { scope: moltbook ? "moltbook" : "legacy", secret };
	}

	if (!legacy) {
		throw new Error(`${LEGACY_RPC_SECRET_ENV} is not configured`);
	}
	return { scope: "legacy", secret: legacy };
}

function getHeader(req: http.IncomingMessage, name: string): string | undefined {
	const value = req.headers[name];
	if (Array.isArray(value)) return value[0];
	return value;
}

function buildSignaturePayload(input: SignatureInput): string {
	const method = input.method.toUpperCase();
	return [SIGNING_VERSION, input.timestamp, input.nonce, method, input.path, input.body].join("\n");
}

function computeSignature(secret: string, input: SignatureInput): string {
	const hmac = crypto.createHmac("sha256", secret);
	hmac.update(buildSignaturePayload(input));
	return hmac.digest("hex");
}

/**
 * Sign payload with Ed25519 private key (asymmetric).
 * Returns base64-encoded signature.
 */
function signAsymmetric(privateKeyBase64: string, input: SignatureInput): string {
	const privateKey = Buffer.from(privateKeyBase64, "base64");
	const payload = Buffer.from(
		[SIGNING_VERSION_ASYMMETRIC, input.timestamp, input.nonce, input.method.toUpperCase(), input.path, input.body].join("\n"),
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
 */
function verifyAsymmetric(publicKeyBase64: string, signature: string, input: SignatureInput): boolean {
	try {
		const publicKey = Buffer.from(publicKeyBase64, "base64");
		const payload = Buffer.from(
			[SIGNING_VERSION_ASYMMETRIC, input.timestamp, input.nonce, input.method.toUpperCase(), input.path, input.body].join("\n"),
		);
		const signatureBuffer = Buffer.from(signature, "base64");
		return crypto.verify(null, payload, { key: publicKey, format: "der", type: "spki" }, signatureBuffer);
	} catch {
		return false;
	}
}

/**
 * Load Moltbook asymmetric keys from environment.
 */
function loadMoltbookAsymmetricKeys(): { privateKey?: string; publicKey?: string } {
	return {
		privateKey: process.env[MOLTBOOK_RPC_PRIVATE_KEY_ENV],
		publicKey: process.env[MOLTBOOK_RPC_PUBLIC_KEY_ENV],
	};
}

/**
 * Generate Ed25519 key pair for asymmetric Moltbook RPC auth.
 * Returns base64-encoded keys in DER format.
 *
 * Usage:
 *   const { privateKey, publicKey } = generateMoltbookKeyPair();
 *   // Relay gets: MOLTBOOK_RPC_PRIVATE_KEY=<privateKey>
 *   // Agent gets: MOLTBOOK_RPC_PUBLIC_KEY=<publicKey>
 */
export function generateMoltbookKeyPair(): { privateKey: string; publicKey: string } {
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

	// For moltbook scope, require asymmetric auth (no symmetric fallback)
	if (options?.scope === "moltbook") {
		const { privateKey } = loadMoltbookAsymmetricKeys();
		if (!privateKey) {
			throw new Error(
				`${MOLTBOOK_RPC_PRIVATE_KEY_ENV} is required for moltbook scope. ` +
					`Generate keys with: telclaude moltbook-keygen`,
			);
		}
		const signature = signAsymmetric(privateKey, input);
		return {
			"X-Telclaude-Timestamp": timestamp,
			"X-Telclaude-Nonce": nonce,
			"X-Telclaude-Signature": signature,
			"X-Telclaude-Auth-Type": "asymmetric",
		};
	}

	// Symmetric HMAC for non-moltbook scopes (telegram, legacy)
	const { secret } = resolveInternalRpcSecret(options);
	const signature = computeSignature(secret, input);

	return {
		"X-Telclaude-Timestamp": timestamp,
		"X-Telclaude-Nonce": nonce,
		"X-Telclaude-Signature": signature,
	};
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

	// Check for asymmetric auth (required for moltbook scope when public key is configured)
	const { publicKey } = loadMoltbookAsymmetricKeys();

	if (authType === "asymmetric") {
		if (!publicKey) {
			return {
				ok: false,
				status: 500,
				error: "Internal auth misconfigured.",
				reason: `Asymmetric auth requested but ${MOLTBOOK_RPC_PUBLIC_KEY_ENV} not configured.`,
			};
		}
		if (verifyAsymmetric(publicKey, signature, input)) {
			nonceCache.set(nonce, now + DEFAULT_NONCE_TTL_MS);
			return { ok: true, scope: "moltbook" };
		}
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Invalid asymmetric signature.",
		};
	}

	// If public key is configured, reject non-asymmetric requests that would be moltbook scope
	// This prevents downgrade attacks where attacker uses symmetric auth
	if (publicKey) {
		const moltbookSecret = process.env[MOLTBOOK_RPC_SECRET_ENV];
		if (moltbookSecret) {
			// Check if this signature matches the moltbook symmetric secret
			const moltbookSig = computeSignature(moltbookSecret, input);
			if (signature === moltbookSig) {
				return {
					ok: false,
					status: 401,
					error: "Unauthorized.",
					reason: "Symmetric auth disabled for moltbook scope. Use asymmetric auth.",
				};
			}
		}
	}

	// Symmetric HMAC verification for non-moltbook scopes
	const secrets = loadInternalRpcSecrets();
	if (secrets.length === 0) {
		return {
			ok: false,
			status: 500,
			error: "Internal auth misconfigured.",
			reason: `Missing RPC secret. Set ${TELEGRAM_RPC_SECRET_ENV} or ${MOLTBOOK_RPC_SECRET_ENV}.`,
		};
	}

	const sigBuffer = Buffer.from(signature, "utf8");

	for (const { scope, secret } of secrets) {
		const expected = computeSignature(secret, input);
		const expectedBuffer = Buffer.from(expected, "utf8");
		if (sigBuffer.length !== expectedBuffer.length) {
			continue; // Try next secret instead of failing immediately
		}
		if (crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
			nonceCache.set(nonce, now + DEFAULT_NONCE_TTL_MS);
			return { ok: true, scope };
		}
	}

	return {
		ok: false,
		status: 401,
		error: "Unauthorized.",
		reason: "Invalid signature.",
	};
}
