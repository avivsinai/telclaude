import crypto from "node:crypto";
import type http from "node:http";

const HEADER_TIMESTAMP = "x-telclaude-timestamp";
const HEADER_NONCE = "x-telclaude-nonce";
const HEADER_SIGNATURE = "x-telclaude-signature";
const SIGNING_VERSION = "v1";

const TELEGRAM_RPC_SECRET_ENV = "TELEGRAM_RPC_SECRET";
const MOLTBOOK_RPC_SECRET_ENV = "MOLTBOOK_RPC_SECRET";
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
	const { secret } = resolveInternalRpcSecret(options);
	const timestamp = Date.now().toString();
	const nonce = crypto.randomBytes(16).toString("hex");
	const signature = computeSignature(secret, { timestamp, nonce, method, path, body });

	return {
		"X-Telclaude-Timestamp": timestamp,
		"X-Telclaude-Nonce": nonce,
		"X-Telclaude-Signature": signature,
	};
}

export function verifyInternalAuth(req: http.IncomingMessage, body: string): InternalAuthResult {
	const secrets = loadInternalRpcSecrets();
	if (secrets.length === 0) {
		return {
			ok: false,
			status: 500,
			error: "Internal auth misconfigured.",
			reason: `Missing RPC secret. Set ${TELEGRAM_RPC_SECRET_ENV} or ${MOLTBOOK_RPC_SECRET_ENV}.`,
		};
	}

	const timestamp = getHeader(req, HEADER_TIMESTAMP);
	const nonce = getHeader(req, HEADER_NONCE);
	const signature = getHeader(req, HEADER_SIGNATURE);

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
	const sigBuffer = Buffer.from(signature, "utf8");

	for (const { scope, secret } of secrets) {
		const expected = computeSignature(secret, { timestamp, nonce, method, path, body });
		const expectedBuffer = Buffer.from(expected, "utf8");
		if (sigBuffer.length !== expectedBuffer.length) {
			return {
				ok: false,
				status: 401,
				error: "Unauthorized.",
				reason: "Signature length mismatch.",
			};
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
