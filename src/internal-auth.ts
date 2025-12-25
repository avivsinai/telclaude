import crypto from "node:crypto";
import type http from "node:http";

const HEADER_TIMESTAMP = "x-telclaude-timestamp";
const HEADER_NONCE = "x-telclaude-nonce";
const HEADER_SIGNATURE = "x-telclaude-signature";
const SIGNING_VERSION = "v1";

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

export type InternalAuthResult =
	| { ok: true }
	| { ok: false; status: number; error: string; reason: string };

function getInternalRpcSecret(): string {
	const secret = process.env.TELCLAUDE_INTERNAL_RPC_SECRET;
	if (!secret) {
		throw new Error("TELCLAUDE_INTERNAL_RPC_SECRET is not configured");
	}
	return secret;
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
): Record<string, string> {
	const secret = getInternalRpcSecret();
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
	let secret: string;
	try {
		secret = getInternalRpcSecret();
	} catch (err) {
		return {
			ok: false,
			status: 500,
			error: "Internal auth misconfigured.",
			reason: err instanceof Error ? err.message : "Missing internal auth secret.",
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
	const expected = computeSignature(secret, { timestamp, nonce, method, path, body });

	const sigBuffer = Buffer.from(signature, "utf8");
	const expectedBuffer = Buffer.from(expected, "utf8");
	if (sigBuffer.length !== expectedBuffer.length) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Signature length mismatch.",
		};
	}
	if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
		return {
			ok: false,
			status: 401,
			error: "Unauthorized.",
			reason: "Invalid signature.",
		};
	}

	nonceCache.set(nonce, now + DEFAULT_NONCE_TTL_MS);

	return { ok: true };
}
