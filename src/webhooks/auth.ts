import crypto from "node:crypto";
import { safeEqual } from "../security/safe-equal.js";

export const WEBHOOK_SIGNATURE_HEADER = "x-telclaude-webhook-signature";
export const WEBHOOK_SIGNATURE_MAX_SKEW_SECONDS = 5 * 60;

export type WebhookSignatureVerification = {
	ok: boolean;
	signatureValid: boolean;
	timestampDeltaSeconds?: number;
	failureReason?: string;
};

type ParsedSignatureHeader = {
	timestamp: number;
	signatureHex: string;
};

export function assertWebhookSecret(secret: string): void {
	if (Buffer.byteLength(secret, "utf8") < 32) {
		throw new Error("webhook HMAC secret must be at least 32 bytes");
	}
}

export function createWebhookSignatureHeader(params: {
	secret: string;
	rawBody: Buffer;
	timestampSeconds?: number;
}): string {
	assertWebhookSecret(params.secret);
	const timestamp = params.timestampSeconds ?? Math.floor(Date.now() / 1000);
	const signature = crypto
		.createHmac("sha256", params.secret)
		.update(String(timestamp))
		.update(".")
		.update(params.rawBody)
		.digest("hex");
	return `t=${timestamp},v1=${signature}`;
}

function parseSignatureHeader(value: string | string[] | undefined): ParsedSignatureHeader | null {
	const raw = Array.isArray(value) ? value[0] : value;
	if (!raw) return null;

	const parts = new Map<string, string>();
	for (const part of raw.split(",")) {
		const eq = part.indexOf("=");
		if (eq <= 0) continue;
		parts.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
	}

	const timestampRaw = parts.get("t");
	const signatureHex = parts.get("v1");
	if (!timestampRaw || !signatureHex) return null;
	if (!/^\d+$/.test(timestampRaw)) return null;
	if (!/^[a-fA-F0-9]{64}$/.test(signatureHex)) return null;

	return {
		timestamp: Number.parseInt(timestampRaw, 10),
		signatureHex: signatureHex.toLowerCase(),
	};
}

export function verifyWebhookSignature(params: {
	header: string | string[] | undefined;
	secret: string;
	rawBody: Buffer;
	nowMs?: number;
	maxSkewSeconds?: number;
}): WebhookSignatureVerification {
	const parsed = parseSignatureHeader(params.header);
	if (!parsed) {
		return {
			ok: false,
			signatureValid: false,
			failureReason: "invalid_signature_header",
		};
	}

	assertWebhookSecret(params.secret);

	const nowSeconds = Math.floor((params.nowMs ?? Date.now()) / 1000);
	const timestampDeltaSeconds = Math.abs(nowSeconds - parsed.timestamp);
	const expected = createWebhookSignatureHeader({
		secret: params.secret,
		rawBody: params.rawBody,
		timestampSeconds: parsed.timestamp,
	}).split("v1=")[1];
	const signatureValid = safeEqual(expected, parsed.signatureHex);
	if (!signatureValid) {
		return {
			ok: false,
			signatureValid: false,
			timestampDeltaSeconds,
			failureReason: "signature_mismatch",
		};
	}

	if (timestampDeltaSeconds > (params.maxSkewSeconds ?? WEBHOOK_SIGNATURE_MAX_SKEW_SECONDS)) {
		return {
			ok: false,
			signatureValid: true,
			timestampDeltaSeconds,
			failureReason: "timestamp_out_of_range",
		};
	}

	return {
		ok: true,
		signatureValid: true,
		timestampDeltaSeconds,
	};
}
