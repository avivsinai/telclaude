import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	createWhatsAppBridgeAuthToken,
	WHATSAPP_SIDECAR_AUTH_HEADER,
	WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER,
	WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER,
	WHATSAPP_SIDECAR_SESSION_KEY_HEADER,
} from "../relay/whatsapp-edge-channel-connector.js";

export const WHATSAPP_BRIDGE_SEND_PATH = "/v1/whatsapp/send";
export const WHATSAPP_BRIDGE_HEALTH_PATH = "/health";
export const WHATSAPP_BRIDGE_STATUS_PATH = "/v1/status";
export const WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION = "telclaude.edge.whatsapp.inbound.v1";
export const WHATSAPP_INBOUND_SIGNATURE_HEADER = "x-telclaude-whatsapp-inbound-signature";

export type WhatsAppBridgeHeaders = {
	readonly [WHATSAPP_SIDECAR_AUTH_HEADER]?: string | readonly string[];
	readonly [WHATSAPP_SIDECAR_SESSION_KEY_HEADER]?: string | readonly string[];
	readonly [WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER]?: string | readonly string[];
	readonly [WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER]?: string | readonly string[];
};

export type WhatsAppBridgeAttachment = {
	readonly mediaType: string;
	readonly bytesBase64: string;
	readonly sizeBytes?: number;
	readonly quarantineId?: string;
};

export type WhatsAppBridgeSendRequest = {
	readonly schemaVersion: string;
	readonly outboundRef: string;
	readonly idempotencyKey: string;
	readonly destination: {
		readonly kind: string;
		readonly addressRef?: string;
	};
	readonly body: string;
	readonly attachments?: readonly WhatsAppBridgeAttachment[];
};

export type WhatsAppInboundBridgeEvent = {
	readonly schemaVersion: typeof WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION;
	readonly eventId: string;
	readonly messageId: string;
	readonly cursorSequence: number;
	readonly chatKind: "direct" | "group";
	readonly senderAddressRef: string;
	readonly conversationKey: string;
	readonly text?: string;
	readonly attachments: readonly {
		readonly mediaType: string;
		readonly bytesBase64: string;
		readonly scanState?: "pending" | "clean" | "blocked" | "failed";
	}[];
	readonly receivedAtMs: number;
};

export type WhatsAppBridgeValidationResult =
	| { readonly ok: true; readonly sessionKey: string }
	| { readonly ok: false; readonly status: number; readonly code: string; readonly reason: string };

export function digestWhatsAppBridgeSendRequest(request: unknown): `sha256:${string}` {
	const canonical = JSON.stringify(sortKeysDeep(request));
	const digest = crypto.createHash("sha256").update(canonical).digest("hex");
	return `sha256:${digest}`;
}

export function signWhatsAppInboundBridgeEvent(event: unknown, secret: string): `sha256:${string}` {
	const digest = crypto
		.createHmac("sha256", secret)
		.update(JSON.stringify(sortKeysDeep(event)))
		.digest("hex");
	return `sha256:${digest}`;
}

export function whatsappInboundBridgeBody(event: WhatsAppInboundBridgeEvent): string {
	return JSON.stringify({ event });
}

export function validateWhatsAppBridgeSend(
	request: unknown,
	headers: WhatsAppBridgeHeaders,
	bridgeSecret: string,
	nowMs: number = Date.now(),
): WhatsAppBridgeValidationResult {
	const secret = bridgeSecret.trim();
	if (!secret) {
		return failure(
			503,
			"whatsapp_bridge_secret_unconfigured",
			"Bridge shared secret is not configured.",
		);
	}
	const sessionKey = firstHeader(headers[WHATSAPP_SIDECAR_SESSION_KEY_HEADER])?.trim();
	if (!sessionKey) {
		return failure(401, "whatsapp_bridge_session_missing", "Missing bridge session key.");
	}

	const digest = firstHeader(headers[WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER])?.trim();
	if (!digest) {
		return failure(401, "whatsapp_bridge_digest_missing", "Missing request digest.");
	}
	const expected = digestWhatsAppBridgeSendRequest(request);
	if (!timingSafeEqualText(digest, expected)) {
		return failure(401, "whatsapp_bridge_digest_mismatch", "Request digest mismatch.");
	}

	const expiresAt = firstHeader(headers[WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER])?.trim();
	if (!expiresAt) {
		return failure(401, "whatsapp_bridge_session_expiry_missing", "Missing session expiry.");
	}
	const expiresAtMs = Date.parse(expiresAt);
	if (!Number.isFinite(expiresAtMs)) {
		return failure(401, "whatsapp_bridge_session_expiry_invalid", "Invalid session expiry.");
	}
	if (expiresAtMs <= nowMs) {
		return failure(401, "whatsapp_bridge_session_expired", "Bridge session expired.");
	}
	const auth = firstHeader(headers[WHATSAPP_SIDECAR_AUTH_HEADER])?.trim();
	if (!auth) {
		return failure(401, "whatsapp_bridge_auth_missing", "Missing bridge auth token.");
	}
	const expectedAuth = createWhatsAppBridgeAuthToken({
		secret,
		sessionKey,
		requestDigest: digest,
		expiresAt,
	});
	if (!timingSafeEqualText(auth, expectedAuth)) {
		return failure(401, "whatsapp_bridge_auth_mismatch", "Bridge auth token mismatch.");
	}

	return { ok: true, sessionKey };
}

export function parseWhatsAppDestinationJid(
	request: WhatsAppBridgeSendRequest,
):
	| { readonly ok: true; readonly jid: string }
	| { readonly ok: false; readonly code: string; readonly reason: string } {
	if (request.destination.kind !== "address" || !request.destination.addressRef) {
		return {
			ok: false,
			code: "whatsapp_destination_invalid",
			reason: "WhatsApp bridge requires destination.kind=address and destination.addressRef.",
		};
	}
	const addressRef = normalizeWhatsAppAddressRef(request.destination.addressRef);
	if (!addressRef) {
		return {
			ok: false,
			code: "whatsapp_destination_invalid",
			reason: "WhatsApp destination must be an E.164 number with optional whatsapp: prefix.",
		};
	}
	const digits = addressRef.slice("whatsapp:+".length);
	return { ok: true, jid: `${digits}@s.whatsapp.net` };
}

export function jidToWhatsAppAddressRef(jid: string): string | null {
	const bare = jid.split(":")[0]?.split("@")[0];
	if (!bare || !/^[1-9]\d{6,14}$/.test(bare)) return null;
	return `whatsapp:+${bare}`;
}

export function normalizeWhatsAppAddressRef(value: string): string | null {
	const trimmed = value.trim();
	const e164 = trimmed.startsWith("whatsapp:") ? trimmed.slice("whatsapp:".length) : trimmed;
	if (!/^\+[1-9]\d{6,14}$/.test(e164)) return null;
	return `whatsapp:${e164}`;
}

export function isWhatsAppGroupJid(jid: string): boolean {
	return jid.endsWith("@g.us");
}

function firstHeader(value: string | readonly string[] | undefined): string | undefined {
	if (typeof value === "string") return value;
	return value?.[0];
}

function timingSafeEqualText(left: string, right: string): boolean {
	const leftBuffer = Buffer.from(left);
	const rightBuffer = Buffer.from(right);
	if (leftBuffer.byteLength !== rightBuffer.byteLength) return false;
	return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function failure(
	status: number,
	code: string,
	reason: string,
): Extract<WhatsAppBridgeValidationResult, { ok: false }> {
	return { ok: false, status, code, reason };
}
