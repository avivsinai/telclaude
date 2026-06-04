import { createHash, randomBytes } from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { QUARANTINE_MAX_BYTES } from "./attachment-quarantine-store.js";
import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "./edge-channel-connector.js";

export const WHATSAPP_SIDECAR_SEND_SCHEMA_VERSION = "telclaude.edge.whatsapp.send.v1";
export const WHATSAPP_SIDECAR_MAX_MEDIA_BYTES = QUARANTINE_MAX_BYTES;
export const WHATSAPP_INBOUND_RISK_WRAP_REQUIRED =
	"WhatsApp inbound listener requires CL-1 risk wrapping before edge.ingest";
export const TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV = "TELCLAUDE_WHATSAPP_SIDECAR_URL";
export const WHATSAPP_SIDECAR_ALLOWED_HOST = "whatsapp-bridge";
export const WHATSAPP_SIDECAR_SESSION_KEY_HEADER = "x-telclaude-whatsapp-session-key";
export const WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER = "x-telclaude-whatsapp-request-digest";
export const WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER = "x-telclaude-whatsapp-session-expires-at";
export const DEFAULT_WHATSAPP_BRIDGE_SESSION_TTL_MS = 60_000;

export type WhatsAppSidecarAttachment = {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly sizeBytes: number;
	readonly bytesBase64: string;
};

export type WhatsAppSidecarSendRequest = {
	readonly schemaVersion: typeof WHATSAPP_SIDECAR_SEND_SCHEMA_VERSION;
	readonly outboundRef: string;
	readonly idempotencyKey: string;
	readonly destination: OutboundDeliveryContext["prepared"]["resolvedDestination"];
	readonly body: string;
	readonly threadMessageIds: readonly string[];
	readonly attachments: readonly WhatsAppSidecarAttachment[];
};

export type WhatsAppSidecarSendResponse =
	| {
			readonly ok: true;
			readonly platformMessageId?: string;
			readonly observedThreadMessageId?: string;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason?: string;
			readonly retryable?: boolean;
	  };

export type WhatsAppBridgeSessionMaterial = {
	readonly sessionKey: string;
	readonly requestDigest: string;
	readonly expiresAtMs: number;
};

export type WhatsAppSidecarSender = (
	request: WhatsAppSidecarSendRequest,
	session: WhatsAppBridgeSessionMaterial,
) => Promise<WhatsAppSidecarSendResponse>;

export type WhatsAppBridgeSessionFactory = (
	request: WhatsAppSidecarSendRequest,
) => Promise<WhatsAppBridgeSessionMaterial>;

type FetchLike = (
	url: URL,
	init: {
		readonly method: "POST";
		readonly headers: Record<string, string>;
		readonly body: string;
	},
) => Promise<{
	readonly ok: boolean;
	readonly status: number;
	json(): Promise<unknown>;
	text(): Promise<string>;
}>;

export type WhatsAppEdgeChannelConnectorOptions = {
	readonly sidecarUrl?: string;
	readonly bridgeSessionFactory?: WhatsAppBridgeSessionFactory;
	readonly sendToSidecar?: WhatsAppSidecarSender;
	readonly fetch?: FetchLike;
	readonly now?: () => number;
};

export function createWhatsAppEdgeChannelConnector(
	options: WhatsAppEdgeChannelConnectorOptions = {},
): EdgeChannelConnector {
	const sidecarUrl = normalizeOptionalUrl(options.sidecarUrl);
	const fetchImpl = options.fetch ?? globalFetch();
	const bridgeSessionFactory =
		options.bridgeSessionFactory ??
		((request) =>
			Promise.resolve(createWhatsAppBridgeSessionMaterial(request, { now: options.now })));

	return {
		channel: "whatsapp",
		async send(context) {
			const request = await buildWhatsAppSidecarSendRequest(context);
			if (!request.ok) return request;

			if (options.sendToSidecar) {
				const session = await createBoundWhatsAppBridgeSession(
					bridgeSessionFactory,
					request.request,
				);
				if (!session.ok) return session;
				return mapSidecarResponse(await options.sendToSidecar(request.request, session.session));
			}
			if (!sidecarUrl.ok) {
				return {
					ok: false,
					code: sidecarUrl.code,
					reason: sidecarUrl.reason,
					retryable: false,
				};
			}
			if (!fetchImpl) {
				return {
					ok: false,
					code: "whatsapp_sidecar_fetch_unavailable",
					reason: "global fetch is not available for WhatsApp sidecar delivery",
					retryable: false,
				};
			}
			const session = await createBoundWhatsAppBridgeSession(bridgeSessionFactory, request.request);
			if (!session.ok) return session;
			return sendViaHttpSidecar(fetchImpl, sidecarUrl.url, session.session, request.request);
		},
		async startListener() {
			throw new Error(WHATSAPP_INBOUND_RISK_WRAP_REQUIRED);
		},
	};
}

export function whatsappSidecarOptionsFromEnv(
	env: Partial<Record<typeof TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV, string | undefined>> = process.env,
): WhatsAppEdgeChannelConnectorOptions {
	const sidecarUrl = env[TELCLAUDE_WHATSAPP_SIDECAR_URL_ENV]?.trim();
	return sidecarUrl ? { sidecarUrl } : {};
}

async function buildWhatsAppSidecarSendRequest(context: OutboundDeliveryContext): Promise<
	| {
			readonly ok: true;
			readonly request: WhatsAppSidecarSendRequest;
	  }
	| Extract<ChannelSendOutcome, { ok: false }>
> {
	const attachments: WhatsAppSidecarAttachment[] = [];
	let totalMediaBytes = 0;
	for (const mediaRef of context.prepared.mediaRefs) {
		const released = await context.resolveAttachment(mediaRef.quarantineId);
		if (!released) {
			return {
				ok: false,
				code: "attachment_missing",
				reason: `prepared attachment is unavailable: ${mediaRef.quarantineId}`,
				retryable: false,
			};
		}
		totalMediaBytes += released.bytes.byteLength;
		if (
			released.bytes.byteLength > WHATSAPP_SIDECAR_MAX_MEDIA_BYTES ||
			totalMediaBytes > WHATSAPP_SIDECAR_MAX_MEDIA_BYTES
		) {
			return {
				ok: false,
				code: "whatsapp_media_too_large",
				reason: `WhatsApp sidecar media exceeds cap ${WHATSAPP_SIDECAR_MAX_MEDIA_BYTES}`,
				retryable: false,
			};
		}
		attachments.push({
			quarantineId: released.quarantineId,
			mediaType: released.mediaType,
			contentHash: released.contentHash,
			sizeBytes: released.bytes.byteLength,
			bytesBase64: Buffer.from(released.bytes).toString("base64"),
		});
	}

	return {
		ok: true,
		request: {
			schemaVersion: WHATSAPP_SIDECAR_SEND_SCHEMA_VERSION,
			outboundRef: context.prepared.outboundRef,
			idempotencyKey: context.prepared.idempotencyKey,
			destination: context.prepared.resolvedDestination,
			body: context.prepared.finalRenderedBody,
			threadMessageIds: context.threadMessageIds,
			attachments,
		},
	};
}

async function sendViaHttpSidecar(
	fetchImpl: FetchLike,
	sidecarUrl: URL,
	session: WhatsAppBridgeSessionMaterial,
	request: WhatsAppSidecarSendRequest,
): Promise<ChannelSendOutcome> {
	const checkedSession = validateWhatsAppBridgeSessionMaterial(session, request);
	if (!checkedSession.ok) return checkedSession;
	let response: Awaited<ReturnType<FetchLike>>;
	try {
		response = await fetchImpl(sidecarUrl, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
				"x-relay-proxy": "true",
				[WHATSAPP_SIDECAR_SESSION_KEY_HEADER]: checkedSession.session.sessionKey,
				[WHATSAPP_SIDECAR_REQUEST_DIGEST_HEADER]: checkedSession.session.requestDigest,
				[WHATSAPP_SIDECAR_SESSION_EXPIRES_AT_HEADER]: new Date(session.expiresAtMs).toISOString(),
			},
			body: JSON.stringify(request),
		});
	} catch (error) {
		return {
			ok: false,
			code: "whatsapp_sidecar_unavailable",
			reason: errorMessage(error),
			retryable: true,
		};
	}
	if (!response.ok) {
		return {
			ok: false,
			code: "whatsapp_sidecar_http_error",
			reason: `WhatsApp sidecar returned HTTP ${response.status}`,
			retryable: response.status >= 500,
		};
	}
	let payload: unknown;
	try {
		payload = await response.json();
	} catch {
		return {
			ok: false,
			code: "whatsapp_sidecar_invalid_response",
			reason: "WhatsApp sidecar returned non-JSON response",
			retryable: false,
		};
	}
	return mapSidecarResponse(parseSidecarResponse(payload));
}

function mapSidecarResponse(response: WhatsAppSidecarSendResponse): ChannelSendOutcome {
	if (!response.ok) {
		return {
			ok: false,
			code: response.code,
			...(response.reason ? { reason: response.reason } : {}),
			retryable: response.retryable ?? false,
		};
	}
	return {
		ok: true,
		...(response.platformMessageId ? { platformMessageId: response.platformMessageId } : {}),
		...(response.observedThreadMessageId
			? { observedThreadMessageId: response.observedThreadMessageId }
			: {}),
	};
}

function parseSidecarResponse(payload: unknown): WhatsAppSidecarSendResponse {
	if (!isRecord(payload)) {
		return {
			ok: false,
			code: "whatsapp_sidecar_invalid_response",
			reason: "WhatsApp sidecar response is not an object",
			retryable: false,
		};
	}
	if (payload.ok === true || payload.status === "ok") {
		const data = isRecord(payload.data) ? payload.data : payload;
		return {
			ok: true,
			...(typeof data.platformMessageId === "string"
				? { platformMessageId: data.platformMessageId }
				: {}),
			...(typeof data.observedThreadMessageId === "string"
				? { observedThreadMessageId: data.observedThreadMessageId }
				: {}),
		};
	}
	return {
		ok: false,
		code: typeof payload.code === "string" ? payload.code : "whatsapp_sidecar_rejected",
		...(typeof payload.reason === "string"
			? { reason: payload.reason }
			: typeof payload.error === "string"
				? { reason: payload.error }
				: {}),
		retryable: payload.retryable === true,
	};
}

function normalizeOptionalUrl(value: string | undefined):
	| {
			readonly ok: true;
			readonly url: URL;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
	  } {
	const trimmed = value?.trim();
	if (!trimmed) {
		return {
			ok: false,
			code: "whatsapp_sidecar_unconfigured",
			reason: "WhatsApp sidecar URL is not configured",
		};
	}
	let base: URL;
	try {
		base = new URL(trimmed);
	} catch {
		return {
			ok: false,
			code: "whatsapp_sidecar_config_invalid",
			reason: "WhatsApp sidecar URL is invalid",
		};
	}
	if (base.protocol !== "http:" && base.protocol !== "https:") {
		return {
			ok: false,
			code: "whatsapp_sidecar_config_invalid",
			reason: "WhatsApp sidecar URL must be http or https",
		};
	}
	if (base.hostname !== WHATSAPP_SIDECAR_ALLOWED_HOST) {
		return {
			ok: false,
			code: "whatsapp_sidecar_config_invalid",
			reason: `WhatsApp sidecar host must be ${WHATSAPP_SIDECAR_ALLOWED_HOST}`,
		};
	}
	return { ok: true, url: new URL("/v1/whatsapp/send", base) };
}

export function createWhatsAppBridgeSessionMaterial(
	request: WhatsAppSidecarSendRequest,
	options: { readonly now?: () => number } = {},
): WhatsAppBridgeSessionMaterial {
	const now = options.now?.() ?? Date.now();
	return {
		sessionKey: `wa-session:${randomBytes(32).toString("base64url")}`,
		requestDigest: digestWhatsAppSidecarSendRequest(request),
		expiresAtMs: now + DEFAULT_WHATSAPP_BRIDGE_SESSION_TTL_MS,
	};
}

export function digestWhatsAppSidecarSendRequest(request: WhatsAppSidecarSendRequest): string {
	const canonical = JSON.stringify(sortKeysDeep(request));
	const digest = createHash("sha256").update(canonical).digest("hex");
	return `sha256:${digest}`;
}

async function createBoundWhatsAppBridgeSession(
	factory: WhatsAppBridgeSessionFactory,
	request: WhatsAppSidecarSendRequest,
): Promise<
	| {
			readonly ok: true;
			readonly session: WhatsAppBridgeSessionMaterial;
	  }
	| Extract<ChannelSendOutcome, { ok: false }>
> {
	return validateWhatsAppBridgeSessionMaterial(await factory(request), request);
}

function validateWhatsAppBridgeSessionMaterial(
	session: WhatsAppBridgeSessionMaterial,
	request: WhatsAppSidecarSendRequest,
):
	| {
			readonly ok: true;
			readonly session: WhatsAppBridgeSessionMaterial;
	  }
	| Extract<ChannelSendOutcome, { ok: false }> {
	const sessionKey = session.sessionKey.trim();
	if (!sessionKey) {
		return {
			ok: false,
			code: "whatsapp_bridge_session_invalid",
			reason: "WhatsApp bridge session key is empty",
			retryable: false,
		};
	}
	const expectedDigest = digestWhatsAppSidecarSendRequest(request);
	if (session.requestDigest !== expectedDigest) {
		return {
			ok: false,
			code: "whatsapp_bridge_session_digest_mismatch",
			reason: "WhatsApp bridge session is not bound to the sidecar request digest",
			retryable: false,
		};
	}
	if (!Number.isFinite(session.expiresAtMs) || session.expiresAtMs <= 0) {
		return {
			ok: false,
			code: "whatsapp_bridge_session_invalid",
			reason: "WhatsApp bridge session expiry is invalid",
			retryable: false,
		};
	}
	return { ok: true, session: { ...session, sessionKey } };
}

function globalFetch(): FetchLike | undefined {
	return typeof fetch === "function" ? (fetch as FetchLike) : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}
