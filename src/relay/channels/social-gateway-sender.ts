import type {
	SocialGatewayMedia,
	SocialGatewayPostRequest,
	SocialGatewayPostResult,
	SocialGatewaySender,
} from "./social-gateway-connector.js";

/**
 * Relay-side transport (injected sender) for the "social" channel.
 *
 * EXTERNAL CHANNEL — a PURE POSTER. The connector
 * (social-gateway-connector.ts) already enforces the public/private air gap,
 * takes the recipient from the edge-validated destination VERBATIM, and resolves
 * attachment bytes through the owner-bound resolver. This sender does exactly one
 * thing: it maps the typed `SocialGatewayPostRequest` to an HTTP POST against the
 * configured social-gateway host/path and maps the HTTP response back to the
 * typed `SocialGatewayPostResult`.
 *
 * Credential model (mirrors gmail-transport): the transport NEVER holds a raw
 * credential. Auth is entirely the relay's job — it wires `deps.post` to the
 * vault credential proxy (`http://relay:8792/{host}/{path}`), which injects the
 * gateway credential for `host`. This sender constructs only the URL parts and
 * the body; it carries no Bearer / token / api_key field.
 *
 * At-most-once boundary: once the POST is dispatched the post may have landed, so
 * NOTHING here signals a retryable success on ambiguity. A thrown poster error,
 * a non-2xx status, or an error body all map to the failure shape
 * (`{ error }`) — never to `{ postId }`.
 */

/**
 * Injected HTTP poster, wired by the relay to the credential proxy. The relay
 * points it at `http://relay:8792/{host}/{path}` so the vault injects the gateway
 * credential for `{host}`; this transport never sees the credential. It returns
 * the parsed status plus both a best-effort JSON body and the raw text.
 */
export type CredentialProxyPost = (req: {
	readonly host: string;
	readonly path: string;
	readonly method?: string;
	readonly body?: string;
	readonly headers?: Record<string, string>;
}) => Promise<{ readonly status: number; readonly json: unknown; readonly text: string }>;

export interface CreateSocialGatewaySenderOptions {
	/**
	 * Posts to the social gateway via the relay credential proxy. The relay wires
	 * this to the vault proxy that injects the gateway credential for `host`; the
	 * transport holds no credential of its own.
	 */
	readonly post: CredentialProxyPost;
	/** Configured social-gateway host (e.g. "gateway.social.internal"). */
	readonly host: string;
	/** Configured social-gateway POST path (e.g. "/v1/post"). */
	readonly path: string;
}

/** JSON-safe media: quarantine bytes are base64-encoded for the POST body. */
interface SocialGatewayMediaWire {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly sizeBytes: number;
	/** base64 of the released quarantine bytes. */
	readonly bytesBase64: string;
}

function encodeMedia(media: readonly SocialGatewayMedia[]): SocialGatewayMediaWire[] {
	return media.map((item) => ({
		quarantineId: item.quarantineId,
		mediaType: item.mediaType,
		contentHash: item.contentHash,
		sizeBytes: item.sizeBytes,
		bytesBase64: Buffer.from(item.bytes).toString("base64"),
	}));
}

/**
 * The gateway accepts `{ post_id }` or `{ id }` as the created post identifier.
 * Returns the first non-empty string id, else undefined.
 */
function extractPostId(json: unknown): string | undefined {
	if (!json || typeof json !== "object") return undefined;
	const body = json as { post_id?: unknown; id?: unknown };
	if (typeof body.post_id === "string" && body.post_id.length > 0) return body.post_id;
	if (typeof body.id === "string" && body.id.length > 0) return body.id;
	return undefined;
}

/**
 * The gateway reports a rejection via an `{ error }` (or `{ message }`) field.
 * Returns a human-readable reason for the failure shape.
 */
function extractError(json: unknown, fallback: string): string {
	if (json && typeof json === "object") {
		const body = json as { error?: unknown; message?: unknown };
		if (typeof body.error === "string" && body.error.length > 0) return body.error;
		if (typeof body.message === "string" && body.message.length > 0) return body.message;
	}
	return fallback;
}

export function createSocialGatewaySender(
	options: CreateSocialGatewaySenderOptions,
): SocialGatewaySender {
	const { post, host, path } = options;

	return async function send(request: SocialGatewayPostRequest): Promise<SocialGatewayPostResult> {
		// Brief: POST { target, targetKind, text, media } to the gateway. The edge
		// provenance fields (outboundRef, idempotencyKey, conversationId) are carried
		// for the gateway's OWN idempotency/dedupe — they are not credentials.
		const body = JSON.stringify({
			target: request.target,
			targetKind: request.targetKind,
			text: request.text,
			media: encodeMedia(request.media),
			outboundRef: request.outboundRef,
			idempotencyKey: request.idempotencyKey,
			...(request.conversationId ? { conversationId: request.conversationId } : {}),
		});

		// At-most-once: a thrown poster error is ambiguous (the POST may have landed),
		// so it maps to a failure — never to a success with a fabricated postId.
		let response: { readonly status: number; readonly json: unknown; readonly text: string };
		try {
			response = await post({
				host,
				path,
				method: "POST",
				body,
				headers: { "content-type": "application/json" },
			});
		} catch (error) {
			return { error: error instanceof Error ? error.message : String(error) };
		}

		// Map only a 2xx with an extractable id to a success postId. Any non-2xx, or a
		// 2xx without an id, fails closed (ambiguity must not read as success).
		if (response.status >= 200 && response.status < 300) {
			const postId = extractPostId(response.json);
			if (postId) return { postId };
			return {
				error: extractError(
					response.json,
					`social gateway returned ${response.status} without a post id`,
				),
			};
		}

		return {
			error: extractError(response.json, `social gateway returned status ${response.status}`),
		};
	};
}
