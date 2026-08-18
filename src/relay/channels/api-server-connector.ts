import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";

/**
 * Outbound connector for the INTERNAL "api-server" channel: a response queue
 * for an API caller. Pure delivery sink invoked by the dispatcher AFTER
 * authorization — it never resolves approvals, touches the side-effect ledger,
 * the conversation store, or the pairing store.
 *
 * Trust model:
 * - The response target comes from the edge-validated, membership-bound
 *   `prepared.resolvedDestination` VERBATIM. Only `address` (the API caller's
 *   response address) and `actor` (the bound caller actor) are deliverable;
 *   a `thread` destination has no api-server response sink and fails closed.
 *   The connector NEVER re-derives the recipient from the body or conversation
 *   members.
 * - There are NO external credentials. Enqueueing goes through an INJECTED
 *   `send` sink (the relay wires it to the api-server outbound response queue),
 *   mirroring gmail-transport's `callProvider` injection. The connector builds
 *   a typed request, calls the sink, and maps the typed result to a
 *   ChannelSendOutcome.
 * - Attachment bytes are released only through the owner-bound resolver from
 *   the context, scoped to the prepared outbound's conversation. A declared
 *   attachment that does not resolve fails closed; raw bytes/paths are never
 *   read from the model.
 * - Inbound stays dark until CL-1: `startListener` throws.
 */

export const API_SERVER_CHANNEL = "api-server" as const;
export const API_SERVER_INBOUND_RISK_WRAP_REQUIRED =
	"api-server inbound listener requires CL-1 risk wrapping before edge.ingest";

/** One attachment carried into the response queue (owner-bound, byte-released). */
export interface ApiServerOutboundAttachment {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly sizeBytes: number;
	readonly bytesBase64: string;
}

/**
 * The typed enqueue request handed to the injected sender. The destination is
 * the verbatim API caller / response target; `conversationId` is carried so the
 * response queue can correlate the reply with the originating API call.
 */
export interface ApiServerOutboundRequest {
	readonly outboundRef: string;
	readonly conversationId: string;
	readonly text: string;
	readonly attachments: readonly ApiServerOutboundAttachment[];
}

/** Result the injected sender returns after enqueueing the response. */
export interface ApiServerSendResult {
	readonly ok: boolean;
	readonly deliveryId?: string;
}

/** Injected enqueue sink. The relay wires this to the api-server response queue. */
export type ApiServerSender = (request: ApiServerOutboundRequest) => Promise<ApiServerSendResult>;

export interface CreateApiServerConnectorOptions {
	/** Enqueues the response onto the api-server outbound queue. No raw creds here. */
	readonly send: ApiServerSender;
}

/**
 * Resolves the response target from the edge destination VERBATIM. The
 * api-server sink addresses an individual API caller, so only `address`
 * (the caller's response address) and `actor` (the bound caller actor) are
 * deliverable. A `thread` destination, or a missing destination field, fails
 * closed (non-retryable).
 */
function resolveResponseTarget(
	destination: OutboundDeliveryContext["prepared"]["resolvedDestination"],
): { readonly ok: true; readonly target: string } | Extract<ChannelSendOutcome, { ok: false }> {
	if (destination.kind === "address") {
		const target = destination.addressRef?.trim();
		if (!target) {
			return {
				ok: false,
				code: "api_server_missing_destination",
				reason: "api-server address destination has no addressRef",
				retryable: false,
			};
		}
		return { ok: true, target };
	}
	if (destination.kind === "actor") {
		const target = destination.actorId?.trim();
		if (!target) {
			return {
				ok: false,
				code: "api_server_missing_destination",
				reason: "api-server actor destination has no actorId",
				retryable: false,
			};
		}
		return { ok: true, target };
	}
	return {
		ok: false,
		code: "api_server_unsupported_destination",
		reason: `api-server cannot deliver to a ${destination.kind} destination`,
		retryable: false,
	};
}

export function createApiServerConnector(
	options: CreateApiServerConnectorOptions,
): EdgeChannelConnector {
	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, resolveAttachment } = context;
		const destination = prepared.resolvedDestination;

		// Build the response target from the edge destination VERBATIM — never
		// re-derive it from the body or conversation members.
		const resolvedTarget = resolveResponseTarget(destination);
		if (!resolvedTarget.ok) return resolvedTarget;

		// The conversationId correlates the response with the API call. It is part
		// of the edge-validated destination; fail closed if it is absent.
		const conversationId = destination.conversationId?.trim();
		if (!conversationId) {
			return {
				ok: false,
				code: "api_server_missing_conversation",
				reason: "api-server destination has no conversationId to correlate the response",
				retryable: false,
			};
		}

		// Attachments only via the owner-bound resolver, scoped to prepared.mediaRefs.
		// A declared attachment that does not resolve fails closed.
		const attachments: ApiServerOutboundAttachment[] = [];
		for (const ref of prepared.mediaRefs) {
			const resolved = await resolveAttachment(ref.quarantineId);
			if (!resolved) {
				return {
					ok: false,
					code: "attachment_missing",
					reason: `attachment ${ref.quarantineId} is not resolvable for this conversation`,
					retryable: false,
				};
			}
			attachments.push({
				quarantineId: resolved.quarantineId,
				mediaType: resolved.mediaType,
				contentHash: resolved.contentHash,
				sizeBytes: resolved.bytes.byteLength,
				bytesBase64: Buffer.from(resolved.bytes).toString("base64"),
			});
		}

		const request: ApiServerOutboundRequest = {
			outboundRef: prepared.outboundRef,
			conversationId,
			text: prepared.finalRenderedBody,
			attachments,
		};

		// At-most-once delivery boundary. Once the enqueue is dispatched we cannot
		// know whether the response queue accepted it, so a thrown sender error or
		// a non-ok result is NON-retryable: a retry could double-enqueue a response
		// the queue already accepted on the first attempt (no sink-side dedupe).
		let result: ApiServerSendResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "api_server_enqueue_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (!result.ok) {
			return {
				ok: false,
				code: "api_server_enqueue_rejected",
				reason: "api-server response queue rejected the enqueue",
				retryable: false,
			};
		}

		const deliveryId = result.deliveryId?.trim();
		return {
			ok: true,
			...(deliveryId ? { platformMessageId: deliveryId } : {}),
		};
	}

	async function startListener(): Promise<never> {
		throw new Error(API_SERVER_INBOUND_RISK_WRAP_REQUIRED);
	}

	return { channel: API_SERVER_CHANNEL, send, startListener };
}
