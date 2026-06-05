import type {
	ApiServerOutboundRequest,
	ApiServerSender,
	ApiServerSendResult,
} from "./api-server-connector.js";

/**
 * Relay-side transport (injected sender) for the INTERNAL "api-server" channel.
 *
 * api-server is an INTERNAL sink: the response is enqueued onto the relay's
 * api-server outbound response queue. There is NO external platform and NO
 * external credential — nothing here holds a token, bearer, or api key, and
 * there is no credential proxy. Auth/transport is entirely the relay's concern;
 * the relay wires `deps.enqueue` to the in-process outbound queue.
 *
 * This mirrors gmail-transport's injected-call shape (an injected sink rather
 * than a transport that holds creds), but for an internal channel the injected
 * call is a queue enqueue, not a credential-proxy POST.
 *
 * Responsibilities:
 * - Adapt the connector's `ApiServerOutboundRequest` to the injected enqueue
 *   sink VERBATIM. The connector already resolved the destination, correlated
 *   the conversation, and released attachment bytes through the owner-bound
 *   resolver; this transport does not re-derive or re-resolve anything.
 * - Map the enqueue outcome to the connector's `ApiServerSendResult`.
 * - Fail closed if `deps.enqueue` is absent (no sink configured) and on any
 *   thrown or rejected enqueue. At-most-once: a thrown/rejected enqueue is
 *   ambiguous (the queue may already hold the response), so it is surfaced as a
 *   failure — never as a retryable success.
 */

/** One attachment carried into the response queue (already owner-bound by the connector). */
export interface ApiServerEnqueueAttachment {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly sizeBytes: number;
	readonly bytesBase64: string;
}

/**
 * The payload handed to the injected enqueue sink. This is the connector's
 * `ApiServerOutboundRequest` forwarded verbatim — the transport adds nothing
 * and reads nothing from the model.
 */
export interface ApiServerEnqueueRequest {
	readonly outboundRef: string;
	readonly conversationId: string;
	readonly text: string;
	readonly attachments: readonly ApiServerEnqueueAttachment[];
}

/**
 * Outcome the injected enqueue sink returns. `accepted: true` means the queue
 * took ownership of the response; `deliveryId` is the queue's correlation
 * handle (optional). `accepted: false` means the queue refused it.
 */
export type ApiServerEnqueueOutcome =
	| { readonly accepted: true; readonly deliveryId?: string }
	| { readonly accepted: false };

/**
 * Injected internal-sink function. The relay wires this to the api-server
 * outbound response queue. No external creds, no proxy. Optional so the
 * transport can fail closed when no sink is configured.
 */
export type ApiServerEnqueue = (
	request: ApiServerEnqueueRequest,
) => Promise<ApiServerEnqueueOutcome>;

export interface CreateApiServerSenderDeps {
	/** Enqueues the response onto the api-server outbound queue. Absent => fail closed. */
	readonly enqueue?: ApiServerEnqueue;
}

const FAILURE: ApiServerSendResult = { ok: false };

function toEnqueueRequest(request: ApiServerOutboundRequest): ApiServerEnqueueRequest {
	return {
		outboundRef: request.outboundRef,
		conversationId: request.conversationId,
		text: request.text,
		attachments: request.attachments.map((attachment) => ({
			quarantineId: attachment.quarantineId,
			mediaType: attachment.mediaType,
			contentHash: attachment.contentHash,
			sizeBytes: attachment.sizeBytes,
			bytesBase64: attachment.bytesBase64,
		})),
	};
}

/**
 * Builds the api-server `ApiServerSender` the connector plugs into via
 * `options.send`. Returns a function assignable to `ApiServerSender`.
 */
export function createApiServerSender(deps: CreateApiServerSenderDeps): ApiServerSender {
	return async function send(request: ApiServerOutboundRequest): Promise<ApiServerSendResult> {
		// Fail closed when no internal sink is wired. The connector maps a
		// non-ok result to a non-retryable failure, so nothing is double-sent.
		const enqueue = deps.enqueue;
		if (!enqueue) return FAILURE;

		// At-most-once boundary. Once the enqueue is dispatched we cannot know
		// whether the queue accepted the response, so a thrown/rejected enqueue
		// is reported as a failure — never as a retryable success.
		let outcome: ApiServerEnqueueOutcome;
		try {
			outcome = await enqueue(toEnqueueRequest(request));
		} catch {
			return FAILURE;
		}

		if (!outcome.accepted) return FAILURE;

		const deliveryId = outcome.deliveryId?.trim();
		return { ok: true, ...(deliveryId ? { deliveryId } : {}) };
	};
}
