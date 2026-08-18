import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	InboundSink,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";

/**
 * Outbound connector for the generic operator-configured "custom-webhook"
 * channel. It is a pure delivery sink invoked by the dispatcher AFTER
 * authorization: it never resolves approvals, never touches the side-effect
 * ledger / conversation store / pairing store, and never holds a credential.
 *
 * What it does:
 * - Builds a typed webhook envelope from `prepared.resolvedDestination`
 *   VERBATIM (the webhook is keyed by addressRef/conversationId — never
 *   re-derived from the body or conversation members) + the relay-rendered
 *   `prepared.finalRenderedBody`.
 * - Resolves declared attachments ONLY through the owner-bound
 *   `context.resolveAttachment`, emitting metadata only (mediaType, sizeBytes,
 *   contentHash). Raw bytes never enter the envelope and the connector never
 *   reads a model-supplied path/byte.
 * - Hands the typed request to an INJECTED sender (`options.send`). The relay
 *   later wires that sender to the credential proxy, which adds the signature
 *   header from the signing key — the key is NOT in this connector.
 *
 * Fail-closed posture: an unsupported destination kind, a missing destination
 * field, or an unresolvable declared attachment returns `{ ok: false }` before
 * the sender is ever called. A thrown sender error or a non-ok platform result
 * maps to `{ ok: false }`; because the POST is a side-effecting external send
 * whose outcome is ambiguous once dispatched, those are non-retryable
 * (at-most-once), matching the Gmail transport.
 */

export const CUSTOM_WEBHOOK_SEND_SCHEMA_VERSION = "telclaude.edge.custom-webhook.send.v1";
export const CUSTOM_WEBHOOK_INBOUND_RISK_WRAP_REQUIRED =
	"custom-webhook inbound listener requires CL-1 risk wrapping before edge.ingest";

/** Attachment metadata carried in the envelope (bytes stay relay-local). */
export interface CustomWebhookEnvelopeAttachment {
	readonly mediaType: string;
	readonly sizeBytes: number;
	/** sha256:<hex>, recomputed by the quarantine store on release. */
	readonly contentHash: string;
}

/**
 * The JSON envelope POSTed to the operator-configured webhook URL. The relay
 * adds the signature header around this body in the credential proxy; the body
 * itself carries no credential.
 */
export interface CustomWebhookEnvelope {
	readonly schemaVersion: typeof CUSTOM_WEBHOOK_SEND_SCHEMA_VERSION;
	readonly outboundRef: string;
	readonly conversationId: string;
	readonly text: string;
	readonly attachments: readonly CustomWebhookEnvelopeAttachment[];
}

/** The destination keying carried verbatim from the prepared outbound. */
export interface CustomWebhookDestination {
	/** The configured webhook is keyed by this addressRef. */
	readonly addressRef: string;
	/** The conversation this envelope belongs to (webhook secondary key). */
	readonly conversationId: string;
}

/** Typed request handed to the injected sender. */
export interface CustomWebhookSendRequest {
	readonly destination: CustomWebhookDestination;
	readonly envelope: CustomWebhookEnvelope;
	/** Relay-minted idempotency key (prepared.idempotencyKey) for sender-side dedup/logging. */
	readonly idempotencyKey: string;
}

/** Result the injected sender reports back. */
export interface CustomWebhookSendResult {
	readonly ok: boolean;
	readonly id?: string;
	readonly status?: number;
}

/**
 * The relay-wired sender. The relay later binds this to the vault credential
 * proxy (which POSTs the envelope to the configured URL and adds the signature
 * header). The connector constructs the typed request, calls this, and maps the
 * result to a ChannelSendOutcome. Mirrors gmail-transport's callProvider.
 */
export type CustomWebhookSender = (
	request: CustomWebhookSendRequest,
) => Promise<CustomWebhookSendResult>;

export interface CreateCustomWebhookConnectorOptions {
	readonly send: CustomWebhookSender;
}

function resolveDestination(
	destination: OutboundDeliveryContext["prepared"]["resolvedDestination"],
):
	| { readonly ok: true; readonly destination: CustomWebhookDestination }
	| Extract<ChannelSendOutcome, { ok: false }> {
	// Build from resolvedDestination VERBATIM. The webhook channel is keyed by an
	// "address" destination — anything else fails closed (no recipient to key on).
	if (destination.kind !== "address") {
		return {
			ok: false,
			code: "custom_webhook_requires_address_destination",
			reason: `custom-webhook cannot deliver to a ${destination.kind} destination`,
			retryable: false,
		};
	}
	const addressRef = destination.addressRef?.trim();
	if (!addressRef) {
		return {
			ok: false,
			code: "custom_webhook_missing_address",
			reason: "custom-webhook address destination has no addressRef",
			retryable: false,
		};
	}
	const conversationId = destination.conversationId?.trim();
	if (!conversationId) {
		return {
			ok: false,
			code: "custom_webhook_missing_conversation",
			reason: "custom-webhook destination has no conversationId to key on",
			retryable: false,
		};
	}
	return { ok: true, destination: { addressRef, conversationId } };
}

async function buildEnvelope(
	context: OutboundDeliveryContext,
	conversationId: string,
): Promise<
	| { readonly ok: true; readonly envelope: CustomWebhookEnvelope }
	| Extract<ChannelSendOutcome, { ok: false }>
> {
	const { prepared, resolveAttachment } = context;
	const attachments: CustomWebhookEnvelopeAttachment[] = [];
	// Scope strictly to prepared.mediaRefs; resolve each through the owner-bound
	// resolver. A declared-but-unresolvable attachment fails closed — we never
	// read raw bytes/paths from the model, and we never silently drop a declared
	// attachment from the envelope.
	for (const mediaRef of prepared.mediaRefs) {
		const released = await resolveAttachment(mediaRef.quarantineId);
		if (!released) {
			return {
				ok: false,
				code: "attachment_missing",
				reason: `prepared attachment is unavailable for this conversation: ${mediaRef.quarantineId}`,
				retryable: false,
			};
		}
		attachments.push({
			mediaType: released.mediaType,
			sizeBytes: released.bytes.byteLength,
			contentHash: released.contentHash,
		});
	}
	return {
		ok: true,
		envelope: {
			schemaVersion: CUSTOM_WEBHOOK_SEND_SCHEMA_VERSION,
			outboundRef: prepared.outboundRef,
			conversationId,
			text: prepared.finalRenderedBody,
			attachments,
		},
	};
}

export function createCustomWebhookConnector(
	options: CreateCustomWebhookConnectorOptions,
): EdgeChannelConnector {
	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const destination = resolveDestination(context.prepared.resolvedDestination);
		if (!destination.ok) return destination;

		const envelope = await buildEnvelope(context, destination.destination.conversationId);
		if (!envelope.ok) return envelope;

		const request: CustomWebhookSendRequest = {
			destination: destination.destination,
			envelope: envelope.envelope,
			idempotencyKey: context.prepared.idempotencyKey,
		};

		// At-most-once delivery boundary. Once the injected sender dispatches the
		// POST we cannot know whether the webhook accepted the envelope, so NOTHING
		// from here on is retryable — neither a thrown sender error nor a non-ok
		// result. A retry would re-POST with no webhook-side dedupe and could
		// duplicate a delivery the endpoint already accepted. (Mirrors
		// gmail-transport's at-most-once boundary.)
		let result: CustomWebhookSendResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "custom_webhook_send_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (!result.ok) {
			return {
				ok: false,
				code: "custom_webhook_send_rejected",
				reason:
					typeof result.status === "number"
						? `custom-webhook endpoint returned status ${result.status}`
						: "custom-webhook endpoint rejected the envelope",
				retryable: false,
			};
		}

		const platformMessageId =
			typeof result.id === "string" && result.id.length > 0 ? result.id : undefined;
		return {
			ok: true,
			...(platformMessageId
				? { platformMessageId, observedThreadMessageId: platformMessageId }
				: {}),
		};
	}

	async function startListener(_sink: InboundSink): Promise<never> {
		throw new Error(CUSTOM_WEBHOOK_INBOUND_RISK_WRAP_REQUIRED);
	}

	return { channel: "custom-webhook", send, startListener };
}
