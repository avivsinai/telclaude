import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";

/**
 * Outbound social-gateway connector (channel literal "social").
 *
 * PUBLIC / SOCIAL PERSONA PATH — DO NOT REGISTER FOR THE PRIVATE HERMES PERSONA.
 * This channel posts to a public social gateway. Public-social content is
 * untrusted and air-gapped from the private persona (see the private/public
 * air-gap invariant): the integrator MUST gate registration so the private
 * Hermes dispatcher never owns this connector. The connector itself stays a
 * pure delivery sink and enforces nothing about persona binding — that gate
 * lives in the wiring, not here.
 *
 * Pure delivery sink invoked by the dispatcher AFTER authorization. It never
 * resolves approvals, never touches the side-effect ledger, never holds raw
 * credentials. Sending goes through an INJECTED `send` (wired by the relay to
 * the vault credential proxy / platform transport). The target comes from
 * `prepared.resolvedDestination` VERBATIM (an edge-validated, membership-bound
 * "actor" or "address" gateway target) — never re-derived from the body or the
 * conversation members. Attachment bytes are released only through the
 * owner-bound resolver. Inbound stays dark until CL-1.
 */

export const SOCIAL_INBOUND_RISK_WRAP_REQUIRED =
	"social inbound listener requires CL-1 risk wrapping before edge.ingest";

/** A media payload released from quarantine, ready to hand to the gateway. */
export interface SocialGatewayMedia {
	readonly quarantineId: string;
	readonly mediaType: string;
	/** sha256:<hex> recomputed by the quarantine store. */
	readonly contentHash: string;
	readonly sizeBytes: number;
	readonly bytes: Uint8Array;
}

/**
 * The typed request the connector builds for the injected sender. The recipient
 * fields are copied VERBATIM from the prepared destination; `text` is the
 * relay-rendered body; `media` is scoped to `prepared.mediaRefs`.
 */
export interface SocialGatewayPostRequest {
	/** "actor" | "address" — the gateway account/target kind, taken verbatim. */
	readonly targetKind: "actor" | "address";
	/** The gateway account/target id (actorId for "actor", addressRef for "address"). */
	readonly target: string;
	readonly text: string;
	readonly media: readonly SocialGatewayMedia[];
	/** Edge provenance for the gateway's own idempotency/dedupe. */
	readonly outboundRef: string;
	readonly idempotencyKey: string;
	readonly conversationId?: string;
}

/**
 * Result returned by the injected sender, mirroring the gateway contract
 * `{ postId?, error? }`. A present `error` (or a thrown sender error) maps to a
 * non-ok outcome.
 */
export interface SocialGatewayPostResult {
	readonly postId?: string;
	readonly error?: string;
}

/**
 * Posts a typed request to the social gateway. The relay wires this to the
 * vault credential proxy / platform transport; the connector never sees raw
 * credentials. Mirrors gmail-transport's injected `callProvider`.
 */
export type SocialGatewaySender = (
	request: SocialGatewayPostRequest,
) => Promise<SocialGatewayPostResult>;

export interface CreateSocialGatewayConnectorOptions {
	readonly send: SocialGatewaySender;
}

function targetFor(
	destination: OutboundDeliveryContext["prepared"]["resolvedDestination"],
):
	| { readonly ok: true; readonly targetKind: "actor" | "address"; readonly target: string }
	| Extract<ChannelSendOutcome, { ok: false }> {
	if (destination.kind === "actor") {
		const target = destination.actorId?.trim();
		if (!target) {
			return {
				ok: false,
				code: "social_missing_target",
				reason: "actor destination has no actorId",
				retryable: false,
			};
		}
		return { ok: true, targetKind: "actor", target };
	}
	if (destination.kind === "address") {
		const target = destination.addressRef?.trim();
		if (!target) {
			return {
				ok: false,
				code: "social_missing_target",
				reason: "address destination has no addressRef",
				retryable: false,
			};
		}
		return { ok: true, targetKind: "address", target };
	}
	return {
		ok: false,
		code: "social_unsupported_destination",
		reason: `social gateway cannot post to a ${destination.kind} destination`,
		retryable: false,
	};
}

export function createSocialGatewayConnector(
	options: CreateSocialGatewayConnectorOptions,
): EdgeChannelConnector {
	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, resolveAttachment } = context;

		// Recipient is taken from the edge-validated destination VERBATIM. Fail
		// closed on an unsupported kind ("thread") or a missing target field.
		const target = targetFor(prepared.resolvedDestination);
		if (!target.ok) return target;

		// Attachments only via the owner-bound resolver, scoped to mediaRefs. Fail
		// closed if a declared attachment is not resolvable for this conversation.
		const media: SocialGatewayMedia[] = [];
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
			media.push({
				quarantineId: resolved.quarantineId,
				mediaType: resolved.mediaType,
				contentHash: resolved.contentHash,
				sizeBytes: resolved.bytes.byteLength,
				bytes: resolved.bytes,
			});
		}

		const request: SocialGatewayPostRequest = {
			targetKind: target.targetKind,
			target: target.target,
			text: prepared.finalRenderedBody,
			media,
			outboundRef: prepared.outboundRef,
			idempotencyKey: prepared.idempotencyKey,
			...(prepared.resolvedDestination.conversationId
				? { conversationId: prepared.resolvedDestination.conversationId }
				: {}),
		};

		// At-most-once boundary: once the gateway call is dispatched we cannot know
		// whether the post landed, so a thrown error here is NOT retryable — a retry
		// would re-post with a fresh attempt and could duplicate a post the gateway
		// already accepted. (Matches gmail-transport's ambiguous-send handling.)
		let result: SocialGatewayPostResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "social_gateway_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (result.error) {
			return {
				ok: false,
				code: "social_gateway_rejected",
				reason: result.error,
				retryable: false,
			};
		}

		return {
			ok: true,
			...(result.postId ? { platformMessageId: result.postId } : {}),
			...(result.postId ? { observedThreadMessageId: result.postId } : {}),
		};
	}

	async function startListener(): Promise<never> {
		throw new Error(SOCIAL_INBOUND_RISK_WRAP_REQUIRED);
	}

	return { channel: "social", send, startListener };
}
