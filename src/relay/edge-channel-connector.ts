import type { z } from "zod";
import type {
	AttachmentRef,
	EdgeChannelSchema,
	PreparedOutbound,
} from "../hermes/edge-adapter-contract.js";

/**
 * Channel-layer primitives (CL-0). These types are the contract between the
 * relay's authorization layer (Codex-owned, up to markExecuted) and the
 * delivery/inbound transports (Claude-owned, downstream of markExecuted).
 *
 * Invariants this layer must preserve:
 * - Transports are pure sinks: they NEVER import the side-effect ledger or
 *   resolve approvals. Authorization is fully decided upstream; a connector
 *   only receives an already-authorized {@link PreparedOutbound}.
 * - Recipients come from {@link PreparedOutbound.resolvedDestination} VERBATIM
 *   (edge-validated, membership-bound). A connector never re-derives the
 *   destination from the conversation members or the model body.
 * - Attachment bytes are resolved only through an owner-bound resolver bound to
 *   the prepared outbound's conversation; a connector cannot read arbitrary
 *   quarantine bytes.
 */

export type EdgeChannel = z.infer<typeof EdgeChannelSchema>;

/** Bytes released from quarantine after an owner-binding check passes. */
export interface QuarantinedBytes {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly bytes: Uint8Array;
	/** sha256:<hex> recomputed by the store; equals the AttachmentRef contentHash. */
	readonly contentHash: string;
}

/**
 * Owner-bound attachment resolver handed to a connector by the dispatcher. It
 * is pre-scoped to the prepared outbound's conversation, so a connector cannot
 * resolve an attachment belonging to a different conversation. Returns null
 * (never throws) when the attachment is missing, expired, not clean, or not
 * authorized for this conversation — the connector then fails closed.
 */
export type BoundAttachmentResolver = (quarantineId: string) => Promise<QuarantinedBytes | null>;

/** Everything a connector needs to deliver one authorized outbound. */
export interface OutboundDeliveryContext {
	readonly prepared: PreparedOutbound;
	/**
	 * Relay-OBSERVED prior transport message ids for this conversation thread
	 * (e.g. email Message-IDs, WhatsApp message keys), oldest-first. Built only
	 * from authenticated inbound/outbound — never from the model body. Used for
	 * In-Reply-To/References (email) or thread keying (chat). Empty for a new
	 * thread.
	 */
	readonly threadMessageIds: readonly string[];
	readonly resolveAttachment: BoundAttachmentResolver;
}

/** A connector's report of a single send attempt. */
export type ChannelSendOutcome =
	| {
			readonly ok: true;
			/** Platform message id (e.g. Gmail message id, sent Message-ID, WA key). */
			readonly platformMessageId?: string;
			/**
			 * Transport message id to record on the conversation thread so the next
			 * send/inbound threads correctly. Usually equals platformMessageId.
			 */
			readonly observedThreadMessageId?: string;
	  }
	| {
			readonly ok: false;
			/** Stable machine code, e.g. "attachment_missing", "transport_unavailable". */
			readonly code: string;
			readonly reason?: string;
			readonly retryable: boolean;
	  };

/** A normalized inbound message produced by a connector's listener (CL-1 consumes it). */
export interface NormalizedInbound {
	readonly channel: EdgeChannel;
	/** Channel-native sender principal (email address, WA phone JID, ...). */
	readonly senderPrincipalId: string;
	/** Channel-native conversation/thread key used to resolve/mint a relay conversation. */
	readonly conversationKey: string;
	/** Transport id of the message this replies to, if any (e.g. In-Reply-To). */
	readonly inReplyToTransportId?: string;
	readonly text?: string;
	/** Quarantined attachment refs (bytes stay relay-local). */
	readonly attachmentRefs: readonly AttachmentRef[];
	/** Transport-unique message id, used for inbound dedup. */
	readonly transportMessageId: string;
	/** Opaque per-listener cursor (UIDVALIDITY:UID, historyId, ...) for ordering/replay. */
	readonly transportCursor: string;
	readonly receivedAtMs: number;
}

/** Sink the inbound-ingress pipeline (CL-1) provides to a connector's listener. */
export type InboundSink = (inbound: NormalizedInbound) => Promise<void>;

/** Handle to stop a running inbound listener. */
export interface ChannelListenerHandle {
	stop(): Promise<void>;
}

/**
 * A per-channel transport. Outbound `send` is a pure delivery sink. Inbound
 * `startListener` is optional and must remain dark until CL-1 (risk-wrap +
 * pairing + air-gap) is wired — connectors enforce that precondition themselves.
 */
export interface EdgeChannelConnector {
	readonly channel: EdgeChannel;
	send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome>;
	startListener?(sink: InboundSink): Promise<ChannelListenerHandle>;
}
