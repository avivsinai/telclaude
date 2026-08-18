import type {
	ChannelListenerHandle,
	InboundSink,
	NormalizedInbound,
} from "../edge-channel-connector.js";

/**
 * Inbound email poller — DARK until CL-1.
 *
 * Inbound email is untrusted external content (anyone can send mail to the
 * operator's address). It must not reach edge.ingest until the CL-1 risk-wrap +
 * pairing + air-gap layer exists to neutralize prompt injection and bind the
 * sender to an authorized conversation seat. Until then `startListener` throws,
 * exactly like the WhatsApp inbound listener: the capability is present in the
 * type system but fail-closed at runtime so it cannot be enabled by accident.
 *
 * The normalization contract ({@link normalizeInboundEmail}) is settled now so
 * CL-1 only has to wire the actual poll loop (Gmail history.list / IMAP IDLE)
 * and the risk-wrap, not redesign the shape.
 */

export const EMAIL_INBOUND_RISK_WRAP_REQUIRED =
	"Email inbound poller requires CL-1 risk wrapping before edge.ingest";

/** Raw fields a poll loop extracts from a fetched message, before normalization. */
export interface RawInboundEmail {
	/** RFC822 Message-ID of the fetched message. */
	readonly messageId: string;
	/** Envelope/header From addr-spec (single address). */
	readonly fromAddress: string;
	/** Message-ID this message replies to (In-Reply-To last token), if any. */
	readonly inReplyTo?: string;
	/** Plain-text body (HTML is stripped/normalized by the poll loop). */
	readonly text?: string;
	/** Opaque per-listener cursor (e.g. "<historyId>" or "<UIDVALIDITY>:<UID>"). */
	readonly cursor: string;
	readonly receivedAtMs: number;
}

/**
 * Pure mapping from a fetched email to the channel-agnostic inbound shape CL-1
 * consumes. Attachments are intentionally empty here: CL-1 quarantines bytes
 * owner-bound before populating attachmentRefs. No bytes are released by this
 * function.
 */
export function normalizeInboundEmail(raw: RawInboundEmail): NormalizedInbound {
	return {
		channel: "email",
		senderPrincipalId: raw.fromAddress,
		// One conversation per sender until CL-1 introduces subject/thread keying.
		conversationKey: raw.fromAddress,
		...(raw.inReplyTo ? { inReplyToTransportId: raw.inReplyTo } : {}),
		...(raw.text !== undefined ? { text: raw.text } : {}),
		attachmentRefs: [],
		transportMessageId: raw.messageId,
		transportCursor: raw.cursor,
		receivedAtMs: raw.receivedAtMs,
	};
}

export interface EmailInboundPoller {
	startListener(sink: InboundSink): Promise<ChannelListenerHandle>;
}

/**
 * Construct the inbound poller. Fail-closed: `startListener` throws until CL-1.
 * The `sink` parameter is part of the eventual contract but is unused while dark.
 */
export function createEmailInboundPoller(): EmailInboundPoller {
	return {
		async startListener(_sink: InboundSink): Promise<ChannelListenerHandle> {
			throw new Error(EMAIL_INBOUND_RISK_WRAP_REQUIRED);
		},
	};
}
