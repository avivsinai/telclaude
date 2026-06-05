import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";

/**
 * Outbound Slack connector (chat.postMessage). Pure delivery sink invoked by
 * the dispatcher AFTER authorization — it never resolves approvals, reads the
 * ledger, or holds a credential.
 *
 * Trust model (mirrors the email/WhatsApp sinks):
 * - The recipient is taken from `prepared.resolvedDestination` VERBATIM. Slack
 *   posts to a `channelId` (Slack channel/DM/group id) with an optional
 *   `threadTs` for in-thread replies; the connector never re-derives either
 *   from the rendered body or the conversation members.
 *     - kind "thread":  threadTs <- destination.threadId,
 *                       channelId <- destination.conversationId
 *     - kind "actor":   channelId <- destination.actorId   (resolved IM/channel id)
 *     - kind "address": channelId <- destination.addressRef (resolved channel id)
 * - The Bearer bot token is NOT handled here. Sending goes through an injected
 *   `send` callback that the relay later wires to the vault credential proxy /
 *   Slack transport, which adds `Authorization: Bearer xoxb-...`. The connector
 *   builds a typed request, calls the sender, and maps the typed result to a
 *   ChannelSendOutcome.
 * - Attachment bytes are released only through the owner-bound resolver, scoped
 *   to `prepared.mediaRefs`. A declared-but-unresolvable attachment fails closed
 *   ("attachment_missing"). The connector never reads raw bytes/paths from the
 *   model.
 * - At-most-once delivery boundary: once the sender is invoked the post may have
 *   landed, so a thrown sender error or a non-ok platform result is mapped to a
 *   NON-retryable failure (matching gmail-transport.ts).
 */

const SLACK_CHANNEL = "slack" as const;
export const SLACK_INBOUND_RISK_WRAP_REQUIRED =
	"slack inbound listener requires CL-1 risk wrapping before edge.ingest";

/** Bytes released from quarantine, shaped for the Slack transport. */
export type SlackAttachment = {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly sizeBytes: number;
	readonly bytes: Uint8Array;
};

/**
 * Typed Slack chat.postMessage request. The injected sender (relay-wired) adds
 * the Bearer bot token; this connector NEVER carries a credential.
 */
export type SlackPostMessageRequest = {
	readonly channelId: string;
	readonly text: string;
	/** Present only for an in-thread reply (resolvedDestination.kind === "thread"). */
	readonly threadTs?: string;
	readonly attachments: readonly SlackAttachment[];
	/** Carried for transport-level dedup; the connector does not interpret it. */
	readonly idempotencyKey: string;
};

/** Platform result from the Slack transport / chat.postMessage call. */
export type SlackPostMessageResult = {
	readonly ok: boolean;
	/** Slack message timestamp ("ts"); the platform message id on success. */
	readonly ts?: string;
	/** Slack error code (e.g. "channel_not_found") when ok is false. */
	readonly error?: string;
};

/** Injected, relay-wired sender. The connector constructs the request and calls this. */
export type SlackPostMessageSender = (
	request: SlackPostMessageRequest,
) => Promise<SlackPostMessageResult>;

export interface CreateSlackConnectorOptions {
	/**
	 * Posts the typed request to Slack chat.postMessage. The relay wires this to
	 * the vault credential proxy / Slack transport, which injects the Bearer bot
	 * token. The connector itself holds no credential.
	 */
	readonly send: SlackPostMessageSender;
}

/**
 * Resolves the Slack {channelId, threadTs?} pair from the edge-validated
 * destination VERBATIM. Fails closed on an unsupported kind or a missing field.
 */
function resolveSlackTarget(
	destination: OutboundDeliveryContext["prepared"]["resolvedDestination"],
):
	| { readonly ok: true; readonly channelId: string; readonly threadTs?: string }
	| Extract<ChannelSendOutcome, { ok: false }> {
	switch (destination.kind) {
		case "thread": {
			const threadTs = destination.threadId?.trim();
			const channelId = destination.conversationId?.trim();
			if (!threadTs || !channelId) {
				return {
					ok: false,
					code: "slack_missing_destination",
					reason:
						"slack thread destination requires both threadId (threadTs) and conversationId (channelId)",
					retryable: false,
				};
			}
			return { ok: true, channelId, threadTs };
		}
		case "actor": {
			const channelId = destination.actorId?.trim();
			if (!channelId) {
				return {
					ok: false,
					code: "slack_missing_destination",
					reason: "slack actor destination requires actorId (channelId)",
					retryable: false,
				};
			}
			return { ok: true, channelId };
		}
		case "address": {
			const channelId = destination.addressRef?.trim();
			if (!channelId) {
				return {
					ok: false,
					code: "slack_missing_destination",
					reason: "slack address destination requires addressRef (channelId)",
					retryable: false,
				};
			}
			return { ok: true, channelId };
		}
		default:
			return {
				ok: false,
				code: "slack_unsupported_destination",
				reason: `slack cannot deliver to a ${String((destination as { kind: string }).kind)} destination`,
				retryable: false,
			};
	}
}

export function createSlackConnector(options: CreateSlackConnectorOptions): EdgeChannelConnector {
	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, resolveAttachment } = context;

		const target = resolveSlackTarget(prepared.resolvedDestination);
		if (!target.ok) return target;

		const attachments: SlackAttachment[] = [];
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
				bytes: resolved.bytes,
			});
		}

		const request: SlackPostMessageRequest = {
			channelId: target.channelId,
			text: prepared.finalRenderedBody,
			...(target.threadTs ? { threadTs: target.threadTs } : {}),
			attachments,
			idempotencyKey: prepared.idempotencyKey,
		};

		// At-most-once boundary: once the sender is invoked the message may have
		// posted, so neither a thrown error nor an ok:false result is retryable.
		let result: SlackPostMessageResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "slack_post_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (!result.ok) {
			return {
				ok: false,
				code: result.error ?? "slack_post_failed",
				...(result.error ? { reason: result.error } : {}),
				retryable: false,
			};
		}

		const ts = result.ts?.trim();
		return {
			ok: true,
			...(ts ? { platformMessageId: ts, observedThreadMessageId: ts } : {}),
		};
	}

	return {
		channel: SLACK_CHANNEL,
		send,
		async startListener() {
			throw new Error(SLACK_INBOUND_RISK_WRAP_REQUIRED);
		},
	};
}
