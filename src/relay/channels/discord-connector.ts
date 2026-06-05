import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../edge-channel-connector.js";

/**
 * Outbound Discord connector. Pure delivery sink invoked by the dispatcher AFTER
 * authorization — it never resolves approvals, touches the side-effect ledger,
 * or reads raw credentials.
 *
 * The platform request is built from `prepared.resolvedDestination` VERBATIM
 * (edge-validated, membership-bound) and `prepared.finalRenderedBody`; the
 * recipient is never re-derived from the body or from conversation members. All
 * three destination kinds (`thread` / `actor` / `address`) carry the Discord
 * channel id in their respective field, so the connector maps that field to the
 * `channelId` of a create-message request and fails closed on an unsupported
 * kind or a missing destination field.
 *
 * Sending goes through an INJECTED `send` (mirrors gmail-transport's
 * callProvider): the relay later wires it to the vault credential proxy / Discord
 * transport that adds the bot token. The connector constructs a typed request,
 * calls the injected sender, and maps the typed result to a ChannelSendOutcome.
 *
 * Reply threading uses the relay-OBSERVED `threadMessageIds` from the context
 * (never the model body) as the Discord `messageReference`, analogous to email's
 * In-Reply-To.
 *
 * Attachment bytes are released ONLY through the owner-bound resolver, scoped to
 * `prepared.mediaRefs`; a declared-but-unresolvable attachment fails closed.
 */

const DISCORD_CHANNEL: EdgeChannelConnector["channel"] = "discord";
export const DISCORD_INBOUND_RISK_WRAP_REQUIRED =
	"discord inbound listener requires CL-1 risk wrapping before edge.ingest";

/** A typed Discord create-message request handed to the injected sender. */
export interface DiscordCreateMessageRequest {
	/** Target Discord channel id (from resolvedDestination VERBATIM). */
	readonly channelId: string;
	/** The relay-rendered message body. */
	readonly content: string;
	/**
	 * Relay-observed prior transport message id this message replies to, if any.
	 * Sourced from threadMessageIds (authenticated transport ids), never the body.
	 */
	readonly messageReference?: string;
	/** Owner-bound attachment bytes resolved for this conversation. */
	readonly attachments: readonly DiscordOutboundAttachment[];
	/** Idempotency key carried verbatim from the prepared outbound. */
	readonly idempotencyKey: string;
	/** Edge outbound ref, for sender-side audit/correlation. */
	readonly outboundRef: string;
}

/** A single attachment released from quarantine for this outbound. */
export interface DiscordOutboundAttachment {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly bytes: Uint8Array;
}

/** The injected sender's typed result. `id` becomes the platformMessageId. */
export type DiscordSendResult =
	| { readonly id: string; readonly error?: undefined }
	| { readonly id?: undefined; readonly error: string };

/**
 * Injected platform transport. The connector NEVER holds the bot token: the
 * relay wires this to the vault credential proxy / Discord client, which adds
 * `Authorization: Bot <token>` out of band.
 */
export type DiscordMessageSender = (
	request: DiscordCreateMessageRequest,
) => Promise<DiscordSendResult>;

export interface CreateDiscordConnectorOptions {
	readonly send: DiscordMessageSender;
}

/**
 * Resolves the Discord channel id from the prepared destination VERBATIM. Every
 * supported kind carries the channel id in its own field; an unsupported kind or
 * a missing field fails closed (the caller turns this into a non-retryable
 * ChannelSendOutcome).
 */
function resolveChannelId(
	destination: OutboundDeliveryContext["prepared"]["resolvedDestination"],
):
	| { readonly ok: true; readonly channelId: string }
	| { readonly ok: false; readonly code: string; readonly reason: string } {
	const field =
		destination.kind === "thread"
			? destination.threadId
			: destination.kind === "actor"
				? destination.actorId
				: destination.kind === "address"
					? destination.addressRef
					: undefined;
	if (field === undefined) {
		return {
			ok: false,
			code: "discord_unsupported_destination_kind",
			reason: `discord cannot deliver to a ${destination.kind} destination`,
		};
	}
	const channelId = field.trim();
	if (!channelId) {
		return {
			ok: false,
			code: "discord_missing_destination",
			reason: `discord ${destination.kind} destination has no channel id`,
		};
	}
	return { ok: true, channelId };
}

export function createDiscordConnector(
	options: CreateDiscordConnectorOptions,
): EdgeChannelConnector {
	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, threadMessageIds, resolveAttachment } = context;

		const resolved = resolveChannelId(prepared.resolvedDestination);
		if (!resolved.ok) {
			return { ok: false, code: resolved.code, reason: resolved.reason, retryable: false };
		}

		const attachments: DiscordOutboundAttachment[] = [];
		for (const ref of prepared.mediaRefs) {
			const released: QuarantinedBytes | null = await resolveAttachment(ref.quarantineId);
			if (!released) {
				return {
					ok: false,
					code: "attachment_missing",
					reason: `attachment ${ref.quarantineId} is not resolvable for this conversation`,
					retryable: false,
				};
			}
			attachments.push({
				quarantineId: released.quarantineId,
				mediaType: released.mediaType,
				contentHash: released.contentHash,
				bytes: released.bytes,
			});
		}

		// Reply target comes from the relay-OBSERVED thread ids (authenticated
		// transport message ids), oldest-first — never from the model body.
		const messageReference =
			threadMessageIds.length > 0 ? threadMessageIds[threadMessageIds.length - 1] : undefined;

		const request: DiscordCreateMessageRequest = {
			channelId: resolved.channelId,
			content: prepared.finalRenderedBody,
			attachments,
			idempotencyKey: prepared.idempotencyKey,
			outboundRef: prepared.outboundRef,
			...(messageReference ? { messageReference } : {}),
		};

		// At-most-once boundary: once the create-message call is dispatched we
		// cannot know whether Discord accepted it, so a thrown sender error is NOT
		// retryable (a retry could duplicate a message Discord already created).
		let result: DiscordSendResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "discord_send_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (result.error !== undefined || typeof result.id !== "string" || result.id.length === 0) {
			return {
				ok: false,
				code: "discord_send_failed",
				...(result.error ? { reason: result.error } : {}),
				retryable: false,
			};
		}

		return {
			ok: true,
			platformMessageId: result.id,
			// Record the created message id so the next reply threads via messageReference.
			observedThreadMessageId: result.id,
		};
	}

	async function startListener(): Promise<never> {
		throw new Error(DISCORD_INBOUND_RISK_WRAP_REQUIRED);
	}

	return { channel: DISCORD_CHANNEL, send, startListener };
}
