import { randomBytes } from "node:crypto";
import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";
import {
	composeEmailMime,
	type EmailAttachmentPart,
	EmailHeaderInjectionError,
} from "./mime-compose.js";
import type { EmailTransport, OutboundAuthorizationContext } from "./transport.js";

/**
 * Outbound email connector. Pure delivery sink invoked by the dispatcher AFTER
 * authorization. It never resolves approvals or touches the ledger.
 *
 * Recipient comes from the edge-validated, membership-bound
 * `prepared.resolvedDestination` VERBATIM; this first cut requires an explicit
 * `address` destination (an email reply needs a concrete To). Threading uses
 * the relay-OBSERVED `threadMessageIds` from the context — never the model
 * body. Attachment bytes are released only through the owner-bound resolver.
 * The raw message is built by the CRLF-safe composer (header-injection is
 * rejected, surfaced here as a non-retryable failure).
 */

const MEDIA_TYPE_EXTENSIONS: Record<string, string> = {
	"text/plain": ".txt",
	"text/html": ".html",
	"image/png": ".png",
	"image/jpeg": ".jpg",
	"image/gif": ".gif",
	"application/pdf": ".pdf",
	"application/json": ".json",
};

function attachmentFilename(index: number, mediaType: string): string {
	const base = mediaType.split(";")[0]?.trim().toLowerCase() ?? "";
	return `attachment-${index + 1}${MEDIA_TYPE_EXTENSIONS[base] ?? ""}`;
}

// Characters that turn a single addr-spec into a list / group / display-name /
// comment header — any of these means the edge "address" destination would fan
// out beyond the one membership-validated recipient. Done via includes (not a
// regex) to keep the guard unambiguous.
const NON_SINGLE_ADDRESS_CHARS = [",", ";", "<", ">", "(", ")", ":", '"', " ", "\t"];

/** A single bare addr-spec only: exactly one @, no list/group/display-name/control syntax. */
function isSingleEmailAddress(value: string): boolean {
	if (value.length === 0 || value.length > 254) return false;
	for (let i = 0; i < value.length; i += 1) {
		if (value.charCodeAt(i) < 0x20 || value.charCodeAt(i) === 0x7f) return false;
	}
	for (const ch of NON_SINGLE_ADDRESS_CHARS) {
		if (value.includes(ch)) return false;
	}
	const at = value.indexOf("@");
	return at > 0 && at === value.lastIndexOf("@") && at < value.length - 1;
}

export interface CreateEmailConnectorOptions {
	readonly transport: EmailTransport;
	/** Operator's configured From address (relay config, never model-supplied). */
	readonly from: string;
	/**
	 * Subject for outbound replies until inbound subject-threading lands. The
	 * inbound poller will later carry the original subject onto the conversation
	 * so this becomes "Re: <subject>"; for now it's a configured default.
	 */
	readonly defaultSubject: string;
	/** Domain for the generated Message-ID; defaults to the From address domain. */
	readonly messageIdDomain?: string;
}

export function createEmailConnector(options: CreateEmailConnectorOptions): EdgeChannelConnector {
	const messageIdDomain =
		options.messageIdDomain ?? options.from.split("@")[1]?.trim() ?? "relay.local";

	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, threadMessageIds, resolveAttachment } = context;
		const destination = prepared.resolvedDestination;
		if (destination.kind !== "address" || !destination.addressRef) {
			return {
				ok: false,
				code: "email_requires_address_recipient",
				reason: `email cannot deliver to a ${destination.kind} destination`,
				retryable: false,
			};
		}
		const to = destination.addressRef;
		// The edge destination must be ONE membership-validated address. Reject any
		// list/group/display-name syntax before composing or sending, so a value like
		// "alice@x, attacker@evil" cannot fan the message out past the bound recipient.
		if (!isSingleEmailAddress(to)) {
			return {
				ok: false,
				code: "email_invalid_recipient",
				reason: "email recipient must be a single address (no list/group/display-name syntax)",
				retryable: false,
			};
		}

		// Carry the edge authorization verbatim for sidecar-gated transports
		// (Gmail). Fail closed if the prepared outbound has no authorizing actor:
		// the operator identity binds the sidecar approval token, and a send with
		// no bound actor must never reach the transport.
		const actorUserId = prepared.authorizingActor.actorId.trim();
		if (!actorUserId) {
			return {
				ok: false,
				code: "missing_authorizing_actor",
				reason: "prepared outbound has no authorizing actor id",
				retryable: false,
			};
		}
		const authorization: OutboundAuthorizationContext = {
			actorUserId,
			outboundRef: prepared.outboundRef,
			sideEffectLedgerRef: prepared.sideEffectLedgerRef,
			edgePreparedHash: prepared.edgePreparedHash,
		};

		const attachments: EmailAttachmentPart[] = [];
		for (let index = 0; index < prepared.mediaRefs.length; index += 1) {
			const ref = prepared.mediaRefs[index];
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
				filename: attachmentFilename(index, resolved.mediaType),
				mediaType: resolved.mediaType,
				bytes: resolved.bytes,
			});
		}

		const messageId = `<${randomBytes(16).toString("hex")}@${messageIdDomain}>`;
		const inReplyTo =
			threadMessageIds.length > 0 ? threadMessageIds[threadMessageIds.length - 1] : undefined;

		let rawMime: string;
		try {
			rawMime = composeEmailMime({
				from: options.from,
				to: [to],
				subject: options.defaultSubject,
				textBody: prepared.finalRenderedBody,
				messageId,
				...(inReplyTo ? { inReplyTo } : {}),
				...(threadMessageIds.length > 0 ? { references: threadMessageIds } : {}),
				...(attachments.length > 0 ? { attachments } : {}),
			});
		} catch (error) {
			if (error instanceof EmailHeaderInjectionError) {
				return {
					ok: false,
					code: "email_header_injection",
					reason: error.message,
					retryable: false,
				};
			}
			throw error;
		}

		const result = await options.transport.send({
			rawMime,
			from: options.from,
			to: [to],
			idempotencyKey: prepared.idempotencyKey,
			authorization,
		});
		if (!result.ok) {
			return { ok: false, code: result.code, reason: result.reason, retryable: result.retryable };
		}
		return {
			ok: true,
			...(result.platformMessageId ? { platformMessageId: result.platformMessageId } : {}),
			// Record our sent Message-ID so the next reply threads via In-Reply-To/References.
			observedThreadMessageId: messageId,
		};
	}

	return { channel: "email", send };
}
