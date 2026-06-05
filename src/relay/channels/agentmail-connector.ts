import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";

/**
 * Outbound AgentMail connector. AgentMail is a programmatic-email REST API:
 * the same delivery semantics as email, but the wire format is a JSON POST
 * ({ to, subject, text, attachments? }) rather than a raw SMTP/RFC822 socket.
 *
 * This is a pure delivery sink invoked by the dispatcher AFTER authorization.
 * It never resolves approvals, never touches the side-effect ledger, and never
 * holds the AgentMail API key. Sending goes through an INJECTED sender
 * (`options.send`) that the relay later wires to the vault credential proxy /
 * platform transport — exactly the gmail-transport.ts `callProvider` pattern.
 * The connector only builds a typed request, calls the injected sender, and
 * maps the typed result to a {@link ChannelSendOutcome}.
 *
 * Recipient comes from the edge-validated, membership-bound
 * `prepared.resolvedDestination` VERBATIM (a single `address`); it is never
 * re-derived from the body or conversation members. Subject and From come from
 * relay config (`options`), never the model. Attachment bytes are released only
 * through the owner-bound resolver, scoped to `prepared.mediaRefs`.
 */

export const AGENTMAIL_INBOUND_RISK_WRAP_REQUIRED =
	"agentmail inbound listener requires CL-1 risk wrapping before edge.ingest";

/** One attachment as the AgentMail REST API expects it (base64-encoded bytes). */
export interface AgentMailAttachment {
	readonly filename: string;
	readonly contentType: string;
	readonly contentBase64: string;
}

/**
 * The typed request handed to the injected sender. The sender (relay-wired) is
 * what adds the AgentMail API key / auth header — this object carries NO
 * credentials. `idempotencyKey` is forwarded for transport-side dedup/logging.
 */
export interface AgentMailSendRequest {
	readonly from: string;
	readonly to: string;
	readonly subject: string;
	readonly text: string;
	readonly attachments?: readonly AgentMailAttachment[];
	readonly idempotencyKey: string;
}

/** Typed result from the injected sender: a platform message id, or an error. */
export interface AgentMailSendResult {
	readonly messageId?: string;
	readonly error?: string;
}

/**
 * Relay-wired AgentMail sender. The relay binds this to the vault credential
 * proxy (the API key is injected there), so the connector never sees raw creds.
 * Mirrors gmail-transport.ts's injected `callProvider`.
 */
export type AgentMailSender = (request: AgentMailSendRequest) => Promise<AgentMailSendResult>;

export interface CreateAgentMailConnectorOptions {
	/** Relay-wired sender (vault credential proxy adds the API key). */
	readonly send: AgentMailSender;
	/** Operator's configured From address (relay config, never model-supplied). */
	readonly from: string;
	/** Subject for outbound sends until inbound subject-threading lands (relay config). */
	readonly defaultSubject: string;
}

// Characters that turn a single addr-spec into a list / group / display-name /
// comment header, which would fan the message out past the one
// membership-validated recipient. Checked via includes (not a regex) to keep
// the guard unambiguous. Reused idea from the email connector.
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

export function createAgentMailConnector(
	options: CreateAgentMailConnectorOptions,
): EdgeChannelConnector {
	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, resolveAttachment } = context;
		const destination = prepared.resolvedDestination;

		// Fail closed on an unsupported destination kind: AgentMail needs a
		// concrete address recipient, never a thread/actor handle.
		if (destination.kind !== "address" || !destination.addressRef) {
			return {
				ok: false,
				code: "agentmail_requires_address_recipient",
				reason: `agentmail cannot deliver to a ${destination.kind} destination`,
				retryable: false,
			};
		}

		const to = destination.addressRef;
		// The edge destination must be ONE membership-validated address. Reject any
		// list/group/display-name syntax before building or sending, so a value like
		// "alice@x, attacker@evil" cannot fan the message out past the bound recipient.
		if (!isSingleEmailAddress(to)) {
			return {
				ok: false,
				code: "agentmail_invalid_recipient",
				reason: "agentmail recipient must be a single address (no list/group/display-name syntax)",
				retryable: false,
			};
		}

		// Attachments ONLY via the owner-bound resolver, scoped to the prepared
		// media refs. Fail closed if a declared attachment is not resolvable; never
		// read raw bytes or paths from the model.
		const attachments: AgentMailAttachment[] = [];
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
				contentType: resolved.mediaType,
				contentBase64: Buffer.from(resolved.bytes).toString("base64"),
			});
		}

		const request: AgentMailSendRequest = {
			from: options.from,
			to,
			subject: options.defaultSubject,
			text: prepared.finalRenderedBody,
			idempotencyKey: prepared.idempotencyKey,
			...(attachments.length > 0 ? { attachments } : {}),
		};

		// At-most-once delivery boundary. Once the AgentMail REST call is
		// dispatched we cannot know whether AgentMail accepted the message, so the
		// outcome here is NOT retryable — neither a thrown sender error nor an error
		// result. A retry would re-POST with no platform-side dedup and could
		// duplicate a message AgentMail already accepted. Matches gmail-transport.ts.
		let result: AgentMailSendResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "agentmail_send_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (result.error) {
			return {
				ok: false,
				code: "agentmail_send_failed",
				reason: result.error,
				retryable: false,
			};
		}

		return {
			ok: true,
			...(result.messageId ? { platformMessageId: result.messageId } : {}),
			// AgentMail exposes only a flat message id; record it so the next reply
			// can thread on it once inbound (CL-1) lands.
			...(result.messageId ? { observedThreadMessageId: result.messageId } : {}),
		};
	}

	async function startListener(): Promise<never> {
		throw new Error(AGENTMAIL_INBOUND_RISK_WRAP_REQUIRED);
	}

	return { channel: "agentmail", send, startListener };
}
