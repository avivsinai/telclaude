import type {
	ChannelSendOutcome,
	EdgeChannelConnector,
	OutboundDeliveryContext,
} from "../edge-channel-connector.js";

/**
 * Outbound dashboard connector. INTERNAL delivery sink that pushes an authorized
 * outbound to the relay web dashboard message sink. There is no external
 * platform and no external credential: the relay later wires `options.send` to
 * the in-process dashboard sink. This file is a pure delivery sink invoked by
 * the dispatcher AFTER authorization — it never resolves approvals, touches the
 * side-effect ledger, the conversation store, the pairing store, or the vault.
 *
 * Recipient comes from `prepared.resolvedDestination` VERBATIM (edge-validated,
 * membership-bound); the connector never re-derives it from the body or the
 * conversation members. Attachment bytes are released only through the
 * owner-bound resolver scoped to this conversation. Inbound stays dark until
 * CL-1 risk wrapping is wired (`startListener` throws).
 */

export const DASHBOARD_INBOUND_RISK_WRAP_REQUIRED =
	"dashboard inbound listener requires CL-1 risk wrapping before edge.ingest";

/** Attachment payload handed to the dashboard sink (relay-resolved, owner-bound). */
export type DashboardSinkAttachment = {
	readonly quarantineId: string;
	readonly mediaType: string;
	readonly contentHash: string;
	readonly sizeBytes: number;
	readonly bytesBase64: string;
};

/**
 * The typed request the connector pushes to the dashboard message sink. The
 * brief's core fields — conversationId, outboundRef, text, at — plus the verbatim
 * resolved destination target and the owner-bound attachments.
 */
export type DashboardSinkRequest = {
	/** Relay conversation this outbound belongs to (from resolvedDestination). */
	readonly conversationId: string;
	/** Stable per-outbound id (idempotency / correlation handle for the sink). */
	readonly outboundRef: string;
	/** The final rendered body (already authorized; never re-rendered here). */
	readonly text: string;
	/** ISO timestamp the relay handed the message to the sink. */
	readonly at: string;
	/**
	 * Verbatim delivery target from the edge destination: the threadId for a
	 * "thread" destination or the addressRef for an "address" destination. The
	 * connector never re-derives this from the body or conversation members.
	 */
	readonly target: string;
	/** Destination kind that produced `target`, carried through for the sink. */
	readonly targetKind: "thread" | "address";
	readonly idempotencyKey: string;
	readonly attachments: readonly DashboardSinkAttachment[];
};

/** Result the injected dashboard sink returns; mapped to ChannelSendOutcome. */
export type DashboardSinkResult =
	| {
			readonly ok: true;
			readonly deliveryId?: string;
	  }
	| {
			readonly ok: false;
			readonly code?: string;
			readonly reason?: string;
			readonly retryable?: boolean;
	  };

/**
 * Injected sink. The relay wires this to the in-process dashboard message sink.
 * The connector constructs a typed request and calls this — it holds no
 * credentials and knows nothing about the sink's transport. Mirrors
 * gmail-transport.ts's injected `callProvider`.
 */
export type DashboardSinkSender = (request: DashboardSinkRequest) => Promise<DashboardSinkResult>;

export interface CreateDashboardConnectorOptions {
	readonly send: DashboardSinkSender;
	/** Clock for the `at` stamp; injected for deterministic tests. */
	readonly now?: () => number;
}

export function createDashboardConnector(
	options: CreateDashboardConnectorOptions,
): EdgeChannelConnector {
	const now = options.now ?? (() => Date.now());

	async function send(context: OutboundDeliveryContext): Promise<ChannelSendOutcome> {
		const { prepared, resolveAttachment } = context;
		const destination = prepared.resolvedDestination;

		// Build the target from the edge destination VERBATIM. The dashboard sink is
		// internal, so both "thread" and "address" destinations are deliverable; an
		// "actor" destination has no dashboard-resolvable target. Fail closed on an
		// unsupported kind or a missing destination field — never re-derive the
		// recipient from the body or conversation members.
		let target: string;
		let targetKind: "thread" | "address";
		if (destination.kind === "thread") {
			if (!destination.threadId) {
				return {
					ok: false,
					code: "dashboard_missing_thread_id",
					reason: "thread destination has no threadId",
					retryable: false,
				};
			}
			target = destination.threadId;
			targetKind = "thread";
		} else if (destination.kind === "address") {
			if (!destination.addressRef) {
				return {
					ok: false,
					code: "dashboard_missing_address_ref",
					reason: "address destination has no addressRef",
					retryable: false,
				};
			}
			target = destination.addressRef;
			targetKind = "address";
		} else {
			return {
				ok: false,
				code: "dashboard_unsupported_destination",
				reason: `dashboard cannot deliver to a ${destination.kind} destination`,
				retryable: false,
			};
		}

		// The dashboard message sink is conversation-scoped; the edge resolves the
		// conversation id onto the destination. Fail closed if it is absent rather
		// than inferring it from the thread/address target.
		const conversationId = destination.conversationId?.trim();
		if (!conversationId) {
			return {
				ok: false,
				code: "dashboard_missing_conversation_id",
				reason: "resolved destination has no conversationId for the dashboard sink",
				retryable: false,
			};
		}

		// Attachments ONLY via the owner-bound resolver, scoped to prepared.mediaRefs.
		// Bytes/paths are NEVER read from the model. Fail closed if a declared
		// attachment is not resolvable for this conversation.
		const attachments: DashboardSinkAttachment[] = [];
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

		const request: DashboardSinkRequest = {
			conversationId,
			outboundRef: prepared.outboundRef,
			text: prepared.finalRenderedBody,
			at: new Date(now()).toISOString(),
			target,
			targetKind,
			idempotencyKey: prepared.idempotencyKey,
			attachments,
		};

		// At-most-once delivery boundary. Once the sink call is dispatched we cannot
		// know whether the dashboard recorded the message, so a thrown sender error is
		// non-retryable — a retry could double-post. (Matches gmail-transport.ts.)
		let result: DashboardSinkResult;
		try {
			result = await options.send(request);
		} catch (error) {
			return {
				ok: false,
				code: "dashboard_send_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (!result.ok) {
			return {
				ok: false,
				code: result.code ?? "dashboard_send_failed",
				...(result.reason ? { reason: result.reason } : {}),
				retryable: result.retryable ?? false,
			};
		}

		return {
			ok: true,
			...(result.deliveryId ? { platformMessageId: result.deliveryId } : {}),
		};
	}

	async function startListener(): Promise<never> {
		throw new Error(DASHBOARD_INBOUND_RISK_WRAP_REQUIRED);
	}

	return { channel: "dashboard", send, startListener };
}
