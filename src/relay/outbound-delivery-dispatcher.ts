import {
	type DeliveryReceipt,
	DeliveryReceiptSchema,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
} from "../hermes/edge-adapter-contract.js";
import type { AttachmentQuarantineStore } from "./attachment-quarantine-store.js";
import type { ChannelSendOutcome, OutboundDeliveryContext } from "./edge-channel-connector.js";
import type { EdgeOutboundExecutorRegistry } from "./edge-outbound-executor-registry.js";

/**
 * Outbound delivery dispatcher (CL-0 seam). This is the ONLY thing
 * `TelclaudeEdgeRuntime.executeOutbound` calls after authorization:
 *
 *   if (this.deliver) return await this.deliver(prepared);
 *
 * It takes a {@link PreparedOutbound} ONLY (executeOutbound has no
 * RelayConversation to hand it). It resolves the conversation itself via the
 * injected {@link OutboundConversationContextResolver}, binds an owner-scoped
 * attachment resolver, dispatches to the channel connector, and maps the
 * connector outcome to a contract-valid {@link DeliveryReceipt}.
 *
 * It imports NEITHER the side-effect ledger NOR ledger-execute — it is a pure
 * transport sink. Authorization, binding, hash re-derivation, replay, and
 * idempotency are all decided upstream before this runs.
 */

export interface OutboundConversationContext {
	/** Relay conversation token this prepared outbound belongs to (binds attachments). */
	readonly conversationToken: string;
	/**
	 * Relay-observed prior transport message ids for the thread, oldest-first.
	 * Built only from authenticated traffic; never from the model body.
	 */
	readonly threadMessageIds: readonly string[];
}

/** Resolves a prepared outbound to its conversation context (token + thread ids). */
export type OutboundConversationContextResolver = (
	prepared: PreparedOutbound,
) => Promise<OutboundConversationContext | null>;

/** Optional hook to record the delivered transport id back onto the conversation thread. */
export type OutboundDeliveredHook = (
	prepared: PreparedOutbound,
	context: OutboundConversationContext,
	outcome: Extract<ChannelSendOutcome, { ok: true }>,
) => Promise<void>;

/**
 * Optional sink for a post-send bookkeeping failure (e.g. recording the thread
 * message id failed). The transport side effect has ALREADY happened, so the
 * dispatcher still returns a "sent" receipt — this hook only surfaces the
 * bookkeeping error for logging/alerting. It must not throw.
 */
export type OutboundDeliveredErrorHook = (
	prepared: PreparedOutbound,
	context: OutboundConversationContext,
	outcome: Extract<ChannelSendOutcome, { ok: true }>,
	error: unknown,
) => void;

/**
 * Optional sink for a connector send FAILURE. The contract {@link DeliveryReceipt}
 * carries only a coarse deliveryStatus (no failure code / retryable flag), so CL-0
 * is deliberately receipt-only: the dispatcher maps any failure to a "failed"
 * receipt and surfaces the connector's classification (code, retryable) through
 * this hook. Retry orchestration consuming code/retryable lives OUTSIDE this seam.
 */
export type OutboundSendFailureHook = (
	prepared: PreparedOutbound,
	failure: Extract<ChannelSendOutcome, { ok: false }>,
) => void;

export type OutboundDeliveryDispatcher = (prepared: PreparedOutbound) => Promise<DeliveryReceipt>;

export interface CreateOutboundDeliveryDispatcherOptions {
	readonly registry: EdgeOutboundExecutorRegistry;
	readonly resolveConversation: OutboundConversationContextResolver;
	readonly quarantineStore: AttachmentQuarantineStore;
	readonly now?: () => number;
	readonly onDelivered?: OutboundDeliveredHook;
	readonly onDeliveredError?: OutboundDeliveredErrorHook;
	readonly onSendFailure?: OutboundSendFailureHook;
}

export function createOutboundDeliveryDispatcher(
	options: CreateOutboundDeliveryDispatcherOptions,
): OutboundDeliveryDispatcher {
	const now = options.now ?? Date.now;

	function receipt(
		prepared: PreparedOutbound,
		status: DeliveryReceipt["deliveryStatus"],
		extra: { platformMessageId?: string; failed?: boolean },
	): DeliveryReceipt {
		const iso = new Date(now()).toISOString();
		return DeliveryReceiptSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
			outboundRef: prepared.outboundRef,
			...(extra.platformMessageId ? { platformMessageId: extra.platformMessageId } : {}),
			deliveryStatus: status,
			timestamps: {
				observedAt: iso,
				...(extra.failed ? { failedAt: iso } : { sentAt: iso }),
			},
			retry: {
				attempt: 1,
				maxAttempts: prepared.retryPolicy.maxAttempts,
				idempotencyKey: prepared.idempotencyKey,
			},
		});
	}

	return async function dispatch(prepared: PreparedOutbound): Promise<DeliveryReceipt> {
		const connector = options.registry.get(prepared.channel);
		if (!connector) {
			// Misconfiguration: authorized to send on a channel with no transport. Fail closed.
			return receipt(prepared, "failed", { failed: true });
		}

		const context = await options.resolveConversation(prepared);
		if (!context) {
			// Conversation no longer resolvable post-authorization. Fail closed.
			return receipt(prepared, "failed", { failed: true });
		}

		// Scope attachment release to THIS prepared outbound's media refs (keyed by
		// quarantineId → expected contentHash). A connector cannot resolve an arbitrary
		// same-conversation attachment that is not attached to this send, and a content
		// drift between the stored bytes and the prepared ref fails closed.
		const allowedAttachments = new Map(
			prepared.mediaRefs.map((media) => [media.quarantineId, media.contentHash]),
		);
		const deliveryContext: OutboundDeliveryContext = {
			prepared,
			threadMessageIds: context.threadMessageIds,
			resolveAttachment: (quarantineId) => {
				const expectedContentHash = allowedAttachments.get(quarantineId);
				if (expectedContentHash === undefined) return Promise.resolve(null);
				const released = options.quarantineStore.resolve(quarantineId, {
					conversationToken: context.conversationToken,
				});
				if (released && released.contentHash !== expectedContentHash) {
					return Promise.resolve(null);
				}
				return Promise.resolve(released);
			},
		};

		let outcome: ChannelSendOutcome;
		try {
			outcome = await connector.send(deliveryContext);
		} catch {
			// A throwing transport is a failed attempt, not a crash of the runtime.
			return receipt(prepared, "failed", { failed: true });
		}

		if (!outcome.ok) {
			// Surface the connector's failure classification (code/retryable) out-of-band;
			// the receipt itself is coarse "failed" (the contract carries no failure code).
			options.onSendFailure?.(prepared, outcome);
			return receipt(prepared, "failed", { failed: true });
		}

		// The transport side effect has now happened. onDelivered is post-send
		// bookkeeping (recording the thread message id); its failure must NOT turn a
		// real send into a dispatch rejection (that would create retry/duplicate-send
		// ambiguity). Surface the error and still return the "sent" receipt.
		if (options.onDelivered) {
			try {
				await options.onDelivered(prepared, context, outcome);
			} catch (error) {
				options.onDeliveredError?.(prepared, context, outcome, error);
			}
		}
		return receipt(prepared, "sent", { platformMessageId: outcome.platformMessageId });
	};
}
