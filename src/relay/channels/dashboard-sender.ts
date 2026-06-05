import type {
	DashboardSinkRequest,
	DashboardSinkResult,
	DashboardSinkSender,
} from "./dashboard-connector.js";

/**
 * Relay-side transport (injected sender) for the INTERNAL "dashboard" channel.
 *
 * The dashboard connector is a pure delivery sink that builds a typed
 * DashboardSinkRequest and hands it to `options.send` (a DashboardSinkSender).
 * This factory PRODUCES that sender: it adapts the connector's request onto the
 * relay's in-process dashboard message store via an injected `deps.deliver`,
 * then maps the store's result back to a DashboardSinkResult.
 *
 * Trust model:
 * - Dashboard is an INTERNAL sink. There is NO external platform, NO external
 *   credential, NO credential proxy. The transport holds no tokens and performs
 *   no network auth — delivery is a single injected in-process call.
 * - Fail closed: if `deps.deliver` is absent the sender returns the failure
 *   shape (ok:false, non-retryable) without attempting delivery.
 * - At-most-once boundary: once `deliver` is dispatched we cannot know whether
 *   the store recorded the message, so a thrown deliver error maps to a
 *   non-retryable ambiguous failure (a retry could double-post). Only the
 *   pre-call "no sink configured" failure leaves nothing dispatched, and even
 *   that stays non-retryable — a missing sink is a wiring fault, not a transient
 *   one. (Mirrors gmail-transport.ts / dashboard-connector.ts.)
 */

const DASHBOARD_DELIVER_REJECTED_REASON = "dashboard message store rejected the outbound";

/** Result the in-process dashboard message store returns from a deliver call. */
export type DashboardStoreDeliverResult =
	| {
			readonly stored: true;
			/** Store-assigned id for the recorded message, surfaced as deliveryId. */
			readonly messageId?: string;
	  }
	| {
			readonly stored: false;
			readonly code?: string;
			readonly reason?: string;
			readonly retryable?: boolean;
	  };

/**
 * Injected internal sink. The relay wires this to the in-process dashboard
 * message store. It takes the SAME typed request the connector built (no
 * re-derivation here) and reports whether the store recorded it. No creds, no
 * proxy, no network.
 */
export type DashboardStoreDeliver = (
	request: DashboardSinkRequest,
) => Promise<DashboardStoreDeliverResult>;

export interface CreateDashboardSenderDeps {
	/**
	 * Pushes the outbound onto the relay dashboard message store. Optional so the
	 * sender can fail closed when the store is not wired in this deployment.
	 */
	readonly deliver?: DashboardStoreDeliver;
}

export function createDashboardSender(deps: CreateDashboardSenderDeps): DashboardSinkSender {
	return async function send(request: DashboardSinkRequest): Promise<DashboardSinkResult> {
		const { deliver } = deps;
		// Fail closed: an unwired store must never silently swallow an authorized
		// outbound. Nothing was dispatched, but a missing sink is a configuration
		// fault, not a transient one — do not signal retryable success.
		if (!deliver) {
			return {
				ok: false,
				code: "dashboard_sink_unconfigured",
				reason: "no dashboard message store is wired for delivery",
				retryable: false,
			};
		}

		// At-most-once boundary. Once deliver is dispatched the store may have
		// recorded the message even on a thrown error, so a thrown deliver error is
		// non-retryable — a retry could double-post the same outbound.
		let result: DashboardStoreDeliverResult;
		try {
			result = await deliver(request);
		} catch (error) {
			return {
				ok: false,
				code: "dashboard_deliver_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (!result.stored) {
			return {
				ok: false,
				code: result.code ?? "dashboard_deliver_failed",
				reason: result.reason ?? DASHBOARD_DELIVER_REJECTED_REASON,
				retryable: result.retryable ?? false,
			};
		}

		return {
			ok: true,
			...(result.messageId ? { deliveryId: result.messageId } : {}),
		};
	};
}
