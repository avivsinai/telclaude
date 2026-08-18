/**
 * Transport abstraction behind the email connector. Two concrete
 * implementations land next: a Gmail-API transport (operator's own account,
 * via the existing google-services vault-backed token manager) and an SMTP
 * transport (arbitrary accounts, creds from the vault). Both receive an already
 * relay-composed raw RFC822 message — neither builds headers, so neither can be
 * an injection vector; they only open the socket / call the API.
 */

/**
 * The edge authorization that produced this send, carried verbatim from the
 * PreparedOutbound by the connector. A transport that delivers through an
 * approval-gated sidecar (the Gmail transport → google-services) uses it to
 * mint a request-bound approval token AFTER the upstream side-effect ledger
 * burn. The one-shot/replay primitive remains that ledger burn; this context is
 * signed PROVENANCE binding the sidecar token 1:1 to the burned authorization,
 * never a replay key. A credentials-based transport (SMTP) ignores it.
 */
export interface OutboundAuthorizationContext {
	/** Operator actor id (record.actorId / prepared.authorizingActor.actorId) — the sidecar x-actor-user-id. */
	readonly actorUserId: string;
	/** Edge prepared ref (prepared.outboundRef). */
	readonly outboundRef: string;
	/** Side-effect ledger record ref (prepared.sideEffectLedgerRef); 1:1 with the burned authorization. */
	readonly sideEffectLedgerRef: string;
	/** Edge prepared hash binding the rendered destination + body + media. */
	readonly edgePreparedHash: string;
}

export interface EmailSendRequest {
	/** Fully composed, CRLF-safe RFC822 message (from the mime composer). */
	readonly rawMime: string;
	readonly from: string;
	readonly to: readonly string[];
	/** Relay-minted idempotency key (prepared.idempotencyKey) for transport-side dedup/logging. */
	readonly idempotencyKey: string;
	/** Edge authorization provenance for sidecar-gated transports (Gmail). */
	readonly authorization: OutboundAuthorizationContext;
}

export type EmailSendResult =
	| { readonly ok: true; readonly platformMessageId?: string }
	| {
			readonly ok: false;
			/** Stable code, e.g. "transport_unavailable", "auth_expired", "rejected". */
			readonly code: string;
			readonly reason?: string;
			readonly retryable: boolean;
	  };

export interface EmailTransport {
	readonly kind: "gmail-api" | "smtp";
	send(request: EmailSendRequest): Promise<EmailSendResult>;
}
