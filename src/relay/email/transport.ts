/**
 * Transport abstraction behind the email connector. Two concrete
 * implementations land next: a Gmail-API transport (operator's own account,
 * via the existing google-services vault-backed token manager) and an SMTP
 * transport (arbitrary accounts, creds from the vault). Both receive an already
 * relay-composed raw RFC822 message — neither builds headers, so neither can be
 * an injection vector; they only open the socket / call the API.
 */

export interface EmailSendRequest {
	/** Fully composed, CRLF-safe RFC822 message (from the mime composer). */
	readonly rawMime: string;
	readonly from: string;
	readonly to: readonly string[];
	/** Relay-minted idempotency key (prepared.idempotencyKey) for transport-side dedup/logging. */
	readonly idempotencyKey: string;
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
