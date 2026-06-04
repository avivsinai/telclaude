import { createHash } from "node:crypto";
import type { ApprovalTokenInput } from "../approval-token.js";
import type { ProviderProxyRequest, ProviderProxyResponse } from "../provider-proxy.js";
import type { EmailSendRequest, EmailSendResult, EmailTransport } from "./transport.js";

/**
 * Gmail outbound transport. It delivers a relay-composed message through the
 * google-services sidecar gmail.send action — the relay never holds the Gmail
 * OAuth credential (the vault injects it inside the credential proxy / sidecar).
 *
 * Trust model (agreed with the authorization owner):
 * - The one-shot / replay primitive is the upstream side-effect ledger burn
 *   (ledger.verify → markExecuted). This transport runs AFTER that burn.
 * - gmail.send is an action-type provider op, so the sidecar independently
 *   requires a request-bound approval token. This transport mints a SEPARATE
 *   google-services token (it does NOT reuse the side-effect ledger token as
 *   the sidecar bearer), scoped to gmail.send with params = { raw }.
 * - paramsHash binds the EXACT raw message: the same { raw } object is used to
 *   mint the token and to call the sidecar, so a tampered body fails the
 *   sidecar's hash check.
 * - approvalNonce is deterministic, derived from the burned record's identity
 *   (outboundRef + sideEffectLedgerRef + edgePreparedHash) so the token is 1:1
 *   with the edge authorization. It is signed provenance, not a replay key.
 */

const GOOGLE_PROVIDER_ID = "google";
const GMAIL_SERVICE = "gmail";
const GMAIL_SEND_ACTION = "send";
const PROVIDER_FETCH_PATH = "/v1/fetch";
const APPROVAL_NONCE_DOMAIN = "edge-outbound-google-send";

/** The relay provider proxy call (proxyProviderRequest), injected for testing. */
export type GmailSidecarProviderCall = (
	request: ProviderProxyRequest,
) => Promise<ProviderProxyResponse>;

/**
 * Mints a vault-signed google-services approval token. The relay wires this to
 * `(input) => generateApprovalToken(input, vaultClient)`; generateApprovalToken
 * fixes providerId="google" and the aud/domain internally, so the transport
 * supplies only the action-scoped claims. Not the record-bearing provider
 * issuer (the transport runs downstream of the dispatcher and has no ledger
 * record — only the prepared authorization provenance).
 */
export type GmailApprovalTokenSigner = (input: ApprovalTokenInput) => Promise<string>;

export interface CreateGmailEmailTransportOptions {
	/** Mints the google-services sidecar approval token (vault-signed). */
	readonly issueApprovalToken: GmailApprovalTokenSigner;
	/** Forwards the fetch to the google-services sidecar via the relay proxy. */
	readonly callProvider: GmailSidecarProviderCall;
}

function deriveApprovalNonce(authorization: EmailSendRequest["authorization"]): string {
	return createHash("sha256")
		.update(
			`${APPROVAL_NONCE_DOMAIN}:${authorization.outboundRef}:${authorization.sideEffectLedgerRef}:${authorization.edgePreparedHash}`,
		)
		.digest("hex");
}

function extractGmailMessageId(data: unknown): string | undefined {
	if (data && typeof data === "object" && "id" in data) {
		const id = (data as { id?: unknown }).id;
		if (typeof id === "string" && id.length > 0) return id;
	}
	return undefined;
}

export function createGmailEmailTransport(
	options: CreateGmailEmailTransportOptions,
): EmailTransport {
	async function send(request: EmailSendRequest): Promise<EmailSendResult> {
		const { actorUserId } = request.authorization;
		// Defense in depth: the connector already fails closed on a missing actor,
		// but never call the sidecar without an operator identity to bind.
		if (!actorUserId) {
			return {
				ok: false,
				code: "missing_authorizing_actor",
				reason: "gmail send has no operator actor id to authorize against",
				retryable: false,
			};
		}

		const raw = Buffer.from(request.rawMime, "utf-8").toString("base64url");
		// The SAME params object mints the token and is sent to the sidecar, so the
		// approval-token paramsHash binds the exact bytes delivered.
		const params = { raw };
		const approvalNonce = deriveApprovalNonce(request.authorization);

		let approvalToken: string;
		try {
			approvalToken = await options.issueApprovalToken({
				service: GMAIL_SERVICE,
				action: GMAIL_SEND_ACTION,
				params,
				actorUserId,
				// Self-account send: the operator's own Gmail, no distinct subject.
				subjectUserId: null,
				approvalNonce,
			});
		} catch (error) {
			return {
				ok: false,
				code: "approval_token_unavailable",
				reason: error instanceof Error ? error.message : String(error),
				retryable: true,
			};
		}

		// At-most-once delivery boundary. Once the sidecar call is dispatched we
		// cannot know whether Gmail accepted the message, so NOTHING from here on is
		// retryable — neither a thrown transport error nor an error result. A retry
		// would compose a fresh Message-ID and re-send with no sidecar dedupe, which
		// could duplicate an email Gmail already accepted on the first attempt. Only
		// the pre-call token-mint failure above is retryable (no message left the
		// relay). Exactly-once (retryable) delivery via a sidecar idempotency-key
		// dedupe store + deterministic Message-ID is a tracked follow-up.
		let response: ProviderProxyResponse;
		try {
			response = await options.callProvider({
				providerId: GOOGLE_PROVIDER_ID,
				path: PROVIDER_FETCH_PATH,
				method: "POST",
				body: JSON.stringify({ service: GMAIL_SERVICE, action: GMAIL_SEND_ACTION, params }),
				userId: actorUserId,
				approvalToken,
				// Pre-approved by the ledger burn — a sidecar denial must not mint a
				// legacy /approve nonce.
				approvalMode: "preapproved-ledger",
			});
		} catch (error) {
			return {
				ok: false,
				code: "gmail_send_ambiguous",
				reason: error instanceof Error ? error.message : String(error),
				retryable: false,
			};
		}

		if (response.status !== "ok") {
			return {
				ok: false,
				code: response.errorCode ?? "gmail_send_failed",
				...(response.error ? { reason: response.error } : {}),
				retryable: false,
			};
		}

		const messageId = extractGmailMessageId(response.data);
		return { ok: true, ...(messageId ? { platformMessageId: messageId } : {}) };
	}

	return { kind: "gmail-api", send };
}
