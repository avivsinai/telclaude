import type {
	CustomWebhookDestination,
	CustomWebhookSender,
	CustomWebhookSendRequest,
	CustomWebhookSendResult,
} from "./custom-webhook-connector.js";

/**
 * Relay-side transport (injected sender) for the operator-configured
 * "custom-webhook" channel. It is the function the connector plugs into via
 * `options.send`. It POSTs the typed `CustomWebhookEnvelope` as JSON to the
 * operator's destination webhook and maps the HTTP outcome back to the
 * connector's `CustomWebhookSendResult`.
 *
 * Credential posture (mirrors gmail-transport's "no raw creds" rule):
 * - The transport NEVER holds a token, signing key, or secret. Auth is entirely
 *   the injected `deps.post`'s responsibility: the relay wires `post` to the
 *   HTTP credential proxy (http://relay:8792/{host}/{path}), which looks up the
 *   per-host credential in the vault and adds the signing header. The body
 *   POSTed here carries no credential field.
 * - The webhook URL is operator config, not transport state. `deps.resolveTarget`
 *   maps the destination's `addressRef` (a logical key like "hook:orders", NOT a
 *   raw URL — see the connector) to the configured `{ host, path }`. The host is
 *   exactly the credential-proxy key, so the proxy injects the right signature.
 *
 * At-most-once delivery boundary (mirrors gmail-transport / slack-connector):
 * once the POST is dispatched we cannot know whether the endpoint accepted the
 * envelope, so a thrown poster error or a non-2xx response maps to the failure
 * shape (`ok: false`). The transport never signals a retryable success on
 * ambiguity — re-POSTing could duplicate a delivery the endpoint already took.
 */

/**
 * Injected HTTP poster wired by the relay to the credential proxy. The relay
 * forwards `http://relay:8792/{host}/{path}` and injects the vault credential
 * (signing header) for `{host}`. The transport supplies host/path/body only and
 * NEVER a credential.
 */
export type CredentialProxyPost = (req: {
	readonly host: string;
	readonly path: string;
	readonly method?: string;
	readonly body?: string;
	readonly headers?: Record<string, string>;
}) => Promise<{ readonly status: number; readonly json: unknown; readonly text: string }>;

/**
 * Operator-configured target for a webhook destination. The relay resolves the
 * destination's `addressRef` to the host the credential proxy is keyed on plus
 * the path on that host. Returning `undefined` means the addressRef has no
 * configured webhook — the transport then fails closed without posting.
 */
export type CustomWebhookTargetResolver = (
	destination: CustomWebhookDestination,
) => { readonly host: string; readonly path: string } | undefined;

export interface CreateCustomWebhookSenderDeps {
	/** Posts through the relay credential proxy (which injects the signing header). */
	readonly post: CredentialProxyPost;
	/** Maps the destination addressRef to the operator-configured {host, path}. */
	readonly resolveTarget: CustomWebhookTargetResolver;
}

/** A 2xx response means the endpoint accepted the envelope. */
function isSuccessStatus(status: number): boolean {
	return status >= 200 && status < 300;
}

/**
 * Best-effort platform message id from the webhook's JSON response. Many webhook
 * receivers echo back an `id` (or `messageId`) for the accepted delivery; absent
 * one, the connector simply records no platform id.
 */
function extractDeliveryId(json: unknown): string | undefined {
	if (!json || typeof json !== "object") return undefined;
	const record = json as Record<string, unknown>;
	for (const key of ["id", "messageId", "deliveryId"]) {
		const value = record[key];
		if (typeof value === "string" && value.length > 0) return value;
	}
	return undefined;
}

export function createCustomWebhookSender(
	deps: CreateCustomWebhookSenderDeps,
): CustomWebhookSender {
	return async function send(request: CustomWebhookSendRequest): Promise<CustomWebhookSendResult> {
		// Fail closed BEFORE posting if the addressRef has no configured webhook.
		const target = deps.resolveTarget(request.destination);
		if (!target) {
			return { ok: false };
		}

		// At-most-once boundary: once the proxy POST is dispatched the endpoint may
		// have accepted the envelope, so a thrown poster error is a non-success
		// failure (the connector treats it as non-retryable). The transport adds no
		// credential — the relay's proxy injects the signing header for `host`.
		let response: { status: number; json: unknown; text: string };
		try {
			response = await deps.post({
				host: target.host,
				path: target.path,
				method: "POST",
				body: JSON.stringify(request.envelope),
				headers: { "Content-Type": "application/json" },
			});
		} catch {
			return { ok: false };
		}

		// Map HTTP {status, ok} -> Result {ok, id?, status}. A non-2xx is a
		// rejection that carries the observed status (the connector surfaces it).
		if (!isSuccessStatus(response.status)) {
			return { ok: false, status: response.status };
		}

		const id = extractDeliveryId(response.json);
		return { ok: true, status: response.status, ...(id ? { id } : {}) };
	};
}
