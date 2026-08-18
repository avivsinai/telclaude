import type {
	AgentMailSender,
	AgentMailSendRequest,
	AgentMailSendResult,
} from "./agentmail-connector.js";

/**
 * Relay-side AgentMail transport (the injected sender that
 * {@link createAgentMailConnector}'s `options.send` plugs into).
 *
 * The connector builds a typed {@link AgentMailSendRequest} (recipient bound to
 * the membership-validated destination, From/subject from relay config, bytes
 * released only through the owner-bound resolver) and hands it here. This sender
 * maps that request to the AgentMail REST JSON send and maps the HTTP response
 * back to an {@link AgentMailSendResult}.
 *
 * Trust model (mirrors gmail-transport.ts):
 * - NO raw credentials live here. Auth is supplied entirely by the injected
 *   {@link CredentialProxyPost}, which the relay wires to the vault credential
 *   proxy: the proxy looks up the AgentMail API key for `deps.host` and injects
 *   the auth header. This transport never constructs a Bearer/api-key value and
 *   never reads a token from config or env.
 * - At-most-once delivery boundary: once the POST is dispatched we cannot know
 *   whether AgentMail accepted the message, so neither a thrown poster error nor
 *   a non-2xx body is signalled as retryable. The connector already records both
 *   as non-retryable; this sender simply never hides an ambiguous outcome behind
 *   a success result.
 */

/**
 * Injected HTTP poster wired by the relay to the credential proxy. The relay
 * points this at `http://relay:8792/{host}/{path}` for `host`, so the proxy
 * injects the AgentMail credential. The transport supplies only the host, path,
 * and JSON body — never a token or auth header.
 */
export type CredentialProxyPost = (req: {
	host: string;
	path: string;
	method?: string;
	body?: string;
	headers?: Record<string, string>;
}) => Promise<{ status: number; json: unknown; text: string }>;

export interface CreateAgentMailSenderOptions {
	/** Credential-proxy poster; the proxy injects the AgentMail API key. */
	readonly post: CredentialProxyPost;
	/** AgentMail API host (e.g. "api.agentmail.to"). Relay config, not the model. */
	readonly host: string;
	/**
	 * AgentMail send path (e.g. "/v0/messages/send"). Defaults to a versioned
	 * messages-send path; the relay passes the deployment's configured path.
	 */
	readonly path?: string;
}

const DEFAULT_SEND_PATH = "/v0/messages/send";

/** The JSON body shape the AgentMail send endpoint expects. */
interface AgentMailWireBody {
	from: string;
	to: string;
	subject: string;
	text: string;
	attachments?: ReadonlyArray<{
		filename: string;
		contentType: string;
		contentBase64: string;
	}>;
}

function buildWireBody(request: AgentMailSendRequest): AgentMailWireBody {
	return {
		from: request.from,
		to: request.to,
		subject: request.subject,
		text: request.text,
		...(request.attachments && request.attachments.length > 0
			? {
					attachments: request.attachments.map((attachment) => ({
						filename: attachment.filename,
						contentType: attachment.contentType,
						contentBase64: attachment.contentBase64,
					})),
				}
			: {}),
	};
}

/**
 * Extract the platform message id from a 2xx AgentMail send body. AgentMail
 * returns the id as either `id` or `message_id`; accept either, require a
 * non-empty string, and otherwise return undefined (the caller treats a missing
 * id as a non-failure success with no recorded id, never inventing one).
 */
function extractMessageId(json: unknown): string | undefined {
	if (!json || typeof json !== "object") return undefined;
	const record = json as { id?: unknown; message_id?: unknown };
	const candidate = record.id ?? record.message_id;
	if (typeof candidate === "string" && candidate.length > 0) return candidate;
	return undefined;
}

/**
 * Pull a human-readable error string out of a non-2xx AgentMail body, falling
 * back to the raw text and finally a status-coded message. Never throws.
 */
function extractError(json: unknown, text: string, status: number): string {
	if (json && typeof json === "object") {
		const record = json as { error?: unknown; message?: unknown };
		const reason = record.error ?? record.message;
		if (typeof reason === "string" && reason.length > 0) return reason;
	}
	if (text.length > 0) return text;
	return `agentmail send failed with status ${status}`;
}

export function createAgentMailSender(options: CreateAgentMailSenderOptions): AgentMailSender {
	const path = options.path ?? DEFAULT_SEND_PATH;

	return async function send(request: AgentMailSendRequest): Promise<AgentMailSendResult> {
		const body = JSON.stringify(buildWireBody(request));

		let response: { status: number; json: unknown; text: string };
		try {
			response = await options.post({
				host: options.host,
				path,
				method: "POST",
				body,
				// Only declares the payload encoding. The auth header is injected by
				// the credential proxy — this transport never sets it.
				headers: { "content-type": "application/json" },
			});
		} catch (error) {
			// Ambiguous: the POST may have reached AgentMail before the throw.
			return { error: error instanceof Error ? error.message : String(error) };
		}

		if (response.status < 200 || response.status >= 300) {
			return { error: extractError(response.json, response.text, response.status) };
		}

		const messageId = extractMessageId(response.json);
		return messageId ? { messageId } : {};
	};
}
