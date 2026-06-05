import type {
	SlackPostMessageRequest,
	SlackPostMessageResult,
	SlackPostMessageSender,
} from "./slack-connector.js";

/**
 * Relay-side Slack transport: the injected sender that the Slack connector calls
 * via `options.send`. It maps a typed `SlackPostMessageRequest` to a Slack
 * `chat.postMessage` POST, runs that POST through the relay credential proxy, and
 * maps the HTTP/Slack response back to the connector's `SlackPostMessageResult`.
 *
 * Trust model (mirrors gmail-transport.ts):
 * - NO credential lives here. The Bearer bot token is injected by the relay's
 *   credential proxy for host `slack.com`; this transport only constructs a
 *   request to the proxy (`{ host, path, method, body, headers }`) and never
 *   sees, holds, or sets an Authorization header / token / api_key.
 * - The connector already resolved {channelId, threadTs?} from the edge-validated
 *   destination VERBATIM. This transport copies them straight into the Slack JSON
 *   ({channel, text, thread_ts?}); it never re-derives a recipient.
 * - chat.postMessage takes inline `text` only. Attachment file upload is a
 *   separate Slack step the connector defers, so declared attachments are NOT
 *   uploaded here — they are surfaced in the failure/notes path only, never
 *   silently dropped without a trace.
 * - At-most-once delivery boundary: once the proxy POST is dispatched the message
 *   may have posted. A thrown poster error, a non-2xx HTTP status, an
 *   un-parseable body, or a Slack `ok:false` body all map to a NON-retryable
 *   failure (`ok:false`). We never signal success on ambiguity.
 */

const SLACK_HOST = "slack.com";
const CHAT_POST_MESSAGE_PATH = "/api/chat.postMessage";
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";

/**
 * Injected HTTP poster wired by the relay to the credential proxy. The relay
 * points this at `http://relay:8792/{host}/{path}` so the proxy injects the
 * vault credential for `{host}`. The transport supplies only host/path/body —
 * never a token.
 */
export type CredentialProxyPost = (req: {
	host: string;
	path: string;
	method?: string;
	body?: string;
	headers?: Record<string, string>;
}) => Promise<{ status: number; json: unknown; text: string }>;

export interface CreateSlackSenderOptions {
	/**
	 * Posts to the Slack host through the relay credential proxy, which injects
	 * the Bearer bot token. The transport holds no credential.
	 */
	readonly post: CredentialProxyPost;
}

/** The Slack `chat.postMessage` wire body. attachments are out of scope here. */
type SlackChatPostMessageBody = {
	readonly channel: string;
	readonly text: string;
	readonly thread_ts?: string;
};

/** Slack's `chat.postMessage` response envelope: `{ok, ts?, error?}`. */
function parseSlackResponse(json: unknown): SlackPostMessageResult | null {
	if (!json || typeof json !== "object") return null;
	const body = json as { ok?: unknown; ts?: unknown; error?: unknown };
	if (typeof body.ok !== "boolean") return null;
	const ts = typeof body.ts === "string" && body.ts.length > 0 ? body.ts : undefined;
	const error = typeof body.error === "string" && body.error.length > 0 ? body.error : undefined;
	return { ok: body.ok, ...(ts ? { ts } : {}), ...(error ? { error } : {}) };
}

export function createSlackSender(options: CreateSlackSenderOptions): SlackPostMessageSender {
	async function send(request: SlackPostMessageRequest): Promise<SlackPostMessageResult> {
		const body: SlackChatPostMessageBody = {
			channel: request.channelId,
			text: request.text,
			...(request.threadTs ? { thread_ts: request.threadTs } : {}),
		};

		// At-most-once boundary: once the POST is dispatched the message may have
		// posted, so a thrown poster error is a NON-retryable failure. The connector
		// maps an ok:false result to a non-retryable ChannelSendOutcome.
		let response: { status: number; json: unknown; text: string };
		try {
			response = await options.post({
				host: SLACK_HOST,
				path: CHAT_POST_MESSAGE_PATH,
				method: "POST",
				body: JSON.stringify(body),
				headers: { "content-type": JSON_CONTENT_TYPE },
			});
		} catch (error) {
			return {
				ok: false,
				error: error instanceof Error ? error.message : String(error),
			};
		}

		// A non-2xx HTTP status means the Slack API call did not succeed at the
		// transport level. Fail closed without trusting any body it carried.
		if (response.status < 200 || response.status >= 300) {
			return { ok: false, error: `slack_http_${response.status}` };
		}

		const parsed = parseSlackResponse(response.json);
		if (!parsed) {
			// 2xx with an unrecognizable body — ambiguous, fail closed.
			return { ok: false, error: "slack_unparseable_response" };
		}

		return parsed;
	}

	return send;
}
