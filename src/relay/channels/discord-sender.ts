import type {
	DiscordCreateMessageRequest,
	DiscordMessageSender,
	DiscordSendResult,
} from "./discord-connector.js";

/**
 * Relay-side Discord transport (the injected sender the discord connector plugs
 * into via `options.send`). It maps a typed {@link DiscordCreateMessageRequest}
 * to a credential-proxy POST against the Discord create-message endpoint, then
 * maps the HTTP response back to the connector's {@link DiscordSendResult}.
 *
 * No credentials live here. Auth is supplied entirely by the injected
 * {@link CredentialProxyPost}: the relay wires `deps.post` to the vault HTTP
 * credential proxy (http://relay:8792/{host}/{path}), which injects
 * `Authorization: Bot <token>` out of band for `discord.com`. This transport
 * never holds, reads, or forwards a bot token — it only constructs the host,
 * path, and JSON body. (Mirrors gmail-transport's injected `callProvider`.)
 *
 * At-most-once boundary: once the POST is dispatched the relay cannot know
 * whether Discord created the message, so a thrown poster error and any
 * non-2xx / malformed body both map to the failure shape (`{ error }`). The
 * connector turns that into a NON-retryable ChannelSendOutcome — a retry could
 * duplicate a message Discord already accepted.
 */

const DISCORD_HOST = "discord.com";
const DISCORD_API_VERSION = "v10";

/**
 * Injected HTTP poster wired by the relay to the credential proxy. The proxy
 * resolves the credential for `host` and injects the auth header; this transport
 * supplies only host/path/body and never sees the token.
 */
export type CredentialProxyPost = (req: {
	host: string;
	path: string;
	method?: string;
	body?: string;
	headers?: Record<string, string>;
}) => Promise<{ status: number; json: unknown; text: string }>;

export interface CreateDiscordSenderOptions {
	/** Credential-proxy poster (relay-wired to the vault proxy for discord.com). */
	readonly post: CredentialProxyPost;
	/**
	 * Override the proxied platform host. Defaults to `discord.com`; exists so a
	 * staging/proxy deployment can retarget without code changes. Never a
	 * credential.
	 */
	readonly host?: string;
}

/** The Discord create-message wire body: `{ content, message_reference? }`. */
interface DiscordCreateMessageBody {
	readonly content: string;
	readonly message_reference?: { readonly message_id: string };
}

function buildPath(channelId: string): string {
	return `/api/${DISCORD_API_VERSION}/channels/${encodeURIComponent(channelId)}/messages`;
}

function buildBody(request: DiscordCreateMessageRequest): DiscordCreateMessageBody {
	const base: DiscordCreateMessageBody = { content: request.content };
	if (request.messageReference) {
		return { ...base, message_reference: { message_id: request.messageReference } };
	}
	return base;
}

/**
 * Extract the created Discord message id from a 2xx body. Discord returns the
 * created message object `{ id, ... }`; a non-string / empty id is treated as a
 * failure (we never signal success on ambiguity).
 */
function extractMessageId(json: unknown): string | undefined {
	if (json && typeof json === "object" && "id" in json) {
		const id = (json as { id?: unknown }).id;
		if (typeof id === "string" && id.length > 0) return id;
	}
	return undefined;
}

/**
 * Derive a failure reason from a non-2xx Discord response. Discord error bodies
 * carry a `message` field (e.g. "Missing Access"); fall back to the raw text or
 * the status code so the connector can surface something actionable.
 */
function failureReason(status: number, json: unknown, text: string): string {
	if (json && typeof json === "object" && "message" in json) {
		const message = (json as { message?: unknown }).message;
		if (typeof message === "string" && message.length > 0) return message;
	}
	if (text.length > 0) return text;
	return `discord responded with status ${status}`;
}

export function createDiscordSender(options: CreateDiscordSenderOptions): DiscordMessageSender {
	const host = options.host ?? DISCORD_HOST;

	return async function send(request: DiscordCreateMessageRequest): Promise<DiscordSendResult> {
		// This create-message path posts JSON only (no multipart file upload yet).
		// Fail closed on declared attachments rather than silently dropping them:
		// with at-most-once burn-before-dispatch, a text-only "success" would lose
		// the media irrecoverably.
		if (request.attachments.length > 0) {
			return { error: "discord_attachments_unsupported" };
		}
		const path = buildPath(request.channelId);
		const body = JSON.stringify(buildBody(request));

		let response: { status: number; json: unknown; text: string };
		try {
			response = await options.post({
				host,
				path,
				method: "POST",
				body,
				headers: { "Content-Type": "application/json" },
			});
		} catch (error) {
			// Ambiguous: the POST may have reached Discord and created the message.
			// Surface a failure so the connector fails closed (non-retryable).
			return { error: error instanceof Error ? error.message : String(error) };
		}

		if (response.status < 200 || response.status >= 300) {
			return { error: failureReason(response.status, response.json, response.text) };
		}

		const id = extractMessageId(response.json);
		if (id === undefined) {
			return {
				error: `discord ${response.status} response carried no message id`,
			};
		}

		return { id };
	};
}
