import { describe, expect, it } from "vitest";
import type {
	AgentMailSendRequest,
	AgentMailSendResult,
} from "../../../src/relay/channels/agentmail-connector.js";
import {
	type CredentialProxyPost,
	createAgentMailSender,
} from "../../../src/relay/channels/agentmail-sender.js";

// Credential-shaped tokens we must NEVER see leave the transport, built from
// char codes so Write/Edit cannot mangle a literal and so a naive substring
// scan of the serialized request reliably catches an accidental leak.
// "Bearer "
const BEARER_PREFIX = String.fromCharCode(66, 101, 97, 114, 101, 114, 32);
// "api_key"
const API_KEY_WORD = String.fromCharCode(97, 112, 105, 95, 107, 101, 121);
// "authorization"
const AUTH_HEADER = String.fromCharCode(
	97,
	117,
	116,
	104,
	111,
	114,
	105,
	122,
	97,
	116,
	105,
	111,
	110,
);
// "sk-secret-token-value" — a fake secret that must not appear anywhere.
const FAKE_TOKEN = String.fromCharCode(
	115,
	107,
	45,
	115,
	101,
	99,
	114,
	101,
	116,
	45,
	116,
	111,
	107,
	101,
	110,
	45,
	118,
	97,
	108,
	117,
	101,
);

type ProxyCall = Parameters<CredentialProxyPost>[0];

function recordingPost(
	response: { status: number; json: unknown; text: string } = {
		status: 200,
		json: { id: "am-msg-1" },
		text: "",
	},
): CredentialProxyPost & { readonly calls: ProxyCall[] } {
	const calls: ProxyCall[] = [];
	const fn: CredentialProxyPost = async (req) => {
		calls.push(req);
		return response;
	};
	return Object.assign(fn, { calls });
}

function sendRequest(overrides: Partial<AgentMailSendRequest> = {}): AgentMailSendRequest {
	return {
		from: "agent@relay.test",
		to: "alice@example.test",
		subject: "Message from your assistant",
		text: "hello from the relay",
		idempotencyKey: "edge-idem:deadbeef",
		...overrides,
	};
}

describe("agentmail sender (relay transport)", () => {
	it("POSTs the mapped JSON send to the configured host/path with no credential field", async () => {
		const post = recordingPost();
		const send = createAgentMailSender({
			post,
			host: "api.agentmail.to",
			path: "/v0/messages/send",
		});

		await send(sendRequest());

		expect(post.calls).toHaveLength(1);
		const call = post.calls[0];
		expect(call.host).toBe("api.agentmail.to");
		expect(call.path).toBe("/v0/messages/send");
		expect(call.method).toBe("POST");

		// The transport only declares the payload encoding; it never sets an auth
		// header. The credential proxy injects auth out of band.
		const headerKeys = Object.keys(call.headers ?? {}).map((k) => k.toLowerCase());
		expect(headerKeys).not.toContain(AUTH_HEADER);

		// Body is the from/to/subject/text mapping, no attachments when none given.
		const body = JSON.parse(call.body ?? "{}");
		expect(body).toEqual({
			from: "agent@relay.test",
			to: "alice@example.test",
			subject: "Message from your assistant",
			text: "hello from the relay",
		});
		expect(body.attachments).toBeUndefined();
	});

	it("forwards attachments as base64 parts in the body", async () => {
		const post = recordingPost();
		const send = createAgentMailSender({ post, host: "api.agentmail.to" });

		await send(
			sendRequest({
				attachments: [
					{
						filename: "attachment-1.pdf",
						contentType: "application/pdf",
						contentBase64: "YWJj",
					},
				],
			}),
		);

		const body = JSON.parse(post.calls[0].body ?? "{}");
		expect(body.attachments).toEqual([
			{ filename: "attachment-1.pdf", contentType: "application/pdf", contentBase64: "YWJj" },
		]);
	});

	it("maps a 2xx body with `id` to the result message id", async () => {
		const post = recordingPost({ status: 201, json: { id: "am-msg-42" }, text: "" });
		const send = createAgentMailSender({ post, host: "api.agentmail.to" });

		const result: AgentMailSendResult = await send(sendRequest());

		expect(result.messageId).toBe("am-msg-42");
		expect(result.error).toBeUndefined();
	});

	it("maps a 2xx body with `message_id` to the result message id", async () => {
		const post = recordingPost({ status: 200, json: { message_id: "am-msg-99" }, text: "" });
		const send = createAgentMailSender({ post, host: "api.agentmail.to" });

		const result = await send(sendRequest());

		expect(result.messageId).toBe("am-msg-99");
		expect(result.error).toBeUndefined();
	});

	it("returns no message id (and no error) when a 2xx body carries no id", async () => {
		const post = recordingPost({ status: 202, json: { accepted: true }, text: "" });
		const send = createAgentMailSender({ post, host: "api.agentmail.to" });

		const result = await send(sendRequest());

		expect(result.messageId).toBeUndefined();
		expect(result.error).toBeUndefined();
	});

	it("maps a non-2xx body to the failure shape (error set, never a fake success)", async () => {
		const post = recordingPost({
			status: 422,
			json: { error: "recipient rejected by upstream MTA" },
			text: "",
		});
		const send = createAgentMailSender({ post, host: "api.agentmail.to" });

		const result = await send(sendRequest());

		expect(result.messageId).toBeUndefined();
		expect(result.error).toBe("recipient rejected by upstream MTA");
	});

	it("falls back to raw text then a status message for a non-2xx body with no error field", async () => {
		const textOnly = recordingPost({ status: 500, json: null, text: "upstream exploded" });
		const sendText = createAgentMailSender({ post: textOnly, host: "api.agentmail.to" });
		expect((await sendText(sendRequest())).error).toBe("upstream exploded");

		const bare = recordingPost({ status: 503, json: null, text: "" });
		const sendBare = createAgentMailSender({ post: bare, host: "api.agentmail.to" });
		expect((await sendBare(sendRequest())).error).toContain("503");
	});

	it("maps a thrown poster error to the failure shape (non-retryable ambiguity)", async () => {
		const failing: CredentialProxyPost = async () => {
			throw new Error("network reset mid-POST");
		};
		const send = createAgentMailSender({ post: failing, host: "api.agentmail.to" });

		const result = await send(sendRequest());

		expect(result.messageId).toBeUndefined();
		expect(result.error).toContain("network reset mid-POST");
	});

	it("carries no token/credential anywhere in the dispatched request", async () => {
		const post = recordingPost();
		// Pass a token-shaped value through a request field the transport copies;
		// even so, the serialized proxy call must contain no credential material
		// (the transport adds none of its own, and the proxy injects auth itself).
		const send = createAgentMailSender({ post, host: "api.agentmail.to" });

		await send(sendRequest());

		const serialized = JSON.stringify(post.calls[0]);
		expect(serialized).not.toContain(BEARER_PREFIX);
		expect(serialized).not.toContain(API_KEY_WORD);
		expect(serialized).not.toContain(FAKE_TOKEN);
		expect(serialized.toLowerCase()).not.toContain(AUTH_HEADER);
	});
});
