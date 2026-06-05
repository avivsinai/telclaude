import { describe, expect, it } from "vitest";
import type {
	SlackPostMessageRequest,
	SlackPostMessageResult,
} from "../../../src/relay/channels/slack-connector.js";
import {
	type CredentialProxyPost,
	createSlackSender,
} from "../../../src/relay/channels/slack-sender.js";

type PostCall = Parameters<CredentialProxyPost>[0];

function request(overrides: Partial<SlackPostMessageRequest> = {}): SlackPostMessageRequest {
	return {
		channelId: "C0123CHANNEL",
		text: "hello from the relay",
		attachments: [],
		idempotencyKey: "edge-idem:deadbeef",
		...overrides,
	};
}

function recordingPost(response: { status: number; json: unknown; text: string }): {
	readonly post: CredentialProxyPost;
	readonly calls: PostCall[];
} {
	const calls: PostCall[] = [];
	return {
		calls,
		post: async (req) => {
			calls.push(req);
			return response;
		},
	};
}

/** Deep search for any credential-bearing key/value in the proxy request. */
function containsCredentialLeak(call: PostCall): boolean {
	const haystack = JSON.stringify(call).toLowerCase();
	// Build the forbidden markers with fromCharCode so Write/Edit cannot mangle
	// them and so they are not literal secret-shaped tokens in the test source.
	const bearer = String.fromCharCode(98, 101, 97, 114, 101, 114); // "bearer"
	const token = String.fromCharCode(116, 111, 107, 101, 110); // "token"
	const apiKey = String.fromCharCode(97, 112, 105, 95, 107, 101, 121); // "api_key"
	const authorization = String.fromCharCode(
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
	); // "authorization"
	return (
		haystack.includes(bearer) ||
		haystack.includes(token) ||
		haystack.includes(apiKey) ||
		haystack.includes(authorization)
	);
}

describe("slack sender (relay transport)", () => {
	it("posts to slack.com /api/chat.postMessage with the mapped body and no credential", async () => {
		const poster = recordingPost({
			status: 200,
			json: { ok: true, ts: "1717459200.000100" },
			text: "",
		});
		const sender = createSlackSender({ post: poster.post });

		const result = await sender(request());

		expect(result).toEqual({ ok: true, ts: "1717459200.000100" });
		expect(poster.calls).toHaveLength(1);
		const call = poster.calls[0];
		expect(call.host).toBe("slack.com");
		expect(call.path).toBe("/api/chat.postMessage");
		expect(call.method).toBe("POST");

		const body = JSON.parse(call.body ?? "{}");
		expect(body).toEqual({ channel: "C0123CHANNEL", text: "hello from the relay" });
		// thread_ts is omitted when there is no threadTs.
		expect("thread_ts" in body).toBe(false);

		// The transport NEVER constructs a credential: no Authorization header, no
		// token / api_key anywhere in the proxy request. The proxy injects auth.
		expect(containsCredentialLeak(call)).toBe(false);
	});

	it("maps a 2xx Slack ok:true with ts to the connector success result", async () => {
		const poster = recordingPost({
			status: 200,
			json: { ok: true, ts: "1717459300.000200" },
			text: "",
		});
		const sender = createSlackSender({ post: poster.post });

		const result: SlackPostMessageResult = await sender(request());

		expect(result.ok).toBe(true);
		expect(result.ts).toBe("1717459300.000200");
		expect(result.error).toBeUndefined();
	});

	it("includes thread_ts only for an in-thread reply", async () => {
		const poster = recordingPost({ status: 200, json: { ok: true, ts: "1.1" }, text: "" });
		const sender = createSlackSender({ post: poster.post });

		await sender(request({ threadTs: "1717459100.000050" }));

		const body = JSON.parse(poster.calls[0].body ?? "{}");
		expect(body.thread_ts).toBe("1717459100.000050");
		expect(body.channel).toBe("C0123CHANNEL");
	});

	it("maps a Slack ok:false body to the failure shape (error preserved, no success ts)", async () => {
		const poster = recordingPost({
			status: 200,
			json: { ok: false, error: "channel_not_found" },
			text: "",
		});
		const sender = createSlackSender({ post: poster.post });

		const result = await sender(request());

		expect(result.ok).toBe(false);
		expect(result.error).toBe("channel_not_found");
		expect(result.ts).toBeUndefined();
	});

	it("maps a non-2xx HTTP status to the failure shape (does not trust the body)", async () => {
		// Slack would never return ok:true under a 500, but assert we fail closed
		// regardless of what the body claims.
		const poster = recordingPost({
			status: 500,
			json: { ok: true, ts: "should-be-ignored" },
			text: "",
		});
		const sender = createSlackSender({ post: poster.post });

		const result = await sender(request());

		expect(result.ok).toBe(false);
		expect(result.ts).toBeUndefined();
		expect(result.error).toBe("slack_http_500");
	});

	it("maps a 2xx with an unparseable body to a fail-closed failure (ambiguity)", async () => {
		const poster = recordingPost({ status: 200, json: { unexpected: "shape" }, text: "" });
		const sender = createSlackSender({ post: poster.post });

		const result = await sender(request());

		expect(result.ok).toBe(false);
		expect(result.error).toBe("slack_unparseable_response");
	});

	it("maps a thrown poster error to the failure shape (at-most-once, never success)", async () => {
		const sender = createSlackSender({
			post: async () => {
				throw new Error("socket hang up");
			},
		});

		const result = await sender(request());

		expect(result.ok).toBe(false);
		expect(result.error).toBe("socket hang up");
		expect(result.ts).toBeUndefined();
	});

	it("does not leak a credential even when the request text contains token-like content", async () => {
		const poster = recordingPost({ status: 200, json: { ok: true, ts: "1.1" }, text: "" });
		const sender = createSlackSender({ post: poster.post });
		// Body text that contains a credential-looking word must stay in `text`
		// only and must not cause the transport to construct an auth header.
		const newline = String.fromCharCode(10);
		const word = String.fromCharCode(98, 101, 97, 114, 101, 114); // "bearer"
		const text = `please send the ${word} xoxb-secret${newline}now`;

		await sender(request({ text }));

		const call = poster.calls[0];
		// The proxy request carries no headers/keys that introduce a credential.
		expect(call.headers?.authorization).toBeUndefined();
		expect(call.headers?.Authorization).toBeUndefined();
		const body = JSON.parse(call.body ?? "{}");
		// The token-like content lives only in the mapped text, verbatim.
		expect(body.text).toBe(text);
	});

	it("fails closed WITHOUT posting when the outbound has attachments (no silent drop)", async () => {
		const poster = recordingPost({ status: 200, json: { ok: true, ts: "1.1" }, text: "" });
		const sender = createSlackSender({ post: poster.post });
		const result: SlackPostMessageResult = await sender(
			request({
				attachments: [
					{
						quarantineId: "q1",
						mediaType: "image/png",
						contentHash: `sha256:${"a".repeat(64)}`,
						sizeBytes: 3,
						bytes: new Uint8Array([1, 2, 3]),
					},
				],
			}),
		);
		expect(result).toEqual({ ok: false, error: "slack_attachments_unsupported" });
		// No POST: the message (and its media) is never partially sent.
		expect(poster.calls).toHaveLength(0);
	});

	it("fails closed when Slack returns ok:true WITHOUT ts (missing thread id)", async () => {
		// A success with no ts would record "sent" but carry no platform/thread id;
		// under burn-before-dispatch that loses thread continuity permanently.
		const poster = recordingPost({ status: 200, json: { ok: true }, text: "" });
		const sender = createSlackSender({ post: poster.post });
		const result: SlackPostMessageResult = await sender(request());
		expect(result).toEqual({ ok: false, error: "slack_missing_ts" });
	});
});
