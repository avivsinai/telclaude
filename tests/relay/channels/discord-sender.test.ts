import { describe, expect, it } from "vitest";
import type { DiscordCreateMessageRequest } from "../../../src/relay/channels/discord-connector.js";
import {
	type CredentialProxyPost,
	createDiscordSender,
} from "../../../src/relay/channels/discord-sender.js";

// Token-shaped needles built from char codes so the fixture never embeds the
// literal strings (Write/Edit could also mangle regex escapes — none used here).
const BOT_PREFIX = String.fromCharCode(66, 111, 116, 32); // "Bot "
const BEARER_PREFIX = String.fromCharCode(66, 101, 97, 114, 101, 114); // "Bearer"
const AUTHORIZATION_KEY = String.fromCharCode(
	65,
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
); // "Authorization"

interface PostCall {
	host: string;
	path: string;
	method?: string;
	body?: string;
	headers?: Record<string, string>;
}

interface PostResponse {
	status: number;
	json: unknown;
	text: string;
}

function recordingPost(response: PostResponse | (() => Promise<PostResponse>)): {
	calls: PostCall[];
	post: CredentialProxyPost;
} {
	const calls: PostCall[] = [];
	const post: CredentialProxyPost = async (req) => {
		calls.push(req);
		if (typeof response === "function") return response();
		return response;
	};
	return { calls, post };
}

function request(
	overrides: Partial<DiscordCreateMessageRequest> = {},
): DiscordCreateMessageRequest {
	return {
		channelId: "123456789012345678",
		content: "hello from the relay",
		attachments: [],
		idempotencyKey: "edge-idem:deadbeef",
		outboundRef: "edge-out:deadbeef",
		...overrides,
	};
}

describe("discord sender (relay transport)", () => {
	it("POSTs to discord.com create-message with the mapped JSON body and no credential field", async () => {
		const { calls, post } = recordingPost({ status: 200, json: { id: "discord-msg-1" }, text: "" });
		const sender = createDiscordSender({ post });

		const result = await sender(request());

		// 2xx with { id } maps to the connector success result.
		expect(result).toEqual({ id: "discord-msg-1" });

		expect(calls).toHaveLength(1);
		const call = calls[0];
		expect(call.host).toBe("discord.com");
		// Channel id from the request VERBATIM, in the path.
		expect(call.path).toBe("/api/v10/channels/123456789012345678/messages");
		expect(call.method).toBe("POST");

		// Body is exactly { content } (no message_reference when no reply target).
		expect(JSON.parse(call.body ?? "")).toEqual({ content: "hello from the relay" });

		// HARD CONSTRAINT: the transport carries NO credential. It supplies only a
		// content-type header; the proxy injects the bot token out of band.
		const serialized = JSON.stringify(call);
		expect(serialized.includes(BOT_PREFIX)).toBe(false);
		expect(serialized.includes(BEARER_PREFIX)).toBe(false);
		expect(serialized.toLowerCase().includes("token")).toBe(false);
		expect(call.headers?.[AUTHORIZATION_KEY]).toBeUndefined();
	});

	it("maps messageReference to a Discord message_reference object", async () => {
		const { calls, post } = recordingPost({ status: 200, json: { id: "discord-msg-2" }, text: "" });
		const sender = createDiscordSender({ post });

		await sender(request({ messageReference: "reply-target-id" }));

		expect(JSON.parse(calls[0].body ?? "")).toEqual({
			content: "hello from the relay",
			message_reference: { message_id: "reply-target-id" },
		});
	});

	it("maps a non-2xx response to the failure shape with Discord's error message", async () => {
		const { calls, post } = recordingPost({
			status: 403,
			json: { message: "Missing Access", code: 50001 },
			text: "",
		});
		const sender = createDiscordSender({ post });

		const result = await sender(request());

		expect(result).toEqual({ error: "Missing Access" });
		// The call was attempted exactly once (at-most-once boundary).
		expect(calls).toHaveLength(1);
	});

	it("falls back to status when a non-2xx body has no message", async () => {
		const { post } = recordingPost({ status: 500, json: {}, text: "" });
		const sender = createDiscordSender({ post });

		const result = await sender(request());

		expect(result).toMatchObject({ error: expect.stringContaining("500") });
	});

	it("maps a thrown poster error to the failure shape (ambiguous, non-success)", async () => {
		const { post } = recordingPost(async () => {
			throw new Error("ECONNRESET after dispatch");
		});
		const sender = createDiscordSender({ post });

		const result = await sender(request());

		expect(result).toMatchObject({ error: expect.stringContaining("ECONNRESET after dispatch") });
		// On ambiguity we never signal success.
		expect("id" in result).toBe(false);
	});

	it("fails closed when a 2xx body carries no message id (no success on ambiguity)", async () => {
		const { post } = recordingPost({ status: 200, json: { not_an_id: true }, text: "" });
		const sender = createDiscordSender({ post });

		const result = await sender(request());

		expect("id" in result).toBe(false);
		expect(result).toMatchObject({ error: expect.stringContaining("no message id") });
	});

	it("retargets the proxied host when one is configured, still credential-free", async () => {
		const { calls, post } = recordingPost({ status: 201, json: { id: "discord-msg-3" }, text: "" });
		const sender = createDiscordSender({ post, host: "discord.proxy.internal" });

		const result = await sender(request());

		expect(result).toEqual({ id: "discord-msg-3" });
		expect(calls[0].host).toBe("discord.proxy.internal");
		expect(JSON.stringify(calls[0]).includes(BOT_PREFIX)).toBe(false);
	});

	it("fails closed WITHOUT posting when the outbound has attachments (no silent drop)", async () => {
		const { calls, post } = recordingPost({ status: 200, json: { id: "m1" }, text: "" });
		const sender = createDiscordSender({ post });
		const result = await sender(
			request({
				attachments: [
					{
						quarantineId: "q1",
						mediaType: "image/png",
						contentHash: `sha256:${"a".repeat(64)}`,
						bytes: new Uint8Array([1, 2, 3]),
					},
				],
			}),
		);
		expect(result).toEqual({ error: "discord_attachments_unsupported" });
		expect(calls).toHaveLength(0);
	});
});
