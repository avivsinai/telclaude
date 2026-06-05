import { describe, expect, it } from "vitest";
import type {
	SocialGatewayMedia,
	SocialGatewayPostRequest,
} from "../../../src/relay/channels/social-gateway-connector.js";
import {
	type CredentialProxyPost,
	createSocialGatewaySender,
} from "../../../src/relay/channels/social-gateway-sender.js";

const HOST = "gateway.social.internal";
const PATH = "/v1/post";

// charCode helpers instead of regex literals (Write/Edit mangle regex escapes).
const SHA256_HASH = `sha256:${String.fromCharCode(98).repeat(64)}`; // sha256:"b"*64
// "Bearer", "token", "api_key" assembled from char codes so the literals never
// appear in this source — the assertion below proves they never appear in the
// serialized request either.
const BEARER = String.fromCharCode(66, 101, 97, 114, 101, 114); // "Bearer"
const TOKEN = String.fromCharCode(116, 111, 107, 101, 110); // "token"
const API_KEY = String.fromCharCode(97, 112, 105, 95, 107, 101, 121); // "api_key"

function media(): SocialGatewayMedia {
	return {
		quarantineId: "q1",
		mediaType: "image/png",
		contentHash: SHA256_HASH,
		sizeBytes: 3,
		bytes: new Uint8Array([1, 2, 3]),
	};
}

function postRequest(overrides: Partial<SocialGatewayPostRequest> = {}): SocialGatewayPostRequest {
	return {
		targetKind: "actor",
		target: "social:gateway-account",
		text: "hello from the public persona",
		media: [],
		outboundRef: "edge-out:deadbeef",
		idempotencyKey: "idem:1",
		conversationId: "c1",
		...overrides,
	};
}

interface Capture {
	calls: Array<{
		host: string;
		path: string;
		method?: string;
		body?: string;
		headers?: Record<string, string>;
	}>;
}

function harness(impl: () => Promise<{ status: number; json: unknown; text: string }>): {
	cap: Capture;
	post: CredentialProxyPost;
} {
	const cap: Capture = { calls: [] };
	const post: CredentialProxyPost = async (req) => {
		cap.calls.push({ ...req });
		return impl();
	};
	return { cap, post };
}

describe("social gateway sender (relay-side transport)", () => {
	it("POSTs to the configured host/path with the mapped body and NO credential field", async () => {
		const { cap, post } = harness(async () => ({
			status: 200,
			json: { post_id: "p-123" },
			text: "{}",
		}));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		await send(postRequest({ media: [media()] }));

		expect(cap.calls).toHaveLength(1);
		const call = cap.calls[0];
		expect(call.host).toBe(HOST);
		expect(call.path).toBe(PATH);
		expect(call.method).toBe("POST");

		const body = JSON.parse(call.body ?? "{}");
		// The brief's mapped fields are present and verbatim from the request.
		expect(body.target).toBe("social:gateway-account");
		expect(body.targetKind).toBe("actor");
		expect(body.text).toBe("hello from the public persona");
		expect(body.outboundRef).toBe("edge-out:deadbeef");
		expect(body.idempotencyKey).toBe("idem:1");
		expect(body.conversationId).toBe("c1");
		// Media bytes are base64-encoded (JSON-safe), metadata preserved.
		expect(body.media).toHaveLength(1);
		expect(body.media[0]).toMatchObject({
			quarantineId: "q1",
			mediaType: "image/png",
			contentHash: SHA256_HASH,
			sizeBytes: 3,
			bytesBase64: Buffer.from(new Uint8Array([1, 2, 3])).toString("base64"),
		});

		// NO credential anywhere in the dispatched request — auth is the proxy's job.
		const serialized = JSON.stringify(call);
		expect(serialized).not.toContain(BEARER);
		expect(serialized).not.toContain(TOKEN);
		expect(serialized).not.toContain(API_KEY);
		expect(serialized).not.toContain("authorization");
		expect(serialized).not.toContain("Authorization");
	});

	it("omits conversationId from the body when absent", async () => {
		const { cap, post } = harness(async () => ({
			status: 201,
			json: { id: "p-9" },
			text: "{}",
		}));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		await send(postRequest({ conversationId: undefined }));

		const body = JSON.parse(cap.calls[0].body ?? "{}");
		expect(body).not.toHaveProperty("conversationId");
	});

	it("maps a 2xx { post_id } to Result.postId", async () => {
		const { post } = harness(async () => ({
			status: 200,
			json: { post_id: "p-abc" },
			text: "{}",
		}));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		const result = await send(postRequest());
		expect(result).toEqual({ postId: "p-abc" });
	});

	it("maps a 2xx { id } (alternate key) to Result.postId", async () => {
		const { post } = harness(async () => ({
			status: 201,
			json: { id: "p-xyz" },
			text: "{}",
		}));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		const result = await send(postRequest());
		expect(result).toEqual({ postId: "p-xyz" });
	});

	it("maps a non-2xx response to the failure shape (error set, no postId)", async () => {
		const { post } = harness(async () => ({
			status: 422,
			json: { error: "target not found" },
			text: "{}",
		}));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		const result = await send(postRequest());
		expect(result.postId).toBeUndefined();
		expect(result.error).toBe("target not found");
	});

	it("maps a non-2xx without an error body to a status-derived failure", async () => {
		const { post } = harness(async () => ({ status: 503, json: null, text: "" }));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		const result = await send(postRequest());
		expect(result.postId).toBeUndefined();
		expect(result.error).toContain("503");
	});

	it("fails closed on a 2xx WITHOUT a post id (ambiguity must not read as success)", async () => {
		const { post } = harness(async () => ({ status: 200, json: { ok: true }, text: "{}" }));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		const result = await send(postRequest());
		expect(result.postId).toBeUndefined();
		expect(result.error).toBeTruthy();
	});

	it("maps a thrown poster error to the failure shape (at-most-once: no fabricated postId)", async () => {
		const { post } = harness(async () => {
			throw new Error("ECONNRESET");
		});
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		const result = await send(postRequest());
		expect(result.postId).toBeUndefined();
		expect(result.error).toBe("ECONNRESET");
	});

	it("never serializes a credential field into the request even on the media path", async () => {
		const { cap, post } = harness(async () => ({
			status: 200,
			json: { post_id: "p-1" },
			text: "{}",
		}));
		const send = createSocialGatewaySender({ post, host: HOST, path: PATH });

		await send(postRequest({ media: [media(), media()] }));

		const serialized = JSON.stringify(cap.calls[0]);
		// The transport carries content-type only; no auth header is set here.
		expect(serialized).not.toContain(BEARER);
		expect(serialized).not.toContain(TOKEN);
		expect(serialized).not.toContain(API_KEY);
	});
});
