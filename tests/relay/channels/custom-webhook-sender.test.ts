import { describe, expect, it } from "vitest";
import type {
	CustomWebhookSendRequest,
	CustomWebhookSendResult,
} from "../../../src/relay/channels/custom-webhook-connector.js";
import {
	buildCustomWebhookTargetResolver,
	type CredentialProxyPost,
	createCustomWebhookSender,
} from "../../../src/relay/channels/custom-webhook-sender.js";

// Write/Edit mangle regex escapes, so build control-char strings from char codes.
const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);

const CONFIGURED_HOST = "hooks.orders.example";
const CONFIGURED_PATH = "/v1/inbound/orders";

function sendRequest(overrides: Partial<CustomWebhookSendRequest> = {}): CustomWebhookSendRequest {
	return {
		destination: { addressRef: "hook:orders", conversationId: "conv-42" },
		envelope: {
			schemaVersion: "telclaude.edge.custom-webhook.send.v1",
			outboundRef: "edge-out:deadbeef",
			conversationId: "conv-42",
			text: "hello from the relay",
			attachments: [],
		},
		idempotencyKey: "edge-idem:deadbeef",
		...overrides,
	};
}

interface PostCall {
	host: string;
	path: string;
	method?: string;
	body?: string;
	headers?: Record<string, string>;
}

function recordingPost(
	result: { status: number; json: unknown; text: string } = {
		status: 200,
		json: { id: "wh-1" },
		text: '{"id":"wh-1"}',
	},
): CredentialProxyPost & { readonly calls: PostCall[] } {
	const calls: PostCall[] = [];
	const post = async (req: PostCall) => {
		calls.push(req);
		return result;
	};
	return Object.assign(post, { calls });
}

// The relay maps the logical addressRef to the operator-configured {host, path}.
const resolveTarget = (destination: { addressRef: string }) =>
	destination.addressRef === "hook:orders"
		? { host: CONFIGURED_HOST, path: CONFIGURED_PATH }
		: undefined;

describe("custom-webhook sender (relay transport)", () => {
	it("POSTs the envelope JSON to the configured host/path and maps a 2xx to success", async () => {
		const post = recordingPost();
		const sender = createCustomWebhookSender({ post, resolveTarget });

		const result: CustomWebhookSendResult = await sender(sendRequest());

		expect(result).toEqual({ ok: true, status: 200, id: "wh-1" });

		expect(post.calls).toHaveLength(1);
		const call = post.calls[0];
		// Proxy POST hits the host the credential proxy is keyed on + the path.
		expect(call.host).toBe(CONFIGURED_HOST);
		expect(call.path).toBe(CONFIGURED_PATH);
		expect(call.method).toBe("POST");
		expect(call.headers).toEqual({ "Content-Type": "application/json" });

		// The body is the envelope serialized verbatim — nothing else.
		expect(call.body).toBeDefined();
		const sentBody = JSON.parse(call.body ?? "");
		expect(sentBody).toEqual(sendRequest().envelope);
	});

	it("carries NO credential/token/secret field — auth is entirely the injected poster's job", async () => {
		const post = recordingPost();
		const sender = createCustomWebhookSender({ post, resolveTarget });
		await sender(sendRequest());

		const call = post.calls[0];
		// The whole request the transport hands to the proxy must be credential-free.
		const serialized = JSON.stringify(call);
		for (const token of [
			"Bearer",
			"Authorization",
			"token",
			"api_key",
			"apiKey",
			"secret",
			"signature",
		]) {
			expect(serialized.toLowerCase()).not.toContain(token.toLowerCase());
		}
		// No header smuggles a credential in.
		expect(Object.keys(call.headers ?? {})).toEqual(["Content-Type"]);
	});

	it("maps a non-2xx response to the failure shape carrying the observed status", async () => {
		const post = recordingPost({ status: 503, json: { error: "down" }, text: '{"error":"down"}' });
		const sender = createCustomWebhookSender({ post, resolveTarget });

		const result = await sender(sendRequest());

		expect(result).toEqual({ ok: false, status: 503 });
		// The transport still attempted the POST exactly once (at-most-once).
		expect(post.calls).toHaveLength(1);
	});

	it("maps a thrown poster error to the failure shape (at-most-once, no retryable success)", async () => {
		let attempts = 0;
		const post: CredentialProxyPost = async () => {
			attempts += 1;
			throw new Error(`socket hang up${CR}${LF}`);
		};
		const sender = createCustomWebhookSender({ post, resolveTarget });

		const result = await sender(sendRequest());

		expect(result).toEqual({ ok: false });
		expect(attempts).toBe(1);
	});

	it("fails closed WITHOUT posting when the addressRef has no configured webhook", async () => {
		const post = recordingPost();
		const sender = createCustomWebhookSender({ post, resolveTarget });

		const result = await sender(
			sendRequest({ destination: { addressRef: "hook:unknown", conversationId: "conv-42" } }),
		);

		expect(result).toEqual({ ok: false });
		expect(post.calls).toHaveLength(0);
	});

	it("reports a 2xx with no echoed id as a success without a platform id", async () => {
		const post = recordingPost({ status: 202, json: { accepted: true }, text: "{}" });
		const sender = createCustomWebhookSender({ post, resolveTarget });

		const result = await sender(sendRequest());

		expect(result).toEqual({ ok: true, status: 202 });
	});
});

describe("buildCustomWebhookTargetResolver", () => {
	it("binds the configured addressRef to host + path, PRESERVING the query string", () => {
		const resolve = buildCustomWebhookTargetResolver({
			addressRef: "hook:orders",
			endpoint: "https://hooks.example.test/inbound?team=ops&v=2",
		});
		expect(resolve).not.toBeNull();
		expect(resolve?.({ addressRef: "hook:orders", conversationId: "c1" })).toEqual({
			host: "hooks.example.test",
			path: "/inbound?team=ops&v=2",
		});
	});

	it("returns undefined for an unknown addressRef (no implicit fan-out to the one endpoint)", () => {
		const resolve = buildCustomWebhookTargetResolver({
			addressRef: "hook:orders",
			endpoint: "https://hooks.example.test/inbound",
		});
		expect(resolve?.({ addressRef: "hook:attacker", conversationId: "c1" })).toBeUndefined();
	});

	it("returns null for an unusable endpoint (userinfo, fragment, non-http(s), or unparseable)", () => {
		expect(
			buildCustomWebhookTargetResolver({
				addressRef: "h",
				endpoint: "https://user:pass@hooks.example.test/inbound",
			}),
		).toBeNull();
		expect(
			buildCustomWebhookTargetResolver({
				addressRef: "h",
				endpoint: "https://hooks.example.test/inbound#frag",
			}),
		).toBeNull();
		expect(
			buildCustomWebhookTargetResolver({ addressRef: "h", endpoint: "ftp://hooks.example.test/x" }),
		).toBeNull();
		expect(buildCustomWebhookTargetResolver({ addressRef: "h", endpoint: "not a url" })).toBeNull();
		expect(
			buildCustomWebhookTargetResolver({ addressRef: "   ", endpoint: "https://x.test/y" }),
		).toBeNull();
	});
});
