import { describe, expect, it, vi } from "vitest";
import type {
	ApiServerOutboundRequest,
	ApiServerSender,
} from "../../../src/relay/channels/api-server-connector.js";
import {
	type ApiServerEnqueue,
	type ApiServerEnqueueRequest,
	createApiServerSender,
} from "../../../src/relay/channels/api-server-sender.js";

function outboundRequest(
	overrides: Partial<ApiServerOutboundRequest> = {},
): ApiServerOutboundRequest {
	return {
		outboundRef: "edge-out:deadbeef",
		conversationId: "conv-7",
		text: "response payload for the caller",
		attachments: [],
		...overrides,
	};
}

/**
 * Walks an arbitrary JSON value and returns the lowercased string keys/values
 * that contain any of the given lowercased substrings. Uses indexOf, not a
 * regex literal (Write/Edit mangle regex escapes).
 */
function findCredentialMentions(value: unknown, needles: readonly string[]): string[] {
	const hits: string[] = [];
	const visit = (node: unknown): void => {
		if (typeof node === "string") {
			const lowered = node.toLowerCase();
			for (const needle of needles) {
				if (lowered.indexOf(needle) !== -1) hits.push(node);
			}
			return;
		}
		if (Array.isArray(node)) {
			for (const item of node) visit(item);
			return;
		}
		if (node && typeof node === "object") {
			for (const [key, child] of Object.entries(node)) {
				const loweredKey = key.toLowerCase();
				for (const needle of needles) {
					if (loweredKey.indexOf(needle) !== -1) hits.push(key);
				}
				visit(child);
			}
		}
	};
	visit(value);
	return hits;
}

const CREDENTIAL_NEEDLES = ["bearer", "token", "api_key", "apikey", "authorization", "secret"];

describe("createApiServerSender", () => {
	it("returns a function assignable to ApiServerSender", () => {
		const enqueue: ApiServerEnqueue = async () => ({ accepted: true });
		const sender: ApiServerSender = createApiServerSender({ enqueue });
		expect(typeof sender).toBe("function");
	});

	it("forwards the connector request to enqueue verbatim and carries no credential field", async () => {
		let received: ApiServerEnqueueRequest | undefined;
		const enqueue = vi.fn<ApiServerEnqueue>(async (request) => {
			received = request;
			return { accepted: true, deliveryId: "q-123" };
		});

		const sender = createApiServerSender({ enqueue });
		await sender(
			outboundRequest({
				attachments: [
					{
						quarantineId: "q:att-1",
						mediaType: "image/png",
						contentHash: `sha256:${"b".repeat(64)}`,
						sizeBytes: 3,
						bytesBase64: "AAAA",
					},
				],
			}),
		);

		expect(enqueue).toHaveBeenCalledOnce();
		expect(received).toEqual({
			outboundRef: "edge-out:deadbeef",
			conversationId: "conv-7",
			text: "response payload for the caller",
			attachments: [
				{
					quarantineId: "q:att-1",
					mediaType: "image/png",
					contentHash: `sha256:${"b".repeat(64)}`,
					sizeBytes: 3,
					bytesBase64: "AAAA",
				},
			],
		});

		// No credential/token/auth field reached the internal sink.
		expect(findCredentialMentions(received, CREDENTIAL_NEEDLES)).toEqual([]);
	});

	it("maps an accepted enqueue to an ok result with the queue deliveryId", async () => {
		const enqueue: ApiServerEnqueue = async () => ({ accepted: true, deliveryId: "  q-777  " });
		const sender = createApiServerSender({ enqueue });

		const result = await sender(outboundRequest());

		expect(result).toEqual({ ok: true, deliveryId: "q-777" });
	});

	it("maps an accepted enqueue with no deliveryId to a bare ok result", async () => {
		const enqueue: ApiServerEnqueue = async () => ({ accepted: true });
		const sender = createApiServerSender({ enqueue });

		const result = await sender(outboundRequest());

		expect(result).toEqual({ ok: true });
	});

	it("maps a refused enqueue to the failure shape", async () => {
		const enqueue: ApiServerEnqueue = async () => ({ accepted: false });
		const sender = createApiServerSender({ enqueue });

		const result = await sender(outboundRequest());

		expect(result).toEqual({ ok: false });
	});

	it("maps a thrown enqueue to the failure shape (at-most-once, never retryable success)", async () => {
		const enqueue: ApiServerEnqueue = async () => {
			throw new Error("queue down");
		};
		const sender = createApiServerSender({ enqueue });

		const result = await sender(outboundRequest());

		expect(result).toEqual({ ok: false });
	});

	it("fails closed when no enqueue sink is configured", async () => {
		const sender = createApiServerSender({});

		const result = await sender(outboundRequest());

		expect(result).toEqual({ ok: false });
	});
});
