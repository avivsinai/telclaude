import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	CUSTOM_WEBHOOK_INBOUND_RISK_WRAP_REQUIRED,
	CUSTOM_WEBHOOK_SEND_SCHEMA_VERSION,
	type CustomWebhookSendRequest,
	type CustomWebhookSendResult,
	createCustomWebhookConnector,
} from "../../../src/relay/channels/custom-webhook-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = "a".repeat(64);
const CONTENT_HASH = `sha256:${"b".repeat(64)}`;
// Write/Edit mangle regex escapes, so build control-char strings from char codes.
const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "custom-webhook",
		resolvedDestination: {
			kind: "address",
			addressRef: "hook:orders",
			conversationId: "conv-42",
		},
		finalRenderedBody: "hello from the relay",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "custom-webhook", principalId: "relay:pairing-authority" },
			identityAssurance: "strong_link",
			scopes: [],
			revocation: { revoked: false },
		},
		edgePreparedHash: HEX64,
		policyResult: { decision: "allowed", reason: "authorized" },
		approvalRequirement: { required: false },
		idempotencyKey: "edge-idem:deadbeef",
		sideEffectLedgerRef: "edge-ledger:deadbeef",
		createdAt: "2026-06-04T00:00:00.000Z",
		retryPolicy: { maxAttempts: 3, backoff: "exponential", deadLetterAfterAttempts: 5 },
		...overrides,
	});
}

function attachmentRef(quarantineId: string, mediaType: string): AttachmentRef {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
		quarantineId,
		mediaType,
		scanState: "clean",
		sizeBytes: 3,
		contentHash: CONTENT_HASH,
		trustLabel: "trusted",
		expiresAt: "2026-06-05T00:00:00.000Z",
		lifecycle: { state: "authorized", authorizedFor: ["conv-42"] },
	};
}

function context(
	prepared: PreparedOutbound,
	opts: {
		attachments?: Record<string, QuarantinedBytes | null>;
	} = {},
): OutboundDeliveryContext {
	return {
		prepared,
		threadMessageIds: [],
		resolveAttachment: async (quarantineId) => opts.attachments?.[quarantineId] ?? null,
	};
}

function recordingSender(
	result: CustomWebhookSendResult = { ok: true, id: "wh-1", status: 200 },
): CustomWebhookSender & { readonly sent: CustomWebhookSendRequest[] } {
	const sent: CustomWebhookSendRequest[] = [];
	const send = async (request: CustomWebhookSendRequest) => {
		sent.push(request);
		return result;
	};
	return Object.assign(send, { sent });
}

type CustomWebhookSender = (request: CustomWebhookSendRequest) => Promise<CustomWebhookSendResult>;

describe("custom-webhook connector", () => {
	it("builds the envelope from resolvedDestination verbatim and maps the platform id", async () => {
		const sender = recordingSender();
		const connector = createCustomWebhookConnector({ send: sender });
		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("wh-1");
		expect(outcome.observedThreadMessageId).toBe("wh-1");

		expect(sender.sent).toHaveLength(1);
		const request = sender.sent[0];
		// Destination keying comes verbatim from prepared.resolvedDestination.
		expect(request.destination).toEqual({ addressRef: "hook:orders", conversationId: "conv-42" });
		expect(request.idempotencyKey).toBe("edge-idem:deadbeef");
		expect(request.envelope).toEqual({
			schemaVersion: CUSTOM_WEBHOOK_SEND_SCHEMA_VERSION,
			outboundRef: "edge-out:deadbeef",
			conversationId: "conv-42",
			text: "hello from the relay",
			attachments: [],
		});
	});

	it("emits attachment metadata only (mediaType, sizeBytes, contentHash) via the owner-bound resolver", async () => {
		const sender = recordingSender();
		const connector = createCustomWebhookConnector({ send: sender });
		const ref = attachmentRef("tc-quarantine:1", "application/pdf");
		await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), {
				attachments: {
					"tc-quarantine:1": {
						quarantineId: "tc-quarantine:1",
						mediaType: "application/pdf",
						bytes: new TextEncoder().encode("abc"),
						contentHash: CONTENT_HASH,
					},
				},
			}),
		);
		const envelope = sender.sent[0].envelope;
		expect(envelope.attachments).toEqual([
			{ mediaType: "application/pdf", sizeBytes: 3, contentHash: CONTENT_HASH },
		]);
		// No raw bytes / paths leak into the envelope.
		expect(JSON.stringify(envelope)).not.toContain("bytes");
	});

	it("fails closed on an unsupported destination kind (never calls the sender)", async () => {
		const sender = recordingSender();
		const connector = createCustomWebhookConnector({ send: sender });
		const outcome = await connector.send(
			context(preparedOutbound({ resolvedDestination: { kind: "thread", threadId: "t1" } })),
		);
		expect(outcome).toMatchObject({
			ok: false,
			code: "custom_webhook_requires_address_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when the address destination has no addressRef", async () => {
		const sender = recordingSender();
		const connector = createCustomWebhookConnector({ send: sender });
		// Bypass the schema (which rejects a blank addressRef): the connector is a
		// separate trust layer and must fail closed even if such a prepared reaches it.
		const base = preparedOutbound();
		const noAddress = {
			...base,
			resolvedDestination: { kind: "address", conversationId: "conv-42" },
		} as PreparedOutbound;
		const outcome = await connector.send(context(noAddress));
		expect(outcome).toMatchObject({
			ok: false,
			code: "custom_webhook_missing_address",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when the destination has no conversationId to key on", async () => {
		const sender = recordingSender();
		const connector = createCustomWebhookConnector({ send: sender });
		const base = preparedOutbound();
		const noConversation = {
			...base,
			resolvedDestination: { kind: "address", addressRef: "hook:orders" },
		} as PreparedOutbound;
		const outcome = await connector.send(context(noConversation));
		expect(outcome).toMatchObject({
			ok: false,
			code: "custom_webhook_missing_conversation",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const sender = recordingSender();
		const connector = createCustomWebhookConnector({ send: sender });
		const ref = attachmentRef("tc-quarantine:missing", "image/png");
		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);
		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing", retryable: false });
		expect(sender.sent).toHaveLength(0);
	});

	it("maps a thrown sender error to a non-retryable ambiguous failure (at-most-once)", async () => {
		const failing: CustomWebhookSender = async () => {
			throw new Error(`socket hang up${CR}${LF}`);
		};
		const connector = createCustomWebhookConnector({ send: failing });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "custom_webhook_send_ambiguous",
			retryable: false,
		});
		if (outcome.ok) throw new Error("expected failure");
		expect(outcome.reason).toContain("socket hang up");
	});

	it("maps a non-ok platform result to a non-retryable rejection carrying the status", async () => {
		const sender = recordingSender({ ok: false, status: 503 });
		const connector = createCustomWebhookConnector({ send: sender });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "custom_webhook_send_rejected",
			retryable: false,
		});
		if (outcome.ok) throw new Error("expected failure");
		expect(outcome.reason).toContain("503");
	});

	it("startListener throws because inbound stays dark until CL-1", async () => {
		const connector = createCustomWebhookConnector({ send: recordingSender() });
		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			CUSTOM_WEBHOOK_INBOUND_RISK_WRAP_REQUIRED,
		);
	});
});
