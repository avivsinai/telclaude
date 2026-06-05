import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	API_SERVER_INBOUND_RISK_WRAP_REQUIRED,
	type ApiServerOutboundRequest,
	type ApiServerSender,
	type ApiServerSendResult,
	createApiServerConnector,
} from "../../../src/relay/channels/api-server-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = "a".repeat(64);

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "api-server",
		resolvedDestination: {
			kind: "address",
			addressRef: "api-caller:client-42",
			conversationId: "conv-7",
		},
		finalRenderedBody: "response payload for the caller",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "api-server", principalId: "relay:pairing-authority" },
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
		contentHash: `sha256:${"b".repeat(64)}`,
		trustLabel: "trusted",
		expiresAt: "2026-06-05T00:00:00.000Z",
		lifecycle: { state: "authorized", authorizedFor: ["conv-7"] },
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
	result: ApiServerSendResult = { ok: true, deliveryId: "delivery-1" },
): ApiServerSender & { readonly sent: ApiServerOutboundRequest[] } {
	const sent: ApiServerOutboundRequest[] = [];
	const send = async (request: ApiServerOutboundRequest): Promise<ApiServerSendResult> => {
		sent.push(request);
		return result;
	};
	return Object.assign(send, { sent });
}

describe("api-server connector", () => {
	it("enqueues to the address response target and maps deliveryId to platformMessageId", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("delivery-1");
		expect(sender.sent).toHaveLength(1);
		expect(sender.sent[0]).toEqual({
			outboundRef: "edge-out:deadbeef",
			conversationId: "conv-7",
			text: "response payload for the caller",
			attachments: [],
		});
	});

	it("enqueues to an actor response target (the bound API caller actor)", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		const outcome = await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: {
						kind: "actor",
						actorId: "api-actor:client-99",
						conversationId: "conv-7",
					},
				}),
			),
		);
		expect(outcome.ok).toBe(true);
		expect(sender.sent).toHaveLength(1);
		expect(sender.sent[0].conversationId).toBe("conv-7");
	});

	it("includes a resolved attachment as base64 bytes scoped to the conversation", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		const ref = attachmentRef("tc-quarantine:1", "application/pdf");
		const bytes = new TextEncoder().encode("abc");
		await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), {
				attachments: {
					"tc-quarantine:1": {
						quarantineId: "tc-quarantine:1",
						mediaType: "application/pdf",
						bytes,
						contentHash: `sha256:${"b".repeat(64)}`,
					},
				},
			}),
		);
		expect(sender.sent[0].attachments).toEqual([
			{
				quarantineId: "tc-quarantine:1",
				mediaType: "application/pdf",
				contentHash: `sha256:${"b".repeat(64)}`,
				sizeBytes: 3,
				bytesBase64: Buffer.from("abc").toString("base64"),
			},
		]);
	});

	it("fails closed for a thread destination (no api-server response sink), never enqueues", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		const outcome = await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "thread", threadId: "t1", conversationId: "conv-7" },
				}),
			),
		);
		expect(outcome).toMatchObject({
			ok: false,
			code: "api_server_unsupported_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when an address destination is missing its addressRef", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		// Bypass the schema (which requires addressRef on an address kind): the
		// connector is a separate trust layer and must fail closed regardless.
		const base = preparedOutbound();
		const noAddress = {
			...base,
			resolvedDestination: { kind: "address", conversationId: "conv-7" },
		} as unknown as PreparedOutbound;
		const outcome = await connector.send(context(noAddress));
		expect(outcome).toMatchObject({
			ok: false,
			code: "api_server_missing_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when the destination has no conversationId to correlate", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		const base = preparedOutbound();
		const noConversation = {
			...base,
			resolvedDestination: { kind: "address", addressRef: "api-caller:client-42" },
		} as unknown as PreparedOutbound;
		const outcome = await connector.send(context(noConversation));
		expect(outcome).toMatchObject({
			ok: false,
			code: "api_server_missing_conversation",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss), never enqueues", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		const ref = attachmentRef("tc-quarantine:missing", "image/png");
		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);
		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing" });
		expect(sender.sent).toHaveLength(0);
	});

	it("maps a non-ok sender result to ok:false, non-retryable (at-most-once)", async () => {
		const sender = recordingSender({ ok: false });
		const connector = createApiServerConnector({ send: sender });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "api_server_enqueue_rejected",
			retryable: false,
		});
	});

	it("maps a thrown sender error to ok:false, non-retryable (ambiguous after dispatch)", async () => {
		const throwingSend: ApiServerSender = async () => {
			throw new Error("queue connection reset");
		};
		const connector = createApiServerConnector({ send: throwingSend });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "api_server_enqueue_ambiguous",
			retryable: false,
		});
		if (outcome.ok) throw new Error("expected failure");
		// charCode-built substring check (no regex literal): the thrown message is
		// surfaced verbatim in the reason.
		const needle = String.fromCharCode(113, 117, 101, 117, 101); // "queue"
		expect(outcome.reason ?? "").toContain(needle);
	});

	it("startListener throws — inbound stays dark until CL-1 risk wrapping", async () => {
		const sender = recordingSender();
		const connector = createApiServerConnector({ send: sender });
		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			API_SERVER_INBOUND_RISK_WRAP_REQUIRED,
		);
	});
});
