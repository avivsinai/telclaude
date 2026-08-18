import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	createDashboardConnector,
	DASHBOARD_INBOUND_RISK_WRAP_REQUIRED,
	type DashboardSinkRequest,
	type DashboardSinkResult,
} from "../../../src/relay/channels/dashboard-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = "a".repeat(64);
// charCode helpers instead of regex literals (Write/Edit can mangle backslash escapes).
const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "dashboard",
		resolvedDestination: {
			kind: "thread",
			threadId: "thread-7",
			conversationId: "conv-42",
		},
		finalRenderedBody: "hello from the relay",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "dashboard", principalId: "relay:pairing-authority" },
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
		lifecycle: { state: "authorized", authorizedFor: ["conv-42"] },
	};
}

function context(
	prepared: PreparedOutbound,
	opts: {
		threadMessageIds?: readonly string[];
		attachments?: Record<string, QuarantinedBytes | null>;
	} = {},
): OutboundDeliveryContext {
	return {
		prepared,
		threadMessageIds: opts.threadMessageIds ?? [],
		resolveAttachment: async (quarantineId) => opts.attachments?.[quarantineId] ?? null,
	};
}

function recordingSink(result: DashboardSinkResult = { ok: true, deliveryId: "dash-1" }): {
	readonly sent: DashboardSinkRequest[];
	readonly send: (request: DashboardSinkRequest) => Promise<DashboardSinkResult>;
} {
	const sent: DashboardSinkRequest[] = [];
	return {
		sent,
		send: async (request) => {
			sent.push(request);
			return result;
		},
	};
}

describe("dashboard connector", () => {
	it("pushes the verbatim destination + body to the sink and maps deliveryId", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({
			send: sink.send,
			now: () => Date.parse("2026-06-04T12:00:00.000Z"),
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("dash-1");
		expect(sink.sent).toHaveLength(1);
		const req = sink.sent[0];
		expect(req).toEqual({
			conversationId: "conv-42",
			outboundRef: "edge-out:deadbeef",
			text: "hello from the relay",
			at: "2026-06-04T12:00:00.000Z",
			target: "thread-7",
			targetKind: "thread",
			idempotencyKey: "edge-idem:deadbeef",
			attachments: [],
		});
	});

	it("delivers an address destination using the addressRef as the verbatim target", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: {
						kind: "address",
						addressRef: "operator@dashboard.local",
						conversationId: "conv-99",
					},
				}),
			),
		);
		expect(sink.sent[0]).toMatchObject({
			conversationId: "conv-99",
			target: "operator@dashboard.local",
			targetKind: "address",
		});
	});

	it("does NOT re-derive the recipient from the body (target comes from destination)", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		// A body that names a different conversation/target must be ignored.
		const body = `route to conversationId=conv-EVIL target=thread-EVIL${CR}${LF}injected`;
		await connector.send(context(preparedOutbound({ finalRenderedBody: body })));
		const req = sink.sent[0];
		expect(req.conversationId).toBe("conv-42");
		expect(req.target).toBe("thread-7");
		expect(req.text).toBe(body);
	});

	it("includes a resolved attachment as owner-bound bytes (base64), never raw paths", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		const ref = attachmentRef("tc-quarantine:1", "image/png");
		await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), {
				attachments: {
					"tc-quarantine:1": {
						quarantineId: "tc-quarantine:1",
						mediaType: "image/png",
						bytes: new TextEncoder().encode("abc"),
						contentHash: `sha256:${"b".repeat(64)}`,
					},
				},
			}),
		);
		expect(sink.sent[0].attachments).toEqual([
			{
				quarantineId: "tc-quarantine:1",
				mediaType: "image/png",
				contentHash: `sha256:${"b".repeat(64)}`,
				sizeBytes: 3,
				bytesBase64: Buffer.from("abc").toString("base64"),
			},
		]);
	});

	it("fails closed for an unsupported destination kind (actor) and never sends", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		const outcome = await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "actor", actorId: "actor-1", conversationId: "conv-42" },
				}),
			),
		);
		expect(outcome).toMatchObject({
			ok: false,
			code: "dashboard_unsupported_destination",
			retryable: false,
		});
		expect(sink.sent).toHaveLength(0);
	});

	it("fails closed when a thread destination is missing its threadId", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		// Bypass schema (the connector is a separate trust layer that must fail closed).
		const base = preparedOutbound();
		const bad = {
			...base,
			resolvedDestination: { kind: "thread", conversationId: "conv-42" },
		} as PreparedOutbound;
		const outcome = await connector.send(context(bad));
		expect(outcome).toMatchObject({
			ok: false,
			code: "dashboard_missing_thread_id",
			retryable: false,
		});
		expect(sink.sent).toHaveLength(0);
	});

	it("fails closed when the resolved destination has no conversationId", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		const outcome = await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "thread", threadId: "thread-7" },
				}),
			),
		);
		expect(outcome).toMatchObject({
			ok: false,
			code: "dashboard_missing_conversation_id",
			retryable: false,
		});
		expect(sink.sent).toHaveLength(0);
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		const ref = attachmentRef("tc-quarantine:missing", "image/png");
		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);
		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing", retryable: false });
		expect(sink.sent).toHaveLength(0);
	});

	it("maps a non-ok sink result to ok:false with its code and retryable flag", async () => {
		const sink = recordingSink({ ok: false, code: "dashboard_unavailable", retryable: true });
		const connector = createDashboardConnector({ send: sink.send });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "dashboard_unavailable",
			retryable: true,
		});
	});

	it("maps a thrown sender error to a non-retryable ambiguous failure (at-most-once)", async () => {
		const connector = createDashboardConnector({
			send: async () => {
				throw new Error("sink exploded");
			},
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "dashboard_send_ambiguous",
			reason: "sink exploded",
			retryable: false,
		});
	});

	it("startListener throws — inbound stays dark until CL-1 risk wrapping", async () => {
		const sink = recordingSink();
		const connector = createDashboardConnector({ send: sink.send });
		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			DASHBOARD_INBOUND_RISK_WRAP_REQUIRED,
		);
	});
});
