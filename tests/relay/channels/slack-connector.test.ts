import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	createSlackConnector,
	SLACK_INBOUND_RISK_WRAP_REQUIRED,
	type SlackPostMessageRequest,
	type SlackPostMessageResult,
} from "../../../src/relay/channels/slack-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = "a".repeat(64);
const SHA256 = `sha256:${"b".repeat(64)}`;

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "slack",
		resolvedDestination: {
			kind: "actor",
			actorId: "C0123CHANNEL",
			conversationId: "conv-1",
		},
		finalRenderedBody: "hello from the relay",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "slack", principalId: "relay:pairing-authority" },
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
		contentHash: SHA256,
		trustLabel: "trusted",
		expiresAt: "2026-06-05T00:00:00.000Z",
		lifecycle: { state: "authorized", authorizedFor: ["conv_aaa"] },
	};
}

function context(
	prepared: PreparedOutbound,
	opts: { attachments?: Record<string, QuarantinedBytes | null> } = {},
): OutboundDeliveryContext {
	return {
		prepared,
		threadMessageIds: [],
		resolveAttachment: async (quarantineId) => opts.attachments?.[quarantineId] ?? null,
	};
}

function recordingSender(result: SlackPostMessageResult = { ok: true, ts: "1717459200.000100" }): {
	readonly send: (request: SlackPostMessageRequest) => Promise<SlackPostMessageResult>;
	readonly sent: SlackPostMessageRequest[];
} {
	const sent: SlackPostMessageRequest[] = [];
	return {
		sent,
		send: async (request) => {
			sent.push(request);
			return result;
		},
	};
}

describe("slack connector", () => {
	it("posts an actor destination to channelId and maps ts -> platform/thread ids", async () => {
		const sender = recordingSender({ ok: true, ts: "1717459200.000100" });
		const connector = createSlackConnector({ send: sender.send });

		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("1717459200.000100");
		expect(outcome.observedThreadMessageId).toBe("1717459200.000100");
		expect(sender.sent).toHaveLength(1);
		const request = sender.sent[0];
		expect(request.channelId).toBe("C0123CHANNEL");
		expect(request.text).toBe("hello from the relay");
		expect(request.threadTs).toBeUndefined();
		expect(request.idempotencyKey).toBe("edge-idem:deadbeef");
		// No raw credential is ever constructed by the connector.
		expect(Object.keys(request)).not.toContain("token");
		expect(Object.keys(request)).not.toContain("authorization");
	});

	it("derives a thread reply from threadId (threadTs) + conversationId (channelId)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });

		await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: {
						kind: "thread",
						threadId: "1717459100.000050",
						conversationId: "C0THREADCHAN",
					},
				}),
			),
		);

		const request = sender.sent[0];
		expect(request.channelId).toBe("C0THREADCHAN");
		expect(request.threadTs).toBe("1717459100.000050");
	});

	it("posts an address destination to channelId (addressRef verbatim)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });

		await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "address", addressRef: "C0ADDRCHAN" },
				}),
			),
		);

		expect(sender.sent[0].channelId).toBe("C0ADDRCHAN");
	});

	it("fails closed when a thread destination is missing its channelId (conversationId)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });

		// thread destination with no conversationId: cannot resolve channelId.
		const base = preparedOutbound();
		const badThread = {
			...base,
			resolvedDestination: { kind: "thread", threadId: "1717459100.000050" },
		} as PreparedOutbound;

		const outcome = await connector.send(context(badThread));

		expect(outcome).toMatchObject({
			ok: false,
			code: "slack_missing_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed on an unsupported destination kind (never sends)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });

		// A prepared that bypassed schema validation reaches the connector with an
		// unknown destination kind. The connector is a separate trust layer and must
		// fail closed rather than guess a recipient.
		const base = preparedOutbound();
		const bogus = {
			...base,
			resolvedDestination: { kind: "broadcast" },
		} as unknown as PreparedOutbound;

		const outcome = await connector.send(context(bogus));

		expect(outcome).toMatchObject({
			ok: false,
			code: "slack_unsupported_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("passes a resolved attachment through to the sender request", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });
		const ref = attachmentRef("tc-quarantine:1", "image/png");

		await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), {
				attachments: {
					"tc-quarantine:1": {
						quarantineId: "tc-quarantine:1",
						mediaType: "image/png",
						bytes: new TextEncoder().encode("abc"),
						contentHash: SHA256,
					},
				},
			}),
		);

		const request = sender.sent[0];
		expect(request.attachments).toHaveLength(1);
		expect(request.attachments[0]).toMatchObject({
			quarantineId: "tc-quarantine:1",
			mediaType: "image/png",
			contentHash: SHA256,
			sizeBytes: 3,
		});
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });
		const ref = attachmentRef("tc-quarantine:missing", "image/png");

		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);

		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing", retryable: false });
		expect(sender.sent).toHaveLength(0);
	});

	it("maps a non-ok platform result to ok:false with the slack error code (non-retryable)", async () => {
		const sender = recordingSender({ ok: false, error: "channel_not_found" });
		const connector = createSlackConnector({ send: sender.send });

		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome).toMatchObject({
			ok: false,
			code: "channel_not_found",
			reason: "channel_not_found",
			retryable: false,
		});
	});

	it("maps a thrown sender error to ok:false (at-most-once, non-retryable)", async () => {
		const connector = createSlackConnector({
			send: async () => {
				throw new Error("socket hang up");
			},
		});

		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome).toMatchObject({
			ok: false,
			code: "slack_post_ambiguous",
			reason: "socket hang up",
			retryable: false,
		});
	});

	it("does not re-derive the recipient from the body (control chars in body stay in text only)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });
		// Build a body containing a newline + a Slack-channel-looking token via
		// fromCharCode so Write/Edit cannot mangle an escape; it must NOT influence
		// the channelId, which comes from resolvedDestination verbatim.
		const newline = String.fromCharCode(10);
		const body = `legit text${newline}channel: C0EVILCHANNEL`;

		await connector.send(context(preparedOutbound({ finalRenderedBody: body })));

		const request = sender.sent[0];
		expect(request.channelId).toBe("C0123CHANNEL");
		expect(request.text).toBe(body);
	});

	it("throws on startListener (inbound stays dark until CL-1 risk wrapping)", async () => {
		const sender = recordingSender();
		const connector = createSlackConnector({ send: sender.send });

		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			SLACK_INBOUND_RISK_WRAP_REQUIRED,
		);
	});
});
