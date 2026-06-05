import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	createDiscordConnector,
	DISCORD_INBOUND_RISK_WRAP_REQUIRED,
	type DiscordCreateMessageRequest,
	type DiscordSendResult,
} from "../../../src/relay/channels/discord-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = "a".repeat(64);
// Build the inbound listener error literal from char codes so the fixture never
// embeds backslash/regex syntax that Write/Edit could mangle.
const RISK_WRAP_NEEDLE = String.fromCharCode(67, 76, 45, 49); // "CL-1"

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "discord",
		resolvedDestination: {
			kind: "thread",
			threadId: "123456789012345678",
			conversationId: "c1",
		},
		finalRenderedBody: "hello from the relay",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "discord", principalId: "relay:pairing-authority" },
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
		lifecycle: { state: "authorized", authorizedFor: ["conv_aaa"] },
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

function recordingSender(
	result: DiscordSendResult = { id: "discord-msg-1" },
): DiscordMessageSenderSpy {
	const sent: DiscordCreateMessageRequest[] = [];
	return {
		sent,
		send: async (request) => {
			sent.push(request);
			return result;
		},
	};
}

interface DiscordMessageSenderSpy {
	readonly sent: DiscordCreateMessageRequest[];
	send(request: DiscordCreateMessageRequest): Promise<DiscordSendResult>;
}

describe("discord connector", () => {
	it("builds a create-message request from resolvedDestination + body and maps id to platformMessageId", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("discord-msg-1");
		expect(outcome.observedThreadMessageId).toBe("discord-msg-1");
		expect(sender.sent).toHaveLength(1);
		const sent = sender.sent[0];
		// channelId comes from resolvedDestination VERBATIM, not the body.
		expect(sent.channelId).toBe("123456789012345678");
		expect(sent.content).toBe("hello from the relay");
		expect(sent.idempotencyKey).toBe("edge-idem:deadbeef");
		expect(sent.outboundRef).toBe("edge-out:deadbeef");
		expect(sent.messageReference).toBeUndefined();
		expect(sent.attachments).toEqual([]);
	});

	it("maps an actor destination's actorId to the channelId", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "actor", actorId: "987654321098765432" },
				}),
			),
		);
		expect(sender.sent[0].channelId).toBe("987654321098765432");
	});

	it("maps an address destination's addressRef to the channelId", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "address", addressRef: "555000111222333444" },
				}),
			),
		);
		expect(sender.sent[0].channelId).toBe("555000111222333444");
	});

	it("sets messageReference from the last relay-observed thread message id", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		await connector.send(
			context(preparedOutbound(), {
				threadMessageIds: ["msg-root", "msg-prev"],
			}),
		);
		expect(sender.sent[0].messageReference).toBe("msg-prev");
	});

	it("fails closed (non-retryable, no send) on a destination kind with no channel id field", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		// kind=actor but the actorId field is absent — the connector must not fall
		// back to any other field or re-derive the recipient.
		const outcome = await connector.send(
			context(preparedOutbound({ resolvedDestination: { kind: "actor" } })),
		);
		expect(outcome).toMatchObject({
			ok: false,
			code: "discord_unsupported_destination_kind",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when the destination field is blank", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		// The schema rejects a blank threadId, so build a prepared that bypassed
		// schema validation: the connector is a separate trust layer and must fail
		// closed on a blank channel id even if such a prepared reaches it.
		const base = preparedOutbound();
		const blank = {
			...base,
			resolvedDestination: { kind: "thread", threadId: "   " },
		} as PreparedOutbound;
		const outcome = await connector.send(context(blank));
		expect(outcome).toMatchObject({
			ok: false,
			code: "discord_missing_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("includes a resolved attachment and never reads raw bytes from the model", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
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
		expect(sender.sent[0].attachments).toHaveLength(1);
		const att = sender.sent[0].attachments[0];
		expect(att.quarantineId).toBe("tc-quarantine:1");
		expect(att.mediaType).toBe("image/png");
		expect(new TextDecoder().decode(att.bytes)).toBe("abc");
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		const ref = attachmentRef("tc-quarantine:missing", "image/png");
		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);
		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing", retryable: false });
		expect(sender.sent).toHaveLength(0);
	});

	it("maps a thrown sender error to a non-retryable failure (at-most-once)", async () => {
		const connector = createDiscordConnector({
			send: async () => {
				throw new Error("network blip after dispatch");
			},
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "discord_send_ambiguous",
			retryable: false,
		});
		if (outcome.ok) throw new Error("expected failure");
		expect(outcome.reason).toContain("network blip after dispatch");
	});

	it("maps a non-ok platform result (error set) to a non-retryable failure", async () => {
		const sender = recordingSender({ error: "Missing Access" });
		const connector = createDiscordConnector({ send: sender.send });
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "discord_send_failed",
			reason: "Missing Access",
			retryable: false,
		});
	});

	it("startListener throws the CL-1 risk-wrap precondition (inbound stays dark)", async () => {
		const sender = recordingSender();
		const connector = createDiscordConnector({ send: sender.send });
		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			DISCORD_INBOUND_RISK_WRAP_REQUIRED,
		);
		expect(DISCORD_INBOUND_RISK_WRAP_REQUIRED).toContain(RISK_WRAP_NEEDLE);
	});
});
