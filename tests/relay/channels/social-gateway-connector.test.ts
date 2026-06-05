import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	createSocialGatewayConnector,
	SOCIAL_INBOUND_RISK_WRAP_REQUIRED,
	type SocialGatewayPostRequest,
	type SocialGatewayPostResult,
} from "../../../src/relay/channels/social-gateway-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = String.fromCharCode(97).repeat(64); // "a" * 64
const SHA256_B = `sha256:${String.fromCharCode(98).repeat(64)}`; // sha256:"b"*64

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "social",
		resolvedDestination: {
			kind: "actor",
			actorId: "social:gateway-account",
			conversationId: "c1",
		},
		finalRenderedBody: "hello from the public persona",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "social", principalId: "relay:pairing-authority" },
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
		contentHash: SHA256_B,
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

function recordingSender(result: SocialGatewayPostResult = { postId: "post-1" }): {
	readonly send: (request: SocialGatewayPostRequest) => Promise<SocialGatewayPostResult>;
	readonly sent: SocialGatewayPostRequest[];
} {
	const sent: SocialGatewayPostRequest[] = [];
	return {
		sent,
		send: async (request) => {
			sent.push(request);
			return result;
		},
	};
}

describe("social-gateway connector", () => {
	it("builds the gateway post from the verbatim actor target + rendered body and maps postId", async () => {
		const sender = recordingSender();
		const connector = createSocialGatewayConnector({ send: sender.send });
		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("post-1");
		expect(outcome.observedThreadMessageId).toBe("post-1");

		expect(sender.sent).toHaveLength(1);
		const req = sender.sent[0];
		expect(req.targetKind).toBe("actor");
		expect(req.target).toBe("social:gateway-account");
		expect(req.text).toBe("hello from the public persona");
		expect(req.media).toEqual([]);
		expect(req.outboundRef).toBe("edge-out:deadbeef");
		expect(req.idempotencyKey).toBe("edge-idem:deadbeef");
		expect(req.conversationId).toBe("c1");
	});

	it("supports an address destination, taking addressRef verbatim", async () => {
		const sender = recordingSender({ postId: "post-2" });
		const connector = createSocialGatewayConnector({ send: sender.send });
		const outcome = await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: { kind: "address", addressRef: "gw://target/handle" },
				}),
			),
		);
		expect(outcome).toMatchObject({ ok: true, platformMessageId: "post-2" });
		expect(sender.sent[0].targetKind).toBe("address");
		expect(sender.sent[0].target).toBe("gw://target/handle");
	});

	it("fails closed for an unsupported destination kind (thread) and never calls the sender", async () => {
		const sender = recordingSender();
		const connector = createSocialGatewayConnector({ send: sender.send });
		const outcome = await connector.send(
			context(preparedOutbound({ resolvedDestination: { kind: "thread", threadId: "t1" } })),
		);
		expect(outcome).toMatchObject({
			ok: false,
			code: "social_unsupported_destination",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when an actor destination has no target field", async () => {
		const sender = recordingSender();
		const connector = createSocialGatewayConnector({ send: sender.send });
		// Bypass the schema (which forbids a blank actorId) to prove the connector
		// is its own trust layer and fails closed on a missing target.
		const base = preparedOutbound();
		const noTarget = {
			...base,
			resolvedDestination: { kind: "actor" as const },
		} as PreparedOutbound;
		const outcome = await connector.send(context(noTarget));
		expect(outcome).toMatchObject({ ok: false, code: "social_missing_target", retryable: false });
		expect(sender.sent).toHaveLength(0);
	});

	it("passes a resolved attachment through to the gateway request (scoped to mediaRefs)", async () => {
		const sender = recordingSender();
		const connector = createSocialGatewayConnector({ send: sender.send });
		const ref = attachmentRef("tc-quarantine:1", "image/png");
		const bytes = new TextEncoder().encode("abc");
		await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), {
				attachments: {
					"tc-quarantine:1": {
						quarantineId: "tc-quarantine:1",
						mediaType: "image/png",
						bytes,
						contentHash: SHA256_B,
					},
				},
			}),
		);
		expect(sender.sent[0].media).toEqual([
			{
				quarantineId: "tc-quarantine:1",
				mediaType: "image/png",
				contentHash: SHA256_B,
				sizeBytes: 3,
				bytes,
			},
		]);
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const sender = recordingSender();
		const connector = createSocialGatewayConnector({ send: sender.send });
		const ref = attachmentRef("tc-quarantine:missing", "image/png");
		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);
		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing", retryable: false });
		expect(sender.sent).toHaveLength(0);
	});

	it("maps a gateway error result to a non-ok, non-retryable outcome", async () => {
		const connector = createSocialGatewayConnector({
			send: async () => ({ error: "rate limited by gateway" }),
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "social_gateway_rejected",
			reason: "rate limited by gateway",
			retryable: false,
		});
	});

	it("maps a thrown sender error to a non-ok, non-retryable (at-most-once) outcome", async () => {
		const connector = createSocialGatewayConnector({
			send: async () => {
				throw new Error("socket hang up");
			},
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({
			ok: false,
			code: "social_gateway_ambiguous",
			reason: "socket hang up",
			retryable: false,
		});
	});

	it("inbound listener stays dark until CL-1", async () => {
		const sender = recordingSender();
		const connector = createSocialGatewayConnector({ send: sender.send });
		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			SOCIAL_INBOUND_RISK_WRAP_REQUIRED,
		);
	});
});
