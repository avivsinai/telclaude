import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import {
	AGENTMAIL_INBOUND_RISK_WRAP_REQUIRED,
	type AgentMailSendRequest,
	type AgentMailSendResult,
	createAgentMailConnector,
} from "../../../src/relay/channels/agentmail-connector.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";

const HEX64 = "a".repeat(64);
// CRLF built from char codes so Write/Edit cannot mangle a literal escape.
const CRLF = String.fromCharCode(13, 10);

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "agentmail",
		resolvedDestination: {
			kind: "address",
			addressRef: "alice@example.test",
			conversationId: "c1",
		},
		finalRenderedBody: "hello from the relay",
		mediaRefs: [],
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: "relay:pairing-authority",
			channelIdentity: { channel: "agentmail", principalId: "relay:pairing-authority" },
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
		attachments?: Record<string, QuarantinedBytes | null>;
	} = {},
): OutboundDeliveryContext {
	return {
		prepared,
		threadMessageIds: [],
		resolveAttachment: async (quarantineId) => opts.attachments?.[quarantineId] ?? null,
	};
}

type AgentMailSender = (request: AgentMailSendRequest) => Promise<AgentMailSendResult>;

function recordingSender(
	result: AgentMailSendResult = { messageId: "am-1" },
): AgentMailSender & { readonly sent: AgentMailSendRequest[] } {
	const sent: AgentMailSendRequest[] = [];
	const fn = async (request: AgentMailSendRequest): Promise<AgentMailSendResult> => {
		sent.push(request);
		return result;
	};
	return Object.assign(fn, { sent });
}

describe("agentmail connector", () => {
	it("builds the platform request verbatim and maps the platform message id", async () => {
		const sender = recordingSender();
		const connector = createAgentMailConnector({
			send: sender,
			from: "agent@relay.test",
			defaultSubject: "Message from your assistant",
		});

		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("am-1");
		expect(outcome.observedThreadMessageId).toBe("am-1");

		expect(sender.sent).toHaveLength(1);
		const sent = sender.sent[0];
		// Recipient comes from resolvedDestination VERBATIM, From/subject from config.
		expect(sent.to).toBe("alice@example.test");
		expect(sent.from).toBe("agent@relay.test");
		expect(sent.subject).toBe("Message from your assistant");
		expect(sent.text).toBe("hello from the relay");
		expect(sent.idempotencyKey).toBe("edge-idem:deadbeef");
		expect(sent.attachments).toBeUndefined();
	});

	it("includes a resolved attachment as a base64 part", async () => {
		const sender = recordingSender();
		const connector = createAgentMailConnector({
			send: sender,
			from: "agent@relay.test",
			defaultSubject: "x",
		});
		const ref = attachmentRef("tc-quarantine:1", "application/pdf");

		await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), {
				attachments: {
					"tc-quarantine:1": {
						quarantineId: "tc-quarantine:1",
						mediaType: "application/pdf",
						bytes: new TextEncoder().encode("abc"),
						contentHash: `sha256:${"b".repeat(64)}`,
					},
				},
			}),
		);

		const sent = sender.sent[0];
		expect(sent.attachments).toEqual([
			{
				filename: "attachment-1.pdf",
				contentType: "application/pdf",
				contentBase64: Buffer.from("abc").toString("base64"),
			},
		]);
	});

	it("fails closed for a non-address destination kind (never sends)", async () => {
		const sender = recordingSender();
		const connector = createAgentMailConnector({
			send: sender,
			from: "agent@relay.test",
			defaultSubject: "x",
		});

		const outcome = await connector.send(
			context(preparedOutbound({ resolvedDestination: { kind: "thread", threadId: "t1" } })),
		);

		expect(outcome).toMatchObject({
			ok: false,
			code: "agentmail_requires_address_recipient",
			retryable: false,
		});
		expect(sender.sent).toHaveLength(0);
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const sender = recordingSender();
		const connector = createAgentMailConnector({
			send: sender,
			from: "agent@relay.test",
			defaultSubject: "x",
		});
		const ref = attachmentRef("tc-quarantine:missing", "image/png");

		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);

		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing", retryable: false });
		expect(sender.sent).toHaveLength(0);
	});

	describe("rejects a recipient that encodes more than one address (no fan-out past the bound member)", () => {
		const cases: Array<[string, string]> = [
			["comma list", "alice@example.test, attacker@evil.test"],
			["semicolon list", "alice@example.test;attacker@evil.test"],
			["display-name angle form", "Alice <alice@example.test>"],
			["group syntax", "team: alice@example.test"],
			["two @", "alice@@example.test"],
			// CRLF header-injection attempt, built without a regex literal.
			["crlf injection", `alice@example.test${CRLF}Bcc: evil@attacker.test`],
		];
		for (const [label, addressRef] of cases) {
			it(`fails closed and does not send for ${label}`, async () => {
				const sender = recordingSender();
				const connector = createAgentMailConnector({
					send: sender,
					from: "agent@relay.test",
					defaultSubject: "x",
				});
				const outcome = await connector.send(
					context(preparedOutbound({ resolvedDestination: { kind: "address", addressRef } })),
				);
				expect(outcome).toMatchObject({
					ok: false,
					code: "agentmail_invalid_recipient",
					retryable: false,
				});
				expect(sender.sent).toHaveLength(0);
			});
		}
	});

	it("maps a thrown sender error to a non-retryable ambiguous failure", async () => {
		const failing: AgentMailSender = async () => {
			throw new Error("network reset mid-POST");
		};
		const connector = createAgentMailConnector({
			send: failing,
			from: "agent@relay.test",
			defaultSubject: "x",
		});

		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome).toMatchObject({
			ok: false,
			code: "agentmail_send_ambiguous",
			retryable: false,
		});
		if (outcome.ok) throw new Error("expected failure");
		expect(outcome.reason).toContain("network reset mid-POST");
	});

	it("maps a non-ok platform result (error field) to a non-retryable failure", async () => {
		const sender = recordingSender({ error: "recipient rejected by upstream MTA" });
		const connector = createAgentMailConnector({
			send: sender,
			from: "agent@relay.test",
			defaultSubject: "x",
		});

		const outcome = await connector.send(context(preparedOutbound()));

		expect(outcome).toMatchObject({
			ok: false,
			code: "agentmail_send_failed",
			retryable: false,
		});
		if (outcome.ok) throw new Error("expected failure");
		expect(outcome.reason).toBe("recipient rejected by upstream MTA");
	});

	it("startListener throws (inbound stays dark until CL-1)", async () => {
		const sender = recordingSender();
		const connector = createAgentMailConnector({
			send: sender,
			from: "agent@relay.test",
			defaultSubject: "x",
		});

		expect(connector.startListener).toBeDefined();
		await expect(connector.startListener?.(async () => {})).rejects.toThrow(
			AGENTMAIL_INBOUND_RISK_WRAP_REQUIRED,
		);
	});
});
