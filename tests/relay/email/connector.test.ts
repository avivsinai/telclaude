import { describe, expect, it } from "vitest";
import {
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../../../src/hermes/edge-adapter-contract.js";
import type {
	OutboundDeliveryContext,
	QuarantinedBytes,
} from "../../../src/relay/edge-channel-connector.js";
import { createEmailConnector } from "../../../src/relay/email/connector.js";
import type { EmailSendRequest, EmailTransport } from "../../../src/relay/email/transport.js";

const HEX64 = "a".repeat(64);

function preparedOutbound(overrides: Partial<PreparedOutbound> = {}): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: "edge-out:deadbeef",
		channel: "email",
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
			channelIdentity: { channel: "email", principalId: "relay:pairing-authority" },
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

function recordingTransport(
	result: Awaited<ReturnType<EmailTransport["send"]>> = { ok: true, platformMessageId: "gmail-1" },
): EmailTransport & { readonly sent: EmailSendRequest[] } {
	const sent: EmailSendRequest[] = [];
	return {
		kind: "gmail-api",
		sent,
		send: async (request) => {
			sent.push(request);
			return result;
		},
	};
}

describe("email connector", () => {
	it("composes and sends to the address recipient, recording the sent Message-ID", async () => {
		const transport = recordingTransport();
		const connector = createEmailConnector({
			transport,
			from: "agent@relay.test",
			defaultSubject: "Message from your assistant",
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome.ok).toBe(true);
		if (!outcome.ok) throw new Error("expected ok");
		expect(outcome.platformMessageId).toBe("gmail-1");
		expect(outcome.observedThreadMessageId).toMatch(/^<[0-9a-f]{32}@relay\.test>$/);
		expect(transport.sent).toHaveLength(1);
		const sent = transport.sent[0];
		expect(sent.to).toEqual(["alice@example.test"]);
		expect(sent.from).toBe("agent@relay.test");
		expect(sent.idempotencyKey).toBe("edge-idem:deadbeef");
		expect(sent.rawMime).toContain("To: alice@example.test\r\n");
		expect(sent.rawMime).toContain("Subject: Message from your assistant\r\n");
		// base64("hello from the relay")
		expect(sent.rawMime).toContain(Buffer.from("hello from the relay").toString("base64"));
	});

	it("adds In-Reply-To (last) and References from the relay-observed thread ids", async () => {
		const transport = recordingTransport();
		const connector = createEmailConnector({
			transport,
			from: "agent@relay.test",
			defaultSubject: "Re: prior",
		});
		await connector.send(
			context(preparedOutbound(), {
				threadMessageIds: ["<root@x.test>", "<prev@x.test>"],
			}),
		);
		const mime = transport.sent[0].rawMime;
		expect(mime).toContain("In-Reply-To: <prev@x.test>\r\n");
		expect(mime).toContain("References: <root@x.test> <prev@x.test>\r\n");
	});

	it("fails closed for a non-address destination (email needs an explicit recipient)", async () => {
		const transport = recordingTransport();
		const connector = createEmailConnector({
			transport,
			from: "agent@relay.test",
			defaultSubject: "x",
		});
		const outcome = await connector.send(
			context(preparedOutbound({ resolvedDestination: { kind: "thread", threadId: "t1" } })),
		);
		expect(outcome).toMatchObject({ ok: false, code: "email_requires_address_recipient" });
		expect(transport.sent).toHaveLength(0);
	});

	it("includes a resolved attachment as a MIME part", async () => {
		const transport = recordingTransport();
		const connector = createEmailConnector({
			transport,
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
		const mime = transport.sent[0].rawMime;
		expect(mime).toContain("Content-Type: multipart/mixed; boundary=");
		expect(mime).toContain('filename="attachment-1.pdf"');
		expect(mime).toContain(Buffer.from("abc").toString("base64"));
	});

	it("fails closed when a declared attachment is not resolvable (owner-bound miss)", async () => {
		const transport = recordingTransport();
		const connector = createEmailConnector({
			transport,
			from: "agent@relay.test",
			defaultSubject: "x",
		});
		const ref = attachmentRef("tc-quarantine:missing", "image/png");
		const outcome = await connector.send(
			context(preparedOutbound({ mediaRefs: [ref] }), { attachments: {} }),
		);
		expect(outcome).toMatchObject({ ok: false, code: "attachment_missing" });
		expect(transport.sent).toHaveLength(0);
	});

	it("rejects a CRLF-injecting recipient as a non-retryable failure (never reaches the transport)", async () => {
		const transport = recordingTransport();
		const connector = createEmailConnector({
			transport,
			from: "agent@relay.test",
			defaultSubject: "x",
		});
		const outcome = await connector.send(
			context(
				preparedOutbound({
					resolvedDestination: {
						kind: "address",
						addressRef: "alice@example.test\r\nBcc: evil@attacker.test",
					},
				}),
			),
		);
		// The single-address validator catches the CRLF (control char) before compose;
		// the composer's own header-injection guard is covered in mime-compose.test.ts.
		expect(outcome).toMatchObject({ ok: false, code: "email_invalid_recipient", retryable: false });
		expect(transport.sent).toHaveLength(0);
	});

	it("propagates a transport failure with its code and retryable flag", async () => {
		const transport = recordingTransport({
			ok: false,
			code: "transport_unavailable",
			retryable: true,
		});
		const connector = createEmailConnector({
			transport,
			from: "agent@relay.test",
			defaultSubject: "x",
		});
		const outcome = await connector.send(context(preparedOutbound()));
		expect(outcome).toMatchObject({ ok: false, code: "transport_unavailable", retryable: true });
	});

	describe("rejects a recipient that encodes more than one address (no fan-out past the bound member)", () => {
		const cases: Array<[string, string]> = [
			["comma list", "alice@example.test, attacker@evil.test"],
			["semicolon list", "alice@example.test;attacker@evil.test"],
			["display-name angle form", "Alice <alice@example.test>"],
			["group syntax", "team: alice@example.test"],
			["two @", "alice@@example.test"],
		];
		for (const [label, addressRef] of cases) {
			it(`fails closed and does not send for ${label}`, async () => {
				const transport = recordingTransport();
				const connector = createEmailConnector({
					transport,
					from: "agent@relay.test",
					defaultSubject: "x",
				});
				const outcome = await connector.send(
					context(preparedOutbound({ resolvedDestination: { kind: "address", addressRef } })),
				);
				expect(outcome).toMatchObject({
					ok: false,
					code: "email_invalid_recipient",
					retryable: false,
				});
				expect(transport.sent).toHaveLength(0);
			});
		}
	});
});
