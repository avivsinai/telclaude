import { describe, expect, it } from "vitest";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpScheduledOutboundSideEffectPrepareInput,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalVerifier,
	telclaudeMcpSideEffectRecordIntegrityFailures,
} from "../../src/hermes/mcp/side-effect-ledger.js";

describe("Telclaude MCP side-effect ledger", () => {
	it("computes deterministic canonical hashes over all provider-bound fields", () => {
		const ledger = createTestLedger();

		const first = ledger.prepare(
			providerInput({
				params: { nested: { z: 2, a: 1 }, items: ["first"] },
				wysiwysRender: "Create draft to Alice: hello",
			}),
		);
		const equivalent = ledger.prepare(
			providerInput({
				params: { items: ["first"], nested: { a: 1, z: 2 } },
				wysiwysRender: "Create draft to Alice: hello",
			}),
		);
		const differentParams = ledger.prepare(
			providerInput({
				params: { nested: { a: 99, z: 2 }, items: ["first"] },
				wysiwysRender: "Create draft to Alice: hello",
			}),
		);
		const differentRender = ledger.prepare(
			providerInput({
				params: { nested: { a: 1, z: 2 }, items: ["first"] },
				wysiwysRender: "Create draft to Bob: hello",
			}),
		);
		const differentApprovalRevision = ledger.prepare(
			providerInput({
				params: { nested: { a: 1, z: 2 }, items: ["first"] },
				approvalRevision: 2,
				wysiwysRender: "Create draft to Alice: hello",
			}),
		);

		expect(first.paramsHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(first.bodyHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(equivalent.paramsHash).toBe(first.paramsHash);
		expect(equivalent.bodyHash).toBe(first.bodyHash);
		expect(differentParams.paramsHash).not.toBe(first.paramsHash);
		expect(differentRender.bodyHash).not.toBe(first.bodyHash);
		expect(differentApprovalRevision.paramsHash).not.toBe(first.paramsHash);
		expect(differentApprovalRevision.bodyHash).not.toBe(first.bodyHash);
	});

	it("computes deterministic canonical hashes over all outbound-bound fields", () => {
		const ledger = createTestLedger();

		const first = ledger.prepare(
			outboundInput({
				renderedBody: "Send WhatsApp to Dan: on my way",
				mediaRefs: ["att-b", "att-a"],
				approvalMetadata: { reviewer: "operator", facts: { z: true, a: false } },
			}),
		);
		const equivalent = ledger.prepare(
			outboundInput({
				renderedBody: "Send WhatsApp to Dan: on my way",
				mediaRefs: ["att-b", "att-a"],
				approvalMetadata: { facts: { a: false, z: true }, reviewer: "operator" },
			}),
		);
		const differentDestination = ledger.prepare(
			outboundInput({
				destination: "+15550009999",
				renderedBody: "Send WhatsApp to Dan: on my way",
				mediaRefs: ["att-b", "att-a"],
				approvalMetadata: { reviewer: "operator", facts: { z: true, a: false } },
			}),
		);
		const differentBody = ledger.prepare(
			outboundInput({
				renderedBody: "Send WhatsApp to Dan: never mind",
				mediaRefs: ["att-b", "att-a"],
				approvalMetadata: { reviewer: "operator", facts: { z: true, a: false } },
			}),
		);
		const differentMedia = ledger.prepare(
			outboundInput({
				renderedBody: "Send WhatsApp to Dan: on my way",
				mediaRefs: ["att-a", "att-b"],
				approvalMetadata: { reviewer: "operator", facts: { z: true, a: false } },
			}),
		);
		const differentEdgePreparedHash = ledger.prepare(
			outboundInput({
				renderedBody: "Send WhatsApp to Dan: on my way",
				mediaRefs: ["att-b", "att-a"],
				approvalMetadata: { reviewer: "operator", facts: { z: true, a: false } },
				edgePreparedHash: "b".repeat(64),
			}),
		);

		expect(first.paramsHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(first.bodyHash).toMatch(/^sha256:[a-f0-9]{64}$/);
		expect(equivalent.paramsHash).toBe(first.paramsHash);
		expect(equivalent.bodyHash).toBe(first.bodyHash);
		expect(differentDestination.paramsHash).not.toBe(first.paramsHash);
		expect(differentDestination.bodyHash).not.toBe(first.bodyHash);
		expect(differentBody.bodyHash).not.toBe(first.bodyHash);
		expect(differentMedia.paramsHash).not.toBe(first.paramsHash);
		expect(differentMedia.bodyHash).not.toBe(first.bodyHash);
		expect(differentEdgePreparedHash.paramsHash).not.toBe(first.paramsHash);
		expect(differentEdgePreparedHash.bodyHash).not.toBe(first.bodyHash);
		expect(() =>
			ledger.prepare(outboundInput({ edgePreparedHash: "edge-prepared-hash-1" })),
		).toThrow("edgePreparedHash must be a 64-character lowercase hex digest");
	});

	it("binds household subject and strong-linked principal evidence into every outbound digest", () => {
		const ledger = createTestLedger();
		const householdReplyBinding = {
			bindingId: "parent-a",
			subjectUserId: "household:parent-a",
			senderPrincipalHash:
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const,
			recipientPrincipalHash:
				"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const,
			identityAssurance: "strong_link" as const,
		};
		const prepared = ledger.prepare(
			outboundInput({
				domain: "household",
				subjectUserId: householdReplyBinding.subjectUserId,
				householdReplyBinding,
			}),
		);
		const changedBinding = ledger.prepare(
			outboundInput({
				domain: "household",
				subjectUserId: "household:parent-b",
				householdReplyBinding: {
					...householdReplyBinding,
					bindingId: "parent-b",
					subjectUserId: "household:parent-b",
				},
			}),
		);

		expect(prepared).toMatchObject({
			subjectUserId: "household:parent-a",
			householdReplyBinding,
		});
		expect(getTelclaudeMcpSideEffectApprovalBinding(prepared)).toMatchObject({
			subjectUserId: "household:parent-a",
			householdReplyBinding,
		});
		expect(changedBinding.paramsHash).not.toBe(prepared.paramsHash);
		expect(changedBinding.bodyHash).not.toBe(prepared.bodyHash);
		expect(
			telclaudeMcpSideEffectRecordIntegrityFailures({
				...prepared,
				householdReplyBinding: {
					...householdReplyBinding,
					recipientPrincipalHash:
						"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			}),
		).toEqual([
			"outbound paramsHash does not match current outbound params/render",
			"outbound bodyHash does not match current outbound render",
		]);
	});

	it("prepares a server-only scheduled outbound with immutable reminder policy evidence", () => {
		const ledger = createTestLedger();
		const prepared = ledger.prepare(scheduledOutboundInput());
		const binding = getTelclaudeMcpSideEffectApprovalBinding(prepared);

		expect(prepared).toMatchObject({
			kind: "scheduled-outbound",
			source: "household-reminder-system.v1",
			domain: "household",
			channel: "whatsapp",
			preparedMediaRefs: [],
			householdReminderPolicy: scheduledOutboundInput().householdReminderPolicy,
		});
		expect(prepared).not.toHaveProperty("approverActorId");
		expect(prepared).not.toHaveProperty("turnConversationRef");
		expect(binding).toMatchObject({
			domainSeparator:
				"telclaude.hermes.mcp.side-effect.scheduled-outbound.approval.v1",
			kind: "scheduled-outbound",
			householdReminderPolicy: scheduledOutboundInput().householdReminderPolicy,
			preparedMediaRefs: [],
		});
		expect(binding.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);

		const changedPolicy = ledger.prepare(
			scheduledOutboundInput({
				householdReminderPolicy: {
					...scheduledOutboundInput().householdReminderPolicy,
					revision: 2,
				},
			}),
		);
		expect(changedPolicy.paramsHash).not.toBe(prepared.paramsHash);
		expect(changedPolicy.bodyHash).not.toBe(prepared.bodyHash);
		expect(
			telclaudeMcpSideEffectRecordIntegrityFailures({
				...prepared,
				requestedBody: "תוכן שונה",
			}),
		).toEqual([
			"scheduled outbound paramsHash does not match current policy/prepared outbound",
			"scheduled outbound bodyHash does not match current policy/prepared outbound",
		]);
	});

	it("rejects standard or human authority fields and non-household media-bearing scheduled sends", () => {
		const ledger = createTestLedger();
		expect(() =>
			ledger.prepare(scheduledOutboundInput({ domain: "private" as "household" })),
		).toThrow(/household/i);
		expect(() =>
			ledger.prepare(
				scheduledOutboundInput({
					preparedMediaRefs: [
						{
							quarantineId: "attachment:forbidden",
							contentHash:
								"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						},
					],
				}),
			),
		).toThrow(/media/i);
		expect(() =>
			ledger.prepare({
				...scheduledOutboundInput(),
				approverActorId: "telegram:operator",
			} as TelclaudeMcpScheduledOutboundSideEffectPrepareInput),
		).toThrow(/approverActorId/);
		expect(() =>
			ledger.prepare({
				...scheduledOutboundInput(),
				turnConversationRef: "turn_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			} as TelclaudeMcpScheduledOutboundSideEffectPrepareInput),
		).toThrow(/turnConversationRef/);
	});

	it("authorizes by stored ref only and passes precise stored binding to the verifier", async () => {
		const verifierCalls: unknown[] = [];
		const ledger = createTestLedger({
			nowMs: () => 1_500,
			verifier: async (request) => {
				verifierCalls.push(request);
				return { ok: true, approvalId: "approval-1" };
			},
		});
		const prepared = ledger.prepare(
			providerInput({
				params: { subject: "Lunch", body: "12:30" },
				providerAccountRef: "google:primary",
				approvalRequestId: "approval-provider-1",
				approvalRevision: 3,
				idempotencyKey: "idem-provider-1",
				wysiwysRender: "Calendar event: Lunch at 12:30",
			}),
		);

		const authorized = await ledger.authorize(prepared.ref, "signed-token");

		expect(authorized).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: prepared.ref,
				status: "executed",
				executedAtMs: 1_500,
				approvalId: "approval-1",
			}),
		});
		expect(verifierCalls).toHaveLength(1);
		expect(verifierCalls[0]).toMatchObject({
			approvalToken: "signed-token",
			nowMs: 1_500,
			record: {
				ref: prepared.ref,
				status: "prepared",
				params: { subject: "Lunch", body: "12:30" },
				wysiwysRender: "Calendar event: Lunch at 12:30",
			},
			binding: {
				domainSeparator: "telclaude.hermes.mcp.side-effect.provider.approval.v1",
				ref: prepared.ref,
				kind: "provider",
				actorId: "telegram:123",
				profileId: "private",
				domain: "private",
				providerId: "google",
				service: "calendar",
				action: "event.create",
				providerAccountRef: "google:primary",
				approvalRequestId: "approval-provider-1",
				approvalRevision: 3,
				idempotencyKey: "idem-provider-1",
				paramsHash: prepared.paramsHash,
				bodyHash: prepared.bodyHash,
				contentHash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
			},
		});

		const verifierRequest = verifierCalls[0] as { binding: TelclaudeMcpSideEffectApprovalBinding };
		expect(Object.isFrozen(verifierRequest.binding)).toBe(true);
		expect(verifierRequest.binding.contentHash).not.toBe(prepared.bodyHash);
	});

	it("denies replay after success and keeps verifier failures retryable", async () => {
		let attempt = 0;
		const ledger = createTestLedger({
			verifier: async () => {
				attempt += 1;
				if (attempt === 1) {
					return { ok: false, code: "approval_mismatch", reason: "token hashes differ" };
				}
				return { ok: true };
			},
		});
		const prepared = ledger.prepare(outboundInput());

		await expect(ledger.authorize(prepared.ref, "wrong-token")).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "token hashes differ",
			retryable: true,
			record: expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		});
		expect(ledger.get(prepared.ref)).toEqual(
			expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		);

		await expect(ledger.authorize(prepared.ref, "signed-token")).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({ ref: prepared.ref, status: "executed" }),
		});
		await expect(ledger.authorize(prepared.ref, "signed-token")).resolves.toEqual({
			ok: false,
			code: "effect_already_executed",
			reason: "side effect has already executed",
			retryable: false,
			record: expect.objectContaining({ ref: prepared.ref, status: "executed" }),
		});
		expect(attempt).toBe(2);
	});

	it("rejects tokens bound to a different paramsHash or bodyHash without consuming", async () => {
		const acceptedTokens = new Map<string, { paramsHash: string; bodyHash: string }>();
		const ledger = createTestLedger({
			verifier: tokenBindingVerifier(acceptedTokens),
		});
		const original = ledger.prepare(
			providerInput({
				params: { amount: 100, currency: "USD" },
				wysiwysRender: "Transfer USD 100",
			}),
		);
		const paramsChanged = ledger.prepare(
			providerInput({
				params: { amount: 101, currency: "USD" },
				wysiwysRender: "Transfer USD 100",
			}),
		);
		const bodyChanged = ledger.prepare(
			providerInput({
				params: { amount: 100, currency: "USD" },
				wysiwysRender: "Transfer USD 100 to attacker",
			}),
		);
		acceptedTokens.set("token-for-original", {
			paramsHash: original.paramsHash,
			bodyHash: original.bodyHash,
		});

		await expect(ledger.authorize(paramsChanged.ref, "token-for-original")).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "token hashes differ",
			retryable: true,
			record: expect.objectContaining({ ref: paramsChanged.ref, status: "prepared" }),
		});
		await expect(ledger.authorize(bodyChanged.ref, "token-for-original")).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "token hashes differ",
			retryable: true,
			record: expect.objectContaining({ ref: bodyChanged.ref, status: "prepared" }),
		});
		expect(ledger.get(paramsChanged.ref)).toEqual(
			expect.objectContaining({ ref: paramsChanged.ref, status: "prepared" }),
		);
		expect(ledger.get(bodyChanged.ref)).toEqual(
			expect.objectContaining({ ref: bodyChanged.ref, status: "prepared" }),
		);
	});

	it("rejects provider self-approval before verifier or direct execution", async () => {
		let verifierCalls = 0;
		const ledger = createTestLedger({
			verifier: async () => {
				verifierCalls += 1;
				return { ok: true };
			},
		});
		const prepared = ledger.prepare(providerInput({ approverActorId: "telegram:123" }));

		await expect(ledger.verify(prepared.ref, "signed-token")).resolves.toEqual({
			ok: false,
			code: "provider_distinct_human_approver_required",
			reason: "provider side effects require approval by a distinct human approver",
			retryable: false,
			record: expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		});
		await expect(ledger.authorize(prepared.ref, "signed-token")).resolves.toEqual({
			ok: false,
			code: "provider_distinct_human_approver_required",
			reason: "provider side effects require approval by a distinct human approver",
			retryable: false,
			record: expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		});
		expect(ledger.markExecuted(prepared.ref, "approval-1")).toEqual({
			ok: false,
			code: "provider_distinct_human_approver_required",
			reason: "provider side effects require approval by a distinct human approver",
			retryable: false,
			record: expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		});
		expect(verifierCalls).toBe(0);
		expect(ledger.get(prepared.ref)).toEqual(
			expect.objectContaining({ ref: prepared.ref, status: "prepared" }),
		);
	});

	it("blocks revoked refs, denies expired refs before verifier, and denies unknown refs", async () => {
		let nowMs = 10_000;
		let verifierCalls = 0;
		const ledger = createTestLedger({
			nowMs: () => nowMs,
			verifier: async () => {
				verifierCalls += 1;
				return { ok: true };
			},
		});
		const revoked = ledger.prepare(outboundInput());

		expect(ledger.revoke(revoked.ref, "operator denied")).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: revoked.ref,
				status: "revoked",
				revokedAtMs: 10_000,
				revokeReason: "operator denied",
			}),
		});
		await expect(ledger.authorize(revoked.ref, "signed-token")).resolves.toEqual({
			ok: false,
			code: "effect_revoked",
			reason: "side effect was revoked",
			retryable: false,
			record: expect.objectContaining({ ref: revoked.ref, status: "revoked" }),
		});

		const expiring = ledger.prepare(providerInput({ ttlMs: 1_000 }));
		nowMs = 11_001;
		await expect(ledger.authorize(expiring.ref, "signed-token")).resolves.toEqual({
			ok: false,
			code: "effect_expired",
			reason: "side effect approval window expired",
			retryable: false,
			record: expect.objectContaining({
				ref: expiring.ref,
				status: "prepared",
			}),
		});
		await expect(ledger.authorize("missing-ref", "signed-token")).resolves.toEqual({
			ok: false,
			code: "effect_not_found",
			reason: "side effect was not prepared",
			retryable: false,
		});
		expect(verifierCalls).toBe(0);
	});

	it("deep-clones and freezes prepare/get/authorize records to prevent TOCTOU mutation", async () => {
		const params = { nested: { a: 1 }, items: ["before"] };
		const approvalMetadata = { reviewer: "operator", facts: { a: true } };
		const mediaRefs = ["att-1"];
		const ledger = createTestLedger();

		const provider = ledger.prepare(providerInput({ params }));
		const outbound = ledger.prepare(outboundInput({ approvalMetadata, mediaRefs }));

		params.nested.a = 99;
		params.items.push("after");
		approvalMetadata.facts.a = false;
		mediaRefs.push("att-2");

		expect(Object.isFrozen(provider)).toBe(true);
		expect(Object.isFrozen(provider.params)).toBe(true);
		expect(Object.isFrozen((provider.params as { nested: object }).nested)).toBe(true);
		expect(() => {
			(provider.params as { nested: { a: number } }).nested.a = 42;
		}).toThrow(TypeError);
		expect(Object.isFrozen(outbound.mediaRefs)).toBe(true);
		expect(() => {
			(outbound.mediaRefs as string[]).push("att-3");
		}).toThrow(TypeError);

		expect(ledger.get(provider.ref)).toEqual(
			expect.objectContaining({
				params: { nested: { a: 1 }, items: ["before"] },
			}),
		);
		expect(ledger.get(outbound.ref)).toEqual(
			expect.objectContaining({
				mediaRefs: ["att-1"],
				approvalMetadata: { reviewer: "operator", facts: { a: true } },
			}),
		);

		const authorized = await ledger.authorize(outbound.ref, "signed-token");
		expect(authorized).toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: outbound.ref,
				status: "executed",
				mediaRefs: ["att-1"],
				approvalMetadata: { reviewer: "operator", facts: { a: true } },
			}),
		});
		if (authorized.ok) {
			expect(authorized.record).not.toBe(outbound);
			expect(Object.isFrozen(authorized.record)).toBe(true);
			expect(Object.isFrozen((authorized.record as { mediaRefs: string[] }).mediaRefs)).toBe(true);
		}
	});

	it("keeps the state machine terminal after execute and prevents revoke-after-execute", async () => {
		const ledger = createTestLedger();
		const prepared = ledger.prepare(providerInput());

		await expect(ledger.authorize(prepared.ref, "signed-token")).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({ ref: prepared.ref, status: "executed" }),
		});

		expect(ledger.revoke(prepared.ref, "too late")).toEqual({
			ok: false,
			code: "effect_already_executed",
			reason: "side effect has already executed",
			retryable: false,
			record: expect.objectContaining({ ref: prepared.ref, status: "executed" }),
		});
		expect(ledger.get(prepared.ref)).toEqual(
			expect.objectContaining({ ref: prepared.ref, status: "executed" }),
		);
	});
});

function createTestLedger(
	options: { verifier?: TelclaudeMcpSideEffectApprovalVerifier; nowMs?: () => number } = {},
) {
	let nextRef = 0;
	return createTelclaudeMcpSideEffectLedger({
		verifyApproval: options.verifier ?? (async () => ({ ok: true })),
		nowMs: options.nowMs ?? (() => 1_000),
		makeRef: () => `effect-${++nextRef}`,
		defaultTtlMs: 60_000,
	});
}

function tokenBindingVerifier(
	acceptedTokens: Map<string, { paramsHash: string; bodyHash: string }>,
): TelclaudeMcpSideEffectApprovalVerifier {
	return async ({ approvalToken, binding }) => {
		const expected = acceptedTokens.get(approvalToken);
		if (!expected) return { ok: false, code: "approval_required", reason: "unknown token" };
		if (expected.paramsHash !== binding.paramsHash || expected.bodyHash !== binding.bodyHash) {
			return { ok: false, code: "approval_mismatch", reason: "token hashes differ" };
		}
		return { ok: true };
	};
}

function providerInput(
	overrides: Partial<TelclaudeMcpProviderSideEffectPrepareInput> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider" as const,
		actorId: "telegram:123",
		approverActorId: "telegram:operator",
		profileId: "private",
		domain: "private" as const,
		providerId: "google",
		service: "calendar",
		action: "event.create",
		params: { subject: "Lunch" },
		providerAccountRef: "google:primary",
		approvalRequestId: "approval-provider-1",
		approvalRevision: 1,
		wysiwysRender: "Calendar event: Lunch",
		idempotencyKey: "idem-provider-1",
		...overrides,
	};
}

function outboundInput(
	overrides: Partial<TelclaudeMcpOutboundSideEffectPrepareInput> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const channel = "whatsapp";
	const requestedBody = "Send WhatsApp to Dan: on my way";
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "+15551234567",
		conversationId: "whatsapp:+15551234567",
	};
	const preparedMediaRefs = [
		{
			quarantineId: "att-1",
			contentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	];
	return {
		kind: "outbound" as const,
		actorId: "telegram:123",
		approverActorId: "telegram:operator",
		profileId: "private",
		domain: "private" as const,
		channel,
		destination: "+15551234567",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: ["att-1"],
		preparedMediaRefs,
		conversationRef: "whatsapp:+15551234567",
		authorizationState: "authorized",
		edgePreparedRef: "edge-outbound-1",
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: "approval-outbound-1",
		approvalRevision: 1,
		approvalMetadata: { reviewer: "operator" },
		idempotencyKey: "idem-outbound-1",
		...overrides,
	};
}

function scheduledOutboundInput(
	overrides: Partial<TelclaudeMcpScheduledOutboundSideEffectPrepareInput> = {},
): TelclaudeMcpScheduledOutboundSideEffectPrepareInput {
	const channel = "whatsapp" as const;
	const requestedBody = "תזכורת: להביא מסמכים";
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "+972501234567",
		conversationId: "whatsapp:household:parent-a",
	};
	return {
		kind: "scheduled-outbound",
		source: "household-reminder-system.v1",
		actorId: "household:whatsapp:parent-a",
		profileId: "parent-a",
		domain: "household",
		subjectUserId: "household:parent-a",
		channel,
		destination: "+972501234567",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		preparedMediaRefs: [],
		conversationRef: "whatsapp:household:parent-a",
		edgePreparedRef: "edge-reminder-fire-1",
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: [],
		}),
		idempotencyKey: "reminder-fire-idem-1",
		householdReminderPolicy: {
			reminderId: "reminder-1",
			fireId: "reminder-fire-1",
			revision: 1,
			confirmedProposalHash:
				"sha256:1111111111111111111111111111111111111111111111111111111111111111",
			scheduleHash:
				"sha256:2222222222222222222222222222222222222222222222222222222222222222",
			contentHash:
				"sha256:3333333333333333333333333333333333333333333333333333333333333333",
			bindingFingerprint:
				"sha256:4444444444444444444444444444444444444444444444444444444444444444",
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			profileId: "parent-a",
			recipientPrincipalHash:
				"sha256:5555555555555555555555555555555555555555555555555555555555555555",
			systemPolicyPrincipal: "telclaude:household-reminder-system",
			systemPolicyVersion: "phase0.v1",
		},
		ttlMs: 60_000,
		...overrides,
	};
}
