import { describe, expect, it } from "vitest";
import { sortKeysDeep } from "../../src/crypto/canonical-hash.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridgeDependencies,
} from "../../src/hermes/mcp/bridge.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "../../src/hermes/mcp/ledger-execute.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalVerification,
	type TelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectRecord,
} from "../../src/hermes/mcp/side-effect-ledger.js";

describe("Telclaude MCP ledger execute dependencies", () => {
	it("authorizes provider and outbound executes through the ledger", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness.ledger);
		const provider = harness.ledger.prepare(providerPrepareInput());
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("provider-token", provider);
		harness.accept("outbound-token", outbound);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "provider-token",
			}),
		).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: provider.ref,
				status: "executed",
				approvalId: "provider-token",
			}),
		});
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: outbound.ref,
				approvalToken: "outbound-token",
			}),
		).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: outbound.ref,
				status: "executed",
				approvalId: "outbound-token",
			}),
		});

		expect(harness.verifierCalls).toEqual([
			expect.objectContaining({
				approvalToken: "provider-token",
				record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
			}),
			expect.objectContaining({
				approvalToken: "outbound-token",
				record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
			}),
		]);
	});

	it("surfaces verifier failures as retryable without executing the prepared ref", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness.ledger);
		const provider = harness.ledger.prepare(providerPrepareInput());

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "unknown-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "approval_mismatch",
			reason: "approval token not accepted",
			retryable: true,
			record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		});
		expect(harness.verifierCalls).toHaveLength(1);
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});

	it("rejects kind mismatches before verification and leaves the ref prepared", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness.ledger);
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: outbound.ref,
				approvalToken: "outbound-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "effect_kind_mismatch",
			reason: "side effect kind mismatch: expected provider",
			retryable: false,
		});
		expect(harness.verifierCalls).toHaveLength(0);
		expect(harness.ledger.get(outbound.ref)).toEqual(
			expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		);
	});

	it("rejects authority mismatches before verification and leaves the ref prepared", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness.ledger);
		const provider = harness.ledger.prepare(providerPrepareInput({ actorId: "other-actor" }));
		harness.accept("provider-token", provider);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "provider-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "effect_authority_mismatch",
			reason: "side effect authority mismatch",
			retryable: false,
		});
		expect(harness.verifierCalls).toHaveLength(0);
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});

	it("surfaces revoked, expired, and executed refs as terminal ledger results", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness.ledger);
		const revoked = harness.ledger.prepare(providerPrepareInput());
		const expired = harness.ledger.prepare(providerPrepareInput({ ttlMs: 10_000 }));
		const replayed = harness.ledger.prepare(providerPrepareInput());
		harness.accept("replayed-token", replayed);
		harness.ledger.revoke(revoked.ref, "operator cancelled");

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: revoked.ref,
				approvalToken: "revoked-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "effect_revoked",
			reason: "side effect was revoked",
			retryable: false,
			record: expect.objectContaining({ ref: revoked.ref, status: "revoked" }),
		});

		harness.setNowMs(120_000);
		await expect(
			bridge.tc_provider_execute_write({
				actionRef: expired.ref,
				approvalToken: "expired-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "effect_expired",
			reason: "side effect approval window expired",
			retryable: false,
			record: expect.objectContaining({ ref: expired.ref, status: "prepared" }),
		});

		harness.setNowMs(100_000);
		await bridge.tc_provider_execute_write({
			actionRef: replayed.ref,
			approvalToken: "replayed-token",
		});
		await expect(
			bridge.tc_provider_execute_write({
				actionRef: replayed.ref,
				approvalToken: "replayed-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "effect_already_executed",
			reason: "side effect has already executed",
			retryable: false,
			record: expect.objectContaining({ ref: replayed.ref, status: "executed" }),
		});

		expect(harness.verifierCalls).toHaveLength(1);
	});

	it("executes provider sidecars through the relay proxy after ledger authorization", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(
			providerPrepareInput({
				providerId: "google",
				service: "gmail",
				action: "create_draft",
				params: { to: "a@example.com", body: "hello" },
				providerAccountRef: "google:gmail:primary",
			}),
		);
		harness.accept("provider-token", provider);
		const providerCalls: unknown[] = [];
		const bridge = createBridge(harness.ledger, {
			providerProxy: async (request) => {
				providerCalls.push(request);
				return { status: "ok", data: { draftId: "draft_123" } };
			},
			providerApprovalTokenIssuer: ({ providerId, service, action, approvalNonce }) =>
				`sidecar:${providerId}:${service}:${action}:${approvalNonce}`,
		});

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "provider-token",
			}),
		).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: provider.ref,
				status: "executed",
				approvalId: "provider-token",
			}),
		});
		expect(providerCalls).toEqual([
			{
				providerId: "google",
				path: "/v1/fetch",
				method: "POST",
				body: JSON.stringify({
					service: "gmail",
					action: "create_draft",
					params: { to: "a@example.com", body: "hello" },
				}),
				userId: "operator",
				approvalToken: "sidecar:google:gmail:create_draft:approval-provider-1",
				approvalMode: "preapproved-ledger",
			},
		]);
		expect(JSON.stringify(providerCalls)).not.toContain("provider-token");
	});

	it("fails closed before provider sidecar execution when no sidecar token issuer is configured", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(providerPrepareInput());
		harness.accept("provider-token", provider);
		const providerCalls: unknown[] = [];
		const bridge = createBridge(harness.ledger, {
			providerProxy: async (request) => {
				providerCalls.push(request);
				return { status: "ok", data: { accepted: true } };
			},
		});

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "provider-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "provider_approval_token_issuer_missing",
			reason: "provider sidecar approval token issuer is not configured",
			retryable: false,
			record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		});
		expect(providerCalls).toEqual([]);
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});

	it("leaves provider refs prepared when sidecar execution fails after approval verification", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(providerPrepareInput());
		harness.accept("provider-token", provider);
		const bridge = createBridge(harness.ledger, {
			providerProxy: async () => ({
				status: "error",
				errorCode: "approval_required",
				error: "sidecar rejected approval",
			}),
			providerApprovalTokenIssuer: () => "sidecar-token",
		});

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "provider-token",
			}),
		).resolves.toEqual({
			ok: false,
			code: "provider_approval_required",
			reason: "sidecar rejected approval",
			retryable: false,
			record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		});
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});
});

function createLedgerHarness(): {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly verifierCalls: TelclaudeMcpSideEffectApprovalVerification[];
	readonly accept: (token: string, record: TelclaudeMcpSideEffectRecord) => void;
	readonly setNowMs: (nowMs: number) => void;
} {
	let nowMs = 100_000;
	let refCounter = 0;
	const accepted = new Map<string, string>();
	const verifierCalls: TelclaudeMcpSideEffectApprovalVerification[] = [];
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => nowMs,
		makeRef: () => `effect-execute-${++refCounter}`,
		defaultTtlMs: 60_000,
		verifyApproval: async (request) => {
			verifierCalls.push(request);
			const expectedBinding = accepted.get(request.approvalToken);
			if (!expectedBinding) {
				return { ok: false, code: "approval_mismatch", reason: "approval token not accepted" };
			}
			if (canonicalBinding(request.binding) !== expectedBinding) {
				return { ok: false, code: "approval_mismatch", reason: "approval token mismatch" };
			}
			return { ok: true, approvalId: request.approvalToken };
		},
	});
	return {
		ledger,
		verifierCalls,
		accept(token, record) {
			accepted.set(token, canonicalBinding(getTelclaudeMcpSideEffectApprovalBinding(record)));
		},
		setNowMs(nextNowMs) {
			nowMs = nextNowMs;
		},
	};
}

function createBridge(
	ledger: TelclaudeMcpSideEffectLedger,
	options: Omit<Parameters<typeof createTelclaudeMcpLedgerExecuteDependencies>[0], "ledger"> = {},
) {
	return createTelclaudeMcpBridge(baseAuthority(), {
		...baseDependencies(),
		...createTelclaudeMcpLedgerExecuteDependencies({ ledger, ...options }),
	});
}

function baseAuthority(overrides: Partial<TelclaudeMcpAuthority> = {}): TelclaudeMcpAuthority {
	return {
		actorId: "operator",
		profileId: "ops",
		domain: "private",
		memorySource: "telegram:ops",
		writableNamespace: "private:ops",
		providerScopes: ["bank"],
		outboundChannels: ["whatsapp"],
		endpointId: "endpoint-private",
		networkNamespace: "netns-private",
		...overrides,
	};
}

function baseDependencies(): TelclaudeMcpBridgeDependencies {
	return {
		providerRead: async () => ({ ok: true }),
		providerPrepareWrite: async () => ({ actionRef: "act_123" }),
		providerExecuteWrite: async () => ({ ok: true }),
		memorySearch: async () => ({ entries: [] }),
		memoryWrite: async () => ({ accepted: 1 }),
		attachmentGet: async () => ({ bytes: 0 }),
		outboundPrepare: async () => ({ outboundRef: "out_123" }),
		outboundExecute: async () => ({ ok: true }),
		auditNote: async () => ({ stored: true }),
	};
}

function providerPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "operator",
		approverActorId: "operator",
		profileId: "ops",
		domain: "private",
		providerId: "bank",
		service: "bank",
		action: "transfer.prepare",
		params: { amount: 100, currency: "ILS" },
		providerAccountRef: "bank:primary",
		approvalRequestId: "approval-provider-1",
		approvalRevision: 1,
		wysiwysRender: "Transfer ILS 100 to saved recipient",
		idempotencyKey: "idem-provider-1",
		...overrides,
	};
}

function outboundPrepareInput() {
	return {
		kind: "outbound" as const,
		actorId: "operator",
		approverActorId: "operator",
		profileId: "ops",
		domain: "private" as const,
		channel: "whatsapp",
		destination: "+15551234567",
		renderedBody: "I'll pick up dinner at 19:00.",
		mediaRefs: ["attachment:menu"],
		conversationRef: "whatsapp:+15551234567",
		approvalRequestId: "approval-outbound-1",
		approvalRevision: 1,
		approvalMetadata: { category: "family-logistics" },
		idempotencyKey: "idem-outbound-1",
	};
}

function canonicalBinding(binding: TelclaudeMcpSideEffectApprovalBinding): string {
	return JSON.stringify(sortKeysDeep(binding));
}
