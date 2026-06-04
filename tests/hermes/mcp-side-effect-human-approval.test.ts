import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpSideEffectApprovalVerifier,
	generateTelclaudeMcpSideEffectApprovalToken,
	type TelclaudeMcpSideEffectApprovalSignatureVerifier,
	type TelclaudeMcpSideEffectApprovalSigner,
	TelclaudeMcpSideEffectJtiStore,
} from "../../src/hermes/mcp/approval-token.js";
import {
	consumeTelclaudeLiveMcpSideEffectApproval,
	requestTelclaudeLiveMcpSideEffectApproval,
	setTelclaudeLiveMcpSideEffectApprovalBinding,
} from "../../src/hermes/mcp/live-side-effect-approvals.js";
import { createSideEffectHumanApprovalController } from "../../src/hermes/mcp/side-effect-human-approval.js";
import {
	createTelclaudeMcpSideEffectLedger,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpSideEffectRecord,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import { getPendingApprovalsForChat } from "../../src/security/approvals.js";
import { closeDb, getDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("Hermes MCP side-effect human approvals", () => {
	let tempDir: string;
	let jtiStore: TelclaudeMcpSideEffectJtiStore;
	let vault: MockVaultClient;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-mcp-human-approval-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
		jtiStore = new TelclaudeMcpSideEffectJtiStore(tempDir);
		vault = new MockVaultClient();
	});

	afterEach(() => {
		setTelclaudeLiveMcpSideEffectApprovalBinding(null);
		jtiStore.close();
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("creates a durable approval row bound to WYSIWYG render and the full side-effect binding", async () => {
		const record = prepareProviderRecord();
		const controller = createController();

		const request = await controller.request({ record, chatId: 111, username: "operator" });

		expect(request).toMatchObject({
			ok: true,
			bindingDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
		});
		if (!request.ok) throw new Error(request.reason);
		const [approval] = getPendingApprovalsForChat(111);
		expect(approval).toMatchObject({
			nonce: request.nonce,
			requestId: record.approvalRequestId,
			from: record.actorId,
			to: record.approverActorId,
			messageId: record.ref,
			riskTier: "high",
			sessionKey: record.ref,
		});
		expect(approval?.body).toContain("Hermes MCP provider side-effect approval required");
		expect(approval?.body).toContain("Human-visible render:\nTransfer ILS 100 to saved recipient");
		expect(approval?.body).toContain(`Params hash: ${record.paramsHash}`);
		expect(approval?.body).toContain(`Body hash: ${record.bodyHash}`);
		expect(approval?.body).toContain(`Binding digest: ${request.bindingDigest}`);
		expect(approval?.body).toContain(`"ref":"${record.ref}"`);
	});

	it("mints a one-shot server-side token after durable approval and authorizes the exact ledger record", async () => {
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-human-token",
			defaultTtlMs: 300_000,
			verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
				vaultClient: vault,
				jtiStore,
				nowSeconds: () => 100,
			}),
		});
		const record = ledger.prepare(providerPrepareInput());
		const controller = createController();
		const request = await controller.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);

		const consumed = await controller.consume({
			record,
			chatId: 111,
			approverActorId: record.approverActorId,
			approvalNonce: request.nonce.toUpperCase(),
		});

		expect(consumed).toMatchObject({
			ok: true,
			actionRef: record.ref,
			approvalId: request.nonce,
			serverSideApprovalStored: true,
		});
		expect("approvalToken" in consumed).toBe(false);
		const stored = controller.takeServerSideApproval({
			actionRef: record.ref,
			record,
			nowMs: 101_000,
		});
		expect(stored).toMatchObject({ ok: true, approvalId: request.nonce });
		if (!stored.ok) throw new Error(stored.reason);
		await expect(ledger.authorize(record.ref, stored.approvalToken)).resolves.toMatchObject({
			ok: true,
			record: {
				ref: record.ref,
				status: "executed",
				approvalId: request.nonce,
			},
		});
		expect(controller.takeServerSideApproval({ actionRef: record.ref, record })).toMatchObject({
			ok: true,
			approvalId: request.nonce,
		});
		stored.finalize();
		expect(controller.takeServerSideApproval({ actionRef: record.ref, record })).toMatchObject({
			ok: false,
			code: "approval_token_unavailable",
		});
	});

	it("rejects wrong approver before consuming the legitimate pending approval", async () => {
		const record = prepareProviderRecord();
		const controller = createController();
		const request = await controller.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);

		await expect(
			controller.consume({
				record,
				chatId: 111,
				approverActorId: "telegram:wrong",
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: false, code: "approval_wrong_approver" });
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);
		expect(vault.signCalls).toHaveLength(0);

		await expect(
			controller.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: true, approvalId: request.nonce });
	});

	it("rejects self approval before creating a security approval row", async () => {
		const record = prepareProviderRecord({
			actorId: "telegram:actor",
			approverActorId: "telegram:actor",
		});
		const controller = createController();

		await expect(controller.request({ record, chatId: 111 })).resolves.toEqual({
			ok: false,
			code: "approval_self_approval_denied",
			reason: "side effects require approval by a distinct human approver",
			retryable: false,
		});
		expect(getPendingApprovalsForChat(111)).toEqual([]);
	});

	it("rejects wrong chat and durable body drift without consuming or minting", async () => {
		const record = prepareProviderRecord();
		const controller = createController();
		const request = await controller.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);

		await expect(
			controller.consume({
				record,
				chatId: 222,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: false, code: "approval_wrong_chat" });
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);

		getDb().prepare("UPDATE approvals SET body = ? WHERE nonce = ?").run("tampered", request.nonce);
		await expect(
			controller.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: false, code: "approval_binding_mismatch" });
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);
		expect(vault.signCalls).toHaveLength(0);
	});

	it("rejects params drift and WYSIWYG render divergence without burning the pending approval", async () => {
		const record = prepareProviderRecord();
		const controller = createController();
		const request = await controller.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);

		await expect(
			controller.consume({
				record: { ...record, params: { amount: 200, currency: "ILS" } },
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: false, code: "effect_integrity_mismatch" });
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);

		const divergentRenderController = createController({
			renderProviderApproval: () => "Transfer ILS 200 to saved recipient",
		});
		await expect(
			divergentRenderController.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: false, code: "approval_wysiwyg_mismatch" });
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);

		await expect(
			controller.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: true, approvalId: request.nonce });
	});

	it("uses the durable approval row across controller restart and fails closed if the token holder is lost", async () => {
		const record = prepareProviderRecord();
		const issuer = createController();
		const request = await issuer.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);

		const restartedRelay = createController();
		await expect(
			restartedRelay.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: true, approvalId: request.nonce });

		const lostWaiterRelay = createController();
		expect(lostWaiterRelay.takeServerSideApproval({ actionRef: record.ref, record })).toEqual({
			ok: false,
			code: "approval_token_unavailable",
			reason: "server-side approval token is unavailable",
			retryable: true,
		});
		expect(restartedRelay.takeServerSideApproval({ actionRef: record.ref, record })).toMatchObject({
			ok: true,
			approvalId: request.nonce,
		});
	});

	it("lets live MCP /approve consume the side-effect row into the server-side token holder", async () => {
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-live-approval",
			defaultTtlMs: 300_000,
			verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
				vaultClient: vault,
				jtiStore,
				nowSeconds: () => 100,
			}),
		});
		const record = ledger.prepare(providerPrepareInput({ approverActorId: "telegram:111" }));
		const controller = createController();
		setTelclaudeLiveMcpSideEffectApprovalBinding({ ledger, controller });

		await requestTelclaudeLiveMcpSideEffectApproval(controller, record);
		const [approval] = getPendingApprovalsForChat(111);
		expect(approval).toMatchObject({
			sessionKey: record.ref,
			to: "telegram:111",
			toolKey: expect.stringMatching(/^hermes\.side-effect-human-approval\.v1:sha256:/),
		});
		if (!approval) throw new Error("missing side-effect approval row");

		await expect(
			consumeTelclaudeLiveMcpSideEffectApproval({
				nonce: approval.nonce.toUpperCase(),
				chatId: 111,
			}),
		).resolves.toMatchObject({
			handled: true,
			ok: true,
			actionRef: record.ref,
			approvalId: approval.nonce,
		});
		expect(getPendingApprovalsForChat(111)).toEqual([]);
		const stored = controller.takeServerSideApproval({
			actionRef: record.ref,
			record,
			nowMs: 101_000,
		});
		expect(stored).toMatchObject({ ok: true, approvalId: approval.nonce });
		if (!stored.ok) throw new Error(stored.reason);
		await expect(ledger.authorize(record.ref, stored.approvalToken)).resolves.toMatchObject({
			ok: true,
			record: { ref: record.ref, status: "executed", approvalId: approval.nonce },
		});
		stored.finalize();
		expect(controller.takeServerSideApproval({ actionRef: record.ref, record })).toMatchObject({
			ok: false,
			code: "approval_token_unavailable",
		});
	});

	it("handles side-effect approvals without falling through to generic approve when live binding is unavailable", async () => {
		const record = prepareProviderRecord({ approverActorId: "telegram:111" });
		const controller = createController();
		await requestTelclaudeLiveMcpSideEffectApproval(controller, record);
		const [approval] = getPendingApprovalsForChat(111);
		if (!approval) throw new Error("missing side-effect approval row");

		await expect(
			consumeTelclaudeLiveMcpSideEffectApproval({
				nonce: approval.nonce,
				chatId: 111,
			}),
		).resolves.toEqual({
			handled: true,
			ok: false,
			reason: "Hermes side-effect approval runtime is unavailable; re-request approval.",
		});
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);
	});

	it("handles wrong-chat live side-effect approvals without consuming the legitimate row", async () => {
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-live-wrong-chat",
			defaultTtlMs: 300_000,
			verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
		});
		const record = ledger.prepare(providerPrepareInput({ approverActorId: "telegram:111" }));
		const controller = createController();
		setTelclaudeLiveMcpSideEffectApprovalBinding({ ledger, controller });
		await requestTelclaudeLiveMcpSideEffectApproval(controller, record);
		const [approval] = getPendingApprovalsForChat(111);
		if (!approval) throw new Error("missing side-effect approval row");

		await expect(
			consumeTelclaudeLiveMcpSideEffectApproval({
				nonce: approval.nonce,
				chatId: 222,
			}),
		).resolves.toMatchObject({
			handled: true,
			ok: false,
			reason: "This approval code belongs to a different chat.",
		});
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);
	});

	it("handles expired live side-effect approvals and deletes the expired row without minting", async () => {
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-live-expired",
			defaultTtlMs: 300_000,
			verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
		});
		const record = ledger.prepare(providerPrepareInput({ approverActorId: "telegram:111" }));
		const controller = createController();
		setTelclaudeLiveMcpSideEffectApprovalBinding({ ledger, controller });
		await requestTelclaudeLiveMcpSideEffectApproval(controller, record);
		const [approval] = getPendingApprovalsForChat(111);
		if (!approval) throw new Error("missing side-effect approval row");
		getDb()
			.prepare("UPDATE approvals SET expires_at = ? WHERE nonce = ?")
			.run(99_000, approval.nonce);

		await expect(
			consumeTelclaudeLiveMcpSideEffectApproval({
				nonce: approval.nonce,
				chatId: 111,
			}),
		).resolves.toMatchObject({
			handled: true,
			ok: false,
		});
		expect(getPendingApprovalsForChat(111)).toEqual([]);
		expect(vault.signCalls).toHaveLength(0);
	});

	it("leaves the durable approval row pending when token minting fails", async () => {
		const record = prepareProviderRecord();
		const controller = createController({
			mintApprovalToken: async () => {
				throw new Error("vault signing unavailable");
			},
		});
		const request = await controller.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);

		await expect(
			controller.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toEqual({
			ok: false,
			code: "approval_token_mint_failed",
			reason: "vault signing unavailable",
			retryable: true,
		});
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);
	});

	it("rejects expired approval rows without minting", async () => {
		const record = prepareProviderRecord();
		const controller = createController();
		const request = await controller.request({ record, chatId: 111 });
		if (!request.ok) throw new Error(request.reason);
		getDb()
			.prepare("UPDATE approvals SET expires_at = ? WHERE nonce = ?")
			.run(99_000, request.nonce);

		await expect(
			controller.consume({
				record,
				chatId: 111,
				approverActorId: record.approverActorId,
				approvalNonce: request.nonce,
			}),
		).resolves.toMatchObject({ ok: false, code: "approval_expired" });
		expect(getPendingApprovalsForChat(111)).toHaveLength(0);
		expect(vault.signCalls).toHaveLength(0);
	});

	it("auto-grants eligible private outbound replies without creating a human approval row", async () => {
		const ledger = createTelclaudeMcpSideEffectLedger({
			nowMs: () => 100_000,
			makeRef: () => "effect-auto-private",
			defaultTtlMs: 300_000,
			verifyApproval: createTelclaudeMcpSideEffectApprovalVerifier({
				vaultClient: vault,
				jtiStore,
				nowSeconds: () => 100,
			}),
		});
		const record = ledger.prepare(outboundPrepareInput());
		const controller = createController({ autoGrant: { enabled: true } });

		const request = await controller.request({ record, chatId: 111 });

		expect(request).toMatchObject({
			ok: true,
			autoGranted: true,
			nonce: "auto-effect-auto-private",
		});
		expect(getPendingApprovalsForChat(111)).toEqual([]);
		expect(vault.signCalls).toHaveLength(1);
		const stored = controller.takeServerSideApproval({
			actionRef: record.ref,
			record,
			nowMs: 101_000,
		});
		expect(stored).toMatchObject({ ok: true, approvalId: "auto-effect-auto-private" });
		if (!stored.ok) throw new Error(stored.reason);
		await expect(ledger.verify(record.ref, stored.approvalToken)).resolves.toMatchObject({
			ok: true,
			approvalId: "auto-effect-auto-private",
		});
		await expect(ledger.verify(record.ref, stored.approvalToken)).resolves.toMatchObject({
			ok: false,
			code: "approval_replayed",
		});
	});

	it("refuses auto-grant for providers, public/social outbound, and missing relay provenance", async () => {
		const controller = createController({ autoGrant: { enabled: true } });
		const provider = prepareProviderRecord();
		const social = prepareOutboundRecord({ domain: "social", profileId: "social" });
		const unproven = prepareOutboundRecord({
			approvalMetadata: {
				source: "hermes-live-mcp",
				pairedProvenance: false,
				replyCapableActorSeat: true,
			},
		});

		const providerRequest = await controller.request({ record: provider, chatId: 111 });
		const socialRequest = await controller.request({ record: social, chatId: 222 });
		const unprovenRequest = await controller.request({ record: unproven, chatId: 333 });

		expect(providerRequest).toMatchObject({ ok: true });
		expect(providerRequest).not.toHaveProperty("autoGranted");
		expect(socialRequest).toMatchObject({ ok: true });
		expect(socialRequest).not.toHaveProperty("autoGranted");
		expect(unprovenRequest).toMatchObject({ ok: true });
		expect(unprovenRequest).not.toHaveProperty("autoGranted");
		expect(getPendingApprovalsForChat(111)).toHaveLength(1);
		expect(getPendingApprovalsForChat(222)).toHaveLength(1);
		expect(getPendingApprovalsForChat(333)).toHaveLength(1);
		expect(vault.signCalls).toHaveLength(0);
	});

	function createController(
		overrides: Partial<Parameters<typeof createSideEffectHumanApprovalController>[0]> = {},
	) {
		return createSideEffectHumanApprovalController({
			nowMs: () => 100_000,
			mintApprovalToken: ({ binding, jti, ttlMs, nowMs }) =>
				generateTelclaudeMcpSideEffectApprovalToken(binding, vault, {
					nowSeconds: () => Math.floor(nowMs / 1_000),
					ttlSeconds: Math.max(1, Math.ceil(ttlMs / 1_000)),
					jti,
				}),
			...overrides,
		});
	}
});

class MockVaultClient
	implements TelclaudeMcpSideEffectApprovalSigner, TelclaudeMcpSideEffectApprovalSignatureVerifier
{
	readonly signCalls: Array<{ payload: string; prefix: string }> = [];
	readonly verifyCalls: Array<{ payload: string; signature: string; prefix: string }> = [];

	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		this.signCalls.push({ payload, prefix });
		return { type: "sign-payload", signature: signatureFor(prefix, payload) };
	}

	async verifyPayload(
		payload: string,
		signature: string,
		prefix: string,
	): Promise<{ type: string; valid: boolean }> {
		this.verifyCalls.push({ payload, signature, prefix });
		return { type: "verify-payload", valid: signature === signatureFor(prefix, payload) };
	}
}

let fixtureRefCounter = 0;

function prepareProviderRecord(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): Extract<TelclaudeMcpSideEffectRecord, { kind: "provider" }> {
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 100_000,
		makeRef: () => `effect-human-${++fixtureRefCounter}`,
		defaultTtlMs: 300_000,
		verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
	});
	const record = ledger.prepare(providerPrepareInput(overrides));
	if (record.kind !== "provider") throw new Error("expected provider record");
	return record;
}

function prepareOutboundRecord(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): Extract<TelclaudeMcpSideEffectRecord, { kind: "outbound" }> {
	const ledger = createTelclaudeMcpSideEffectLedger({
		nowMs: () => 100_000,
		makeRef: () => `effect-human-outbound-${++fixtureRefCounter}`,
		defaultTtlMs: 300_000,
		verifyApproval: async () => ({ ok: false, code: "approval_required", reason: "unused" }),
	});
	const record = ledger.prepare(outboundPrepareInput(overrides));
	if (record.kind !== "outbound") throw new Error("expected outbound record");
	return record;
}

function providerPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "telegram:123",
		approverActorId: "telegram:operator",
		profileId: "private",
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

function outboundPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const requestedBody = "I'll pick up dinner at 19:00.";
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "+15551234567",
		conversationId: "whatsapp:+15551234567",
	};
	const preparedMediaRefs: TelclaudeMcpOutboundSideEffectPrepareInput["preparedMediaRefs"] = [];
	return {
		kind: "outbound",
		actorId: "telegram:123",
		approverActorId: "telegram:operator",
		profileId: "private",
		domain: "private",
		channel: "whatsapp",
		destination: "+15551234567",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: [],
		preparedMediaRefs,
		conversationRef: `conv_${"1".repeat(32)}`,
		authorizationState: "authorized",
		edgePreparedRef: "edge-outbound-1",
		edgePreparedHash: edgePreparedPayloadHash({
			channel: "whatsapp",
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: "approval-outbound-1",
		approvalRevision: 1,
		approvalMetadata: {
			source: "hermes-live-mcp",
			pairedProvenance: true,
			replyCapableActorSeat: true,
		},
		turnConversationRef: `turn_${"1".repeat(32)}`,
		idempotencyKey: "idem-outbound-1",
		...overrides,
	};
}

function signatureFor(prefix: string, payload: string): string {
	return Buffer.from(`${prefix}\n${payload}`, "utf8").toString("base64url");
}
