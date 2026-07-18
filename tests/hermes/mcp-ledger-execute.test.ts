import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createLiveMcpProviderSidecarApprovalTokenIssuer } from "../../src/commands/relay.js";
import { sortKeysDeep } from "../../src/crypto/canonical-hash.js";
import { JtiStore, verifyApprovalToken } from "../../src/google-services/approval.js";
import type { FetchRequest } from "../../src/google-services/types.js";
import {
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
} from "../../src/hermes/edge-adapter-contract.js";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";
import {
	createTelclaudeMcpBridge,
	type TelclaudeMcpAuthority,
	type TelclaudeMcpBridgeDependencies,
} from "../../src/hermes/mcp/bridge.js";
import { createTelclaudeMcpLedgerExecuteDependencies } from "../../src/hermes/mcp/ledger-execute.js";
import { createNotConfiguredTelclaudeMcpCapabilityClients } from "../../src/hermes/mcp/live-relay-clients.js";
import { createGoogleProviderSidecarApprovalTokenIssuer } from "../../src/hermes/mcp/provider-sidecar-token.js";
import {
	createTelclaudeMcpSideEffectLedger,
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpOutboundSideEffectPrepareInput,
	type TelclaudeMcpProviderSideEffectPrepareInput,
	type TelclaudeMcpScheduledOutboundSideEffectPrepareInput,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalVerification,
	type TelclaudeMcpSideEffectLedger,
	type TelclaudeMcpSideEffectRecord,
} from "../../src/hermes/mcp/side-effect-ledger.js";
import type {
	RelayConversation,
	RelayConversationInboundTurn,
} from "../../src/hermes/relay-conversation-store.js";
import type { OutboundDeliveryDispatcher } from "../../src/relay/outbound-delivery-dispatcher.js";
import type { ResolvedWhatsAppHouseholdReplyBinding } from "../../src/relay/whatsapp-household-bindings.js";
import { GOOGLE_APPROVAL_SIGNING_PREFIX } from "../../src/security/approval-domains.js";

describe("Telclaude MCP ledger execute dependencies", () => {
	it("authorizes provider and outbound executes through server-side approval resolution", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness);
		const provider = harness.ledger.prepare(providerPrepareInput());
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("provider-token", provider);
		harness.accept("outbound-token", outbound);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
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
		).rejects.toThrow();
		await expect(
			bridge.tc_outbound_execute({
				outboundRef: outbound.ref,
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

	it("binds outbound approval and execution to the stamped relay turn authority", async () => {
		const harness = createLedgerHarness();
		const turnConversationRef = `turn_${"a".repeat(32)}`;
		const outbound = harness.ledger.prepare(outboundPrepareInput({ turnConversationRef }));
		expect(getTelclaudeMcpSideEffectApprovalBinding(outbound)).toMatchObject({
			turnConversationRef,
		});
		harness.accept("outbound-turn-token", outbound);
		const turnRequests: unknown[] = [];
		const bridge = createBridge(
			harness,
			{
				resolveAuthorizedInboundTurn: (request) => {
					turnRequests.push(request);
					return fixtureInboundTurn({
						ref: turnConversationRef,
						conversationToken: outbound.conversationRef,
						conversationId: outbound.resolvedDestination.conversationId ?? "",
					});
				},
			},
			{ turnConversationRef },
		);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: outbound.ref,
				status: "executed",
				approvalId: "outbound-turn-token",
				turnConversationRef,
			}),
		});
		expect(turnRequests).toEqual([
			expect.objectContaining({
				turnConversationRef,
				expectedConversationRef: outbound.conversationRef,
				actorId: "operator",
				profileId: "ops",
				domain: "private",
				channel: "whatsapp",
				conversationId: outbound.resolvedDestination.conversationId,
				nowMs: 100_000,
			}),
		]);
		expect(harness.resolverCalls).toEqual([
			expect.objectContaining({ actionRef: outbound.ref, recordRef: outbound.ref }),
		]);
		expect(harness.verifierCalls).toHaveLength(1);
	});

	it("rejects missing or wrong execute turn authority before approval resolution", async () => {
		const harness = createLedgerHarness();
		const turnConversationRef = `turn_${"a".repeat(32)}`;
		const outbound = harness.ledger.prepare(outboundPrepareInput({ turnConversationRef }));
		harness.accept("outbound-turn-token", outbound);
		const turnRequests: unknown[] = [];
		const options = {
			resolveAuthorizedInboundTurn: (
				request: Parameters<
					NonNullable<
						Parameters<
							typeof createTelclaudeMcpLedgerExecuteDependencies
						>[0]["resolveAuthorizedInboundTurn"]
					>
				>[0],
			) => {
				turnRequests.push(request);
				return fixtureInboundTurn({
					ref: turnConversationRef,
					conversationToken: outbound.conversationRef,
					conversationId: outbound.resolvedDestination.conversationId ?? "",
				});
			},
		};

		await expect(
			createBridge(harness, options).tc_outbound_execute({ outboundRef: outbound.ref }),
		).resolves.toEqual({
			ok: false,
			code: "effect_turn_authority_mismatch",
			reason: "side effect turn authority mismatch",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		await expect(
			createBridge(harness, options, {
				turnConversationRef: `turn_${"b".repeat(32)}`,
			}).tc_outbound_execute({ outboundRef: outbound.ref }),
		).resolves.toEqual({
			ok: false,
			code: "effect_turn_authority_mismatch",
			reason: "side effect turn authority mismatch",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(turnRequests).toEqual([]);
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rejects unavailable live turn authority before consuming approval tokens", async () => {
		const harness = createLedgerHarness();
		const turnConversationRef = `turn_${"a".repeat(32)}`;
		const outbound = harness.ledger.prepare(outboundPrepareInput({ turnConversationRef }));
		harness.accept("outbound-turn-token", outbound);
		const turnRequests: unknown[] = [];
		const bridge = createBridge(
			harness,
			{
				resolveAuthorizedInboundTurn: (request) => {
					turnRequests.push(request);
					return null;
				},
			},
			{ turnConversationRef },
		);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "effect_turn_authority_unavailable",
			reason: "side effect turn authority is unavailable",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(turnRequests).toHaveLength(1);
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("binds provider side-effect approvals to stamped turn refs when present", async () => {
		const harness = createLedgerHarness();
		const turnConversationRef = `turn_${"a".repeat(32)}`;
		const provider = harness.ledger.prepare(providerPrepareInput({ turnConversationRef }));
		expect(getTelclaudeMcpSideEffectApprovalBinding(provider)).toMatchObject({
			turnConversationRef,
		});
		harness.accept("provider-turn-token", provider);

		await expect(
			createBridge(harness).tc_provider_execute_write({ actionRef: provider.ref }),
		).resolves.toEqual({
			ok: false,
			code: "effect_turn_authority_mismatch",
			reason: "side effect turn authority mismatch",
			retryable: false,
			record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("surfaces missing server-side approvals as retryable without executing the prepared ref", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness);
		const provider = harness.ledger.prepare(providerPrepareInput());

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
			}),
		).resolves.toEqual({
			ok: false,
			code: "approval_token_unavailable",
			reason: "server-side approval token is unavailable",
			retryable: true,
			record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		});
		expect(harness.verifierCalls).toHaveLength(0);
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});

	it("rejects Hermes-supplied provider approval tokens at the bridge boundary", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness);
		const provider = harness.ledger.prepare(providerPrepareInput());
		harness.accept("provider-token", provider);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
				approvalToken: "provider-token",
			}),
		).rejects.toThrow();
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});

	it("rejects outbound body provenance drift before resolving the approval token", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness);
		const outbound = harness.ledger.prepare(
			outboundPrepareInput({ renderedBody: "I'll pick up dinner at 20:00." }),
		);
		harness.accept("outbound-token", outbound);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_body_provenance_mismatch",
			reason: "outbound rendered body does not match the approved requested body",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("fails closed when outbound execution has no live conversation resolver", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness, { resolveAuthorizedOutboundConversation: undefined });
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_conversation_resolver_missing",
			reason: "outbound conversation authorization resolver is not configured",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rechecks live outbound conversation authorization before resolving approvals", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness, { resolveAuthorizedOutboundConversation: () => null });
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_conversation_not_authorized",
			reason: "outbound conversation is not authorized for execution",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rejects self-consistent forged outbound recipients that do not match the live conversation", async () => {
		const harness = createLedgerHarness();
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);
		const bridge = createBridge(harness, {
			resolveAuthorizedOutboundConversation: () =>
				fixtureConversation({
					token: outbound.conversationRef,
					conversationId: "whatsapp:other-conversation",
				}),
		});

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_conversation_mismatch",
			reason: "outbound conversation does not match persisted recipient binding",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rejects outbound conversations with no reply-capable actor seat before approval verification", async () => {
		const harness = createLedgerHarness();
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);
		const bridge = createBridge(harness, {
			resolveAuthorizedOutboundConversation: () =>
				fixtureConversation({
					token: outbound.conversationRef,
					conversationId: outbound.resolvedDestination.conversationId,
					members: [],
				}),
		});

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_recipient_not_targetable",
			reason: "outbound conversation has no reply-capable seat for the actor",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rejects outbound conversations whose actor seat lost message:reply before approval verification", async () => {
		const harness = createLedgerHarness();
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);
		const bridge = createBridge(harness, {
			resolveAuthorizedOutboundConversation: () =>
				fixtureConversation({
					token: outbound.conversationRef,
					conversationId: outbound.resolvedDestination.conversationId,
					members: [
						{
							actorId: "operator",
							channel: "whatsapp",
							principalId: "+15551234567",
							principalHash:
								"sha256:1111111111111111111111111111111111111111111111111111111111111111",
							role: "sender",
							identityAssurance: "strong_link",
							scopes: [],
							revoked: false,
						},
					],
				}),
		});

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_recipient_not_targetable",
			reason: "outbound conversation has no reply-capable seat for the actor",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rejects household execution when the live actor seat principal changed", async () => {
		const harness = createLedgerHarness();
		const outbound = harness.ledger.prepare(householdOutboundPrepareInput());
		harness.accept("outbound-household-token", outbound);
		const bridge = createBridge(
			harness,
			{
				resolveAuthorizedOutboundConversation: () =>
					fixtureConversation({
						token: outbound.conversationRef,
						conversationId: outbound.resolvedDestination.conversationId,
						profileId: "parent-a",
						domain: "household",
						mcpDomain: "household",
						edgeDomain: "household",
						members: [
							{
								actorId: "household:whatsapp:parent-a",
								channel: "whatsapp",
								principalId: "+15550000000",
								principalHash:
									"sha256:2222222222222222222222222222222222222222222222222222222222222222",
								role: "sender",
								identityAssurance: "strong_link",
								scopes: ["message:reply"],
								revoked: false,
							},
						],
					}),
			},
			{
				actorId: "household:whatsapp:parent-a",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
				domain: "household",
				memorySource: "household:parent-a",
				writableNamespace: "household:parent-a",
			},
		);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_recipient_not_targetable",
			reason: "outbound household recipient no longer matches the live actor seat",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it("rejects household execution when the live turn sender principal changed", async () => {
		const harness = createLedgerHarness();
		const turnConversationRef = `turn_${"c".repeat(32)}`;
		const outbound = harness.ledger.prepare(householdOutboundPrepareInput({ turnConversationRef }));
		harness.accept("outbound-household-turn-token", outbound);
		const bridge = createBridge(
			harness,
			{
				resolveAuthorizedInboundTurn: () =>
					fixtureInboundTurn({
						ref: turnConversationRef,
						conversationToken: outbound.conversationRef,
						conversationId: outbound.resolvedDestination.conversationId ?? "",
						profileId: "parent-a",
						domain: "household",
						mcpDomain: "household",
						senderActorId: "household:whatsapp:parent-a",
						senderPrincipalId: "+15550000000",
					}),
			},
			{
				actorId: "household:whatsapp:parent-a",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
				domain: "household",
				memorySource: "household:parent-a",
				writableNamespace: "household:parent-a",
				turnConversationRef,
			},
		);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "effect_turn_authority_mismatch",
			reason: "side effect turn authority mismatch",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.verifierCalls).toHaveLength(0);
	});

	it.each([
		{
			name: "pairing was removed",
			resolution: null,
			code: "household_reply_binding_unavailable",
		},
		{
			name: "binding id changed",
			resolution: resolvedHouseholdReplyBinding({ bindingId: "parent-b" }),
			code: "household_reply_binding_mismatch",
		},
		{
			name: "subject changed",
			resolution: resolvedHouseholdReplyBinding({ subjectUserId: "household:parent-b" }),
			code: "household_reply_binding_mismatch",
		},
		{
			name: "recipient number changed",
			resolution: resolvedHouseholdReplyBinding({
				principalId: "+15550000000",
				replyPrincipalId: "+15550000000",
			}),
			code: "household_reply_binding_mismatch",
		},
	])("rejects household execution when $name before token consumption", async ({
		resolution,
		code,
	}) => {
		const harness = createLedgerHarness();
		const turnConversationRef = `turn_${"d".repeat(32)}`;
		const outbound = harness.ledger.prepare(householdOutboundPrepareInput({ turnConversationRef }));
		harness.accept("outbound-household-binding-token", outbound);
		let bindingResolverCalls = 0;
		let dispatcherCalls = 0;
		const bridge = createBridge(
			harness,
			{
				resolveAuthorizedInboundTurn: () =>
					fixtureInboundTurn({
						ref: turnConversationRef,
						conversationToken: outbound.conversationRef,
						conversationId: outbound.resolvedDestination.conversationId ?? "",
						profileId: "parent-a",
						domain: "household",
						mcpDomain: "household",
						senderActorId: "household:whatsapp:parent-a",
						senderPrincipalId: "+15551234567",
					}),
				resolveAuthorizedOutboundConversation: () =>
					fixtureConversation({
						token: outbound.conversationRef,
						conversationId: outbound.resolvedDestination.conversationId,
						profileId: "parent-a",
						domain: "household",
						mcpDomain: "household",
						edgeDomain: "household",
						humanPairingProvenance: true,
						members: [
							{
								actorId: "household:whatsapp:parent-a",
								channel: "whatsapp",
								principalId: "+15551234567",
								principalHash:
									"sha256:1111111111111111111111111111111111111111111111111111111111111111",
								role: "sender",
								identityAssurance: "strong_link",
								scopes: ["message:reply"],
								revoked: false,
							},
						],
					}),
				resolveHouseholdReplyBinding: () => {
					bindingResolverCalls += 1;
					return resolution;
				},
				outboundDeliveryDispatcher: async (prepared) => {
					dispatcherCalls += 1;
					return sentOutboundDeliveryDispatcher(prepared);
				},
			},
			{
				actorId: "household:whatsapp:parent-a",
				subjectUserId: "household:parent-a",
				profileId: "parent-a",
				domain: "household",
				memorySource: "household:parent-a",
				writableNamespace: "household:parent-a",
				turnConversationRef,
			},
		);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code,
			reason: expect.any(String),
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(bindingResolverCalls).toBe(1);
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
		expect(dispatcherCalls).toBe(0);
	});

	it("accepts social MCP domain outbound records against public-social relay conversations", async () => {
		const harness = createLedgerHarness();
		const base = outboundPrepareInput();
		const resolvedDestination = {
			kind: "address" as const,
			addressRef: "@public-social-user",
			conversationId: "public-social-conversation",
		};
		const outbound = harness.ledger.prepare({
			...base,
			profileId: "social",
			domain: "social",
			destination: "@public-social-user",
			resolvedDestination,
			conversationRef: "conv_social",
			edgePreparedHash: edgePreparedPayloadHash({
				channel: base.channel,
				resolvedDestination,
				body: base.requestedBody,
				mediaRefs: base.preparedMediaRefs,
			}),
		});
		harness.accept("outbound-social-token", outbound);
		const bridge = createBridge(
			harness,
			{
				resolveAuthorizedOutboundConversation: () =>
					fixtureConversation({
						token: "conv_social",
						conversationId: "public-social-conversation",
						profileId: "social",
						domain: "public-social",
						mcpDomain: "social",
						edgeDomain: "public-social",
					}),
			},
			{ profileId: "social", domain: "social" },
		);

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: outbound.ref,
				status: "executed",
				approvalId: "outbound-social-token",
			}),
		});
	});

	it("executes prepared WhatsApp outbound through the outbound delivery dispatcher", async () => {
		const harness = createLedgerHarness();
		const resolvedDestination = {
			kind: "address" as const,
			addressRef: "whatsapp:+15551234567",
			conversationId: "whatsapp:+15551234567",
		};
		const outbound = harness.ledger.prepare(
			outboundPrepareInput({
				preparedMediaRefs: [
					{
						quarantineId: "attachment:menu",
						contentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						mediaType: "application/pdf",
						sizeBytes: 1234,
						redactedFilename: "provider-statement.pdf",
					},
				],
				destination: "model-facing label that must not be used for delivery",
				resolvedDestination,
				edgePreparedHash: edgePreparedPayloadHash({
					channel: "whatsapp",
					resolvedDestination,
					body: "I'll pick up dinner at 19:00.",
					mediaRefs: [
						{
							quarantineId: "attachment:menu",
							contentHash:
								"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							mediaType: "application/pdf",
							sizeBytes: 1234,
							redactedFilename: "provider-statement.pdf",
						},
					],
				}),
			}),
		);
		harness.accept("outbound-token", outbound);
		const dispatched: PreparedOutbound[] = [];
		const dispatcher: OutboundDeliveryDispatcher = async (prepared) => {
			dispatched.push(prepared);
			return {
				schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
				outboundRef: prepared.outboundRef,
				platformMessageId: "wa-msg-1",
				deliveryStatus: "sent",
				timestamps: {
					observedAt: "2026-06-04T00:00:00.000Z",
					sentAt: "2026-06-04T00:00:00.000Z",
				},
				retry: {
					attempt: 1,
					maxAttempts: prepared.retryPolicy.maxAttempts,
					idempotencyKey: prepared.idempotencyKey,
				},
			};
		};
		const bridge = createBridge(harness, {
			outboundDeliveryDispatcher: dispatcher,
			resolveAuthorizedOutboundConversation: () =>
				fixtureConversation({
					token: outbound.conversationRef,
					conversationId: outbound.resolvedDestination.conversationId,
					threadMessageIds: ["wa-thread-1"],
				}),
		});

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({
				ref: outbound.ref,
				status: "executed",
				approvalId: "outbound-token",
			}),
		});
		expect(dispatched).toHaveLength(1);
		expect(dispatched[0]).toMatchObject({
			outboundRef: outbound.edgePreparedRef,
			channel: "whatsapp",
			resolvedDestination,
			finalRenderedBody: outbound.renderedBody,
			idempotencyKey: outbound.idempotencyKey,
			mediaRefs: [
				expect.objectContaining({
					mediaType: "application/pdf",
					sizeBytes: 1234,
					redactedFilename: "provider-statement.pdf",
				}),
			],
		});
	});

	it("executes a legacy prepared outbound with the pre-D5 attachment fallback", async () => {
		const harness = createLedgerHarness();
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("legacy-outbound-token", outbound);
		const dispatched: PreparedOutbound[] = [];
		const bridge = createBridge(harness, {
			outboundDeliveryDispatcher: async (prepared) => {
				dispatched.push(prepared);
				return {
					schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
					outboundRef: prepared.outboundRef,
					deliveryStatus: "sent" as const,
					timestamps: { observedAt: "2026-06-04T00:00:00.000Z" },
					retry: {
						attempt: 1,
						maxAttempts: prepared.retryPolicy.maxAttempts,
						idempotencyKey: prepared.idempotencyKey,
					},
				};
			},
			resolveAuthorizedOutboundConversation: () =>
				fixtureConversation({
					token: outbound.conversationRef,
					conversationId: outbound.resolvedDestination.conversationId,
				}),
		});

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toMatchObject({
			ok: true,
		});
		expect(dispatched[0]?.mediaRefs[0]).toMatchObject({
			mediaType: "application/octet-stream",
			sizeBytes: 0,
		});
		expect(dispatched[0]?.mediaRefs[0]).not.toHaveProperty("redactedFilename");
	});

	it("executes scheduled outbound only through the internal system authorizer with immediate revalidation", async () => {
		const harness = createLedgerHarness();
		const scheduled = harness.ledger.prepare(scheduledOutboundPrepareInput());
		harness.accept("scheduled-token", scheduled);
		const dispatched: PreparedOutbound[] = [];
		const ordering: string[] = [];
		let authorizeCalls = 0;
		let immediateRevalidationCalls = 0;
		const scheduledOutboundAuthorizer = Object.assign(
			async () => {
				authorizeCalls += 1;
				return {
					ok: true as const,
					approvalToken: "scheduled-token",
					approvalId: "scheduled-token",
				};
			},
			{
				revalidate: async () => {
					immediateRevalidationCalls += 1;
					ordering.push("revalidate");
					return { ok: true as const };
				},
			},
		);
		const dependencies = createTelclaudeMcpLedgerExecuteDependencies({
			ledger: harness.ledger,
			scheduledOutboundAuthorizer,
			outboundDeliveryDispatcher: async (prepared) => {
				ordering.push("dispatch");
				dispatched.push(prepared);
				return sentOutboundDeliveryDispatcher(prepared);
			},
			nowMs: harness.nowMs,
		});

		await expect(
			dependencies.scheduledOutboundExecute({
				outboundRef: scheduled.ref,
				beforeDispatch: () => {
					ordering.push("fire-cas");
					return true;
				},
			}),
		).resolves.toEqual({
			ok: true,
			receipt: expect.objectContaining({
				outboundRef: scheduled.edgePreparedRef,
				deliveryStatus: "sent",
			}),
			record: expect.objectContaining({
				ref: scheduled.ref,
				kind: "scheduled-outbound",
				status: "executed",
				approvalId: "scheduled-token",
			}),
		});
		expect(authorizeCalls).toBe(1);
		expect(immediateRevalidationCalls).toBe(1);
		expect(ordering).toEqual(["revalidate", "fire-cas", "dispatch"]);
		expect(dispatched).toEqual([
			expect.objectContaining({
				outboundRef: scheduled.edgePreparedRef,
				resolvedDestination: scheduled.resolvedDestination,
				finalRenderedBody: scheduled.renderedBody,
				mediaRefs: [],
				idempotencyKey: scheduled.idempotencyKey,
			}),
		]);
		expect(harness.resolverCalls).toEqual([]);
	});

	it("fails a claimed scheduled outbound terminally when immediate policy revalidation drifts", async () => {
		const harness = createLedgerHarness();
		const scheduled = harness.ledger.prepare(scheduledOutboundPrepareInput());
		harness.accept("scheduled-token", scheduled);
		let dispatcherCalls = 0;
		const dependencies = createTelclaudeMcpLedgerExecuteDependencies({
			ledger: harness.ledger,
			scheduledOutboundAuthorizer: Object.assign(
				async () => ({
					ok: true as const,
					approvalToken: "scheduled-token",
					approvalId: "scheduled-token",
				}),
				{
					revalidate: async () => ({
						ok: false as const,
						code: "reminder_binding_drift",
						reason: "household reminder binding or consent changed",
						retryable: false as const,
					}),
				},
			),
			outboundDeliveryDispatcher: async (prepared) => {
				dispatcherCalls += 1;
				return sentOutboundDeliveryDispatcher(prepared);
			},
			nowMs: harness.nowMs,
		});

		await expect(
			dependencies.scheduledOutboundExecute({
				outboundRef: scheduled.ref,
				beforeDispatch: () => true,
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "reminder_binding_drift",
			retryable: false,
			record: { ref: scheduled.ref, status: "failed" },
		});
		expect(dispatcherCalls).toBe(0);
		expect(harness.ledger.get(scheduled.ref)).toMatchObject({ status: "failed" });
	});

	it("fails a claimed scheduled outbound before transport when the fire CAS loses", async () => {
		const harness = createLedgerHarness();
		const scheduled = harness.ledger.prepare(scheduledOutboundPrepareInput());
		harness.accept("scheduled-token", scheduled);
		let dispatcherCalls = 0;
		const dependencies = createTelclaudeMcpLedgerExecuteDependencies({
			ledger: harness.ledger,
			scheduledOutboundAuthorizer: Object.assign(
				async () => ({
					ok: true as const,
					approvalToken: "scheduled-token",
					approvalId: "scheduled-token",
				}),
				{ revalidate: async () => ({ ok: true as const }) },
			),
			outboundDeliveryDispatcher: async (prepared) => {
				dispatcherCalls += 1;
				return sentOutboundDeliveryDispatcher(prepared);
			},
			nowMs: harness.nowMs,
		});

		await expect(
			dependencies.scheduledOutboundExecute({
				outboundRef: scheduled.ref,
				beforeDispatch: () => false,
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "scheduled_outbound_fire_cas_failed",
			retryable: false,
			record: { ref: scheduled.ref, status: "failed" },
		});
		expect(dispatcherCalls).toBe(0);
	});

	it("keeps scheduled execution out of the MCP bridge and rejects standard records", async () => {
		const harness = createLedgerHarness();
		const dependencies = createTelclaudeMcpLedgerExecuteDependencies({
			ledger: harness.ledger,
			nowMs: harness.nowMs,
		});
		const standard = harness.ledger.prepare(outboundPrepareInput());
		const bridge = createBridge(harness);

		expect(bridge).not.toHaveProperty("tc_scheduled_outbound_execute");
		await expect(
			dependencies.scheduledOutboundExecute({
				outboundRef: standard.ref,
				beforeDispatch: () => true,
			}),
		).resolves.toMatchObject({
			ok: false,
			code: "effect_kind_mismatch",
			retryable: false,
		});
	});

	it("fails closed before approval resolution when WhatsApp outbound has no dispatcher", async () => {
		const harness = createLedgerHarness();
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);
		const bridge = createBridge(harness, { outboundDeliveryDispatcher: undefined });

		await expect(bridge.tc_outbound_execute({ outboundRef: outbound.ref })).resolves.toEqual({
			ok: false,
			code: "outbound_delivery_dispatcher_missing",
			reason: "outbound delivery dispatcher is not configured for WhatsApp",
			retryable: false,
			record: expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		});
		expect(harness.resolverCalls).toHaveLength(0);
		expect(harness.verifierCalls).toHaveLength(0);
		expect(harness.ledger.get(outbound.ref)).toEqual(
			expect.objectContaining({ ref: outbound.ref, status: "prepared" }),
		);
	});

	it("rejects provider self-approval before verifier or sidecar execution", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(providerPrepareInput({ approverActorId: "operator" }));
		harness.accept("provider-token", provider);
		const providerCalls: unknown[] = [];
		const bridge = createBridge(harness, {
			providerProxy: async (request) => {
				providerCalls.push(request);
				return { status: "ok", data: { accepted: true } };
			},
			providerApprovalTokenIssuer: () => "sidecar-token",
		});

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
			}),
		).resolves.toEqual({
			ok: false,
			code: "provider_distinct_human_approver_required",
			reason: "provider side effects require approval by a distinct human approver",
			retryable: false,
			record: expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		});
		expect(harness.verifierCalls).toHaveLength(0);
		expect(providerCalls).toEqual([]);
		expect(harness.ledger.get(provider.ref)).toEqual(
			expect.objectContaining({ ref: provider.ref, status: "prepared" }),
		);
	});

	it("rejects kind mismatches before verification and leaves the ref prepared", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness);
		const outbound = harness.ledger.prepare(outboundPrepareInput());
		harness.accept("outbound-token", outbound);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: outbound.ref,
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
		const bridge = createBridge(harness);
		const provider = harness.ledger.prepare(providerPrepareInput({ actorId: "other-actor" }));
		harness.accept("provider-token", provider);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
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

	it("rejects provider scope mismatches before verification and leaves the ref prepared", async () => {
		const harness = createLedgerHarness();
		const bridge = createBridge(harness);
		const provider = harness.ledger.prepare(
			providerPrepareInput({
				providerId: "clalit",
				service: "clalit",
				action: "appointments.cancel",
				params: { appointmentId: "appt_123" },
				providerAccountRef: "clalit:primary",
			}),
		);
		harness.accept("provider-token", provider);

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
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
		const bridge = createBridge(harness);
		const revoked = harness.ledger.prepare(providerPrepareInput());
		const expired = harness.ledger.prepare(providerPrepareInput({ ttlMs: 10_000 }));
		const replayed = harness.ledger.prepare(providerPrepareInput());
		harness.accept("replayed-token", replayed);
		harness.ledger.revoke(revoked.ref, "operator cancelled");

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: revoked.ref,
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
		});
		await expect(
			bridge.tc_provider_execute_write({
				actionRef: replayed.ref,
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

	it("executes provider sidecars through the relay proxy with a sidecar-verifiable token after ledger authorization", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(
			providerPrepareInput({
				providerId: "google",
				service: "gmail",
				action: "create_draft",
				params: { to: "a@example.com", subject: "hello", body: "hello" },
				subjectUserId: "admin",
				providerAccountRef: "google:gmail:primary",
			}),
		);
		harness.accept("provider-token", provider);
		const providerCalls: unknown[] = [];
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-hermes-ledger-sidecar-"));
		const jtiStore = new JtiStore(tempDir);
		const vault = new PrefixSigningVault();
		const bridge = createBridge(
			harness,
			{
				providerProxy: async (request) => {
					providerCalls.push(request);
					expect(request.approvalToken).toMatch(/^v1\./);
					expect(request.approvalToken).not.toBe("provider-token");
					const sidecarResult = verifyApprovalToken(
						request.approvalToken ?? "",
						JSON.parse(String(request.body)) as FetchRequest,
						request.userId ?? "",
						(payload, signature) =>
							vault.verifySignature(payload, signature, GOOGLE_APPROVAL_SIGNING_PREFIX),
						jtiStore,
					);
					expect(sidecarResult).toEqual({ ok: true });
					return { status: "ok", data: { draftId: "draft_123" } };
				},
				providerApprovalTokenIssuer: createGoogleProviderSidecarApprovalTokenIssuer({
					vaultClient: vault,
				}),
			},
			{ providerScopes: ["google"] },
		);

		try {
			await expect(
				bridge.tc_provider_execute_write({
					actionRef: provider.ref,
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
				expect.objectContaining({
					providerId: "google",
					path: "/v1/fetch",
					method: "POST",
					body: JSON.stringify({
						service: "gmail",
						action: "create_draft",
						params: { to: "a@example.com", subject: "hello", body: "hello" },
						subjectUserId: "admin",
					}),
					userId: "operator",
					approvalToken: expect.stringMatching(/^v1\./),
					approvalMode: "preapproved-ledger",
				}),
			]);
			expect(JSON.stringify(providerCalls)).not.toContain("provider-token");
		} finally {
			jtiStore.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("executes a Clalit renewal through the issuer configured by the live relay", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(
			providerPrepareInput({
				actorId: "household:whatsapp:parent-b",
				approverActorId: "telegram:parent-a",
				profileId: "parent-b",
				domain: "household",
				providerId: "clalit",
				service: "clalit",
				action: "prescription_renewal",
				params: { prescriptionId: "synthetic-rx" },
				subjectUserId: "household:parent-b",
				providerAccountRef: "clalit:primary",
			}),
		);
		harness.accept("provider-token", provider);
		const vault = new PrefixSigningVault();
		const providerCalls: unknown[] = [];
		const bridge = createBridge(
			harness,
			{
				providerProxy: async (request) => {
					providerCalls.push(request);
					expect(claimsFromApprovalToken(request.approvalToken ?? "")).toMatchObject({
						aud: "israel-services",
						providerId: "clalit",
						service: "clalit",
						action: "prescription_renewal",
						subjectUserId: "household:parent-b",
					});
					return { status: "ok", data: { accepted: true } };
				},
				providerApprovalTokenIssuer: createLiveMcpProviderSidecarApprovalTokenIssuer(vault),
			},
			{
				actorId: "household:whatsapp:parent-b",
				profileId: "parent-b",
				domain: "household",
				memorySource: "household:parent-b",
				writableNamespace: "household:parent-b",
				providerScopes: ["clalit"],
			},
		);

		await expect(bridge.tc_provider_execute_write({ actionRef: provider.ref })).resolves.toEqual({
			ok: true,
			record: expect.objectContaining({ ref: provider.ref, status: "executed" }),
		});
		expect(providerCalls).toEqual([
			expect.objectContaining({
				providerId: "clalit",
				body: JSON.stringify({
					service: "clalit",
					action: "prescription_renewal",
					params: { prescriptionId: "synthetic-rx" },
					subjectUserId: "household:parent-b",
				}),
				userId: "household:whatsapp:parent-b",
				approvalToken: expect.stringMatching(/^v1\./),
				approvalMode: "preapproved-ledger",
			}),
		]);
	});

	it("fails closed before provider sidecar execution when no sidecar token issuer is configured", async () => {
		const harness = createLedgerHarness();
		const provider = harness.ledger.prepare(providerPrepareInput());
		harness.accept("provider-token", provider);
		const providerCalls: unknown[] = [];
		const bridge = createBridge(harness, {
			providerProxy: async (request) => {
				providerCalls.push(request);
				return { status: "ok", data: { accepted: true } };
			},
		});

		await expect(
			bridge.tc_provider_execute_write({
				actionRef: provider.ref,
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
		const bridge = createBridge(harness, {
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
	readonly resolverCalls: Array<{ readonly actionRef: string; readonly recordRef: string }>;
	readonly accept: (token: string, record: TelclaudeMcpSideEffectRecord) => void;
	readonly setNowMs: (nowMs: number) => void;
	readonly nowMs: () => number;
	readonly resolveSideEffectApprovalToken: Parameters<
		typeof createTelclaudeMcpLedgerExecuteDependencies
	>[0]["sideEffectApprovalTokenResolver"];
} {
	let nowMs = 100_000;
	let refCounter = 0;
	const accepted = new Map<string, string>();
	const serverApprovals = new Map<
		string,
		{ readonly approvalToken: string; readonly binding: string }
	>();
	const verifierCalls: TelclaudeMcpSideEffectApprovalVerification[] = [];
	const resolverCalls: Array<{ readonly actionRef: string; readonly recordRef: string }> = [];
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
		resolverCalls,
		accept(token, record) {
			const binding = canonicalBinding(getTelclaudeMcpSideEffectApprovalBinding(record));
			accepted.set(token, binding);
			serverApprovals.set(record.ref, { approvalToken: token, binding });
		},
		setNowMs(nextNowMs) {
			nowMs = nextNowMs;
		},
		nowMs() {
			return nowMs;
		},
		resolveSideEffectApprovalToken({ actionRef, record }) {
			resolverCalls.push({ actionRef, recordRef: record.ref });
			const stored = serverApprovals.get(actionRef);
			if (!stored) {
				return {
					ok: false,
					code: "approval_token_unavailable",
					reason: "server-side approval token is unavailable",
					retryable: true,
				};
			}
			if (stored.binding !== canonicalBinding(getTelclaudeMcpSideEffectApprovalBinding(record))) {
				return {
					ok: false,
					code: "approval_binding_mismatch",
					reason: "server-side approval binding mismatch",
					retryable: false,
				};
			}
			return {
				ok: true,
				approvalToken: stored.approvalToken,
				finalize: () => {
					serverApprovals.delete(actionRef);
				},
			};
		},
	};
}

function createBridge(
	harness: ReturnType<typeof createLedgerHarness>,
	options: Omit<Parameters<typeof createTelclaudeMcpLedgerExecuteDependencies>[0], "ledger"> = {},
	authorityOverrides: Partial<TelclaudeMcpAuthority> = {},
) {
	const hasOutboundResolver = Object.hasOwn(options, "resolveAuthorizedOutboundConversation");
	const hasOutboundDispatcher = Object.hasOwn(options, "outboundDeliveryDispatcher");
	return createTelclaudeMcpBridge(baseAuthority(authorityOverrides), {
		...baseDependencies(),
		...createTelclaudeMcpLedgerExecuteDependencies({
			ledger: harness.ledger,
			sideEffectApprovalTokenResolver:
				options.sideEffectApprovalTokenResolver ?? harness.resolveSideEffectApprovalToken,
			resolveAuthorizedOutboundConversation: hasOutboundResolver
				? options.resolveAuthorizedOutboundConversation
				: resolveFixtureConversation,
			outboundDeliveryDispatcher: hasOutboundDispatcher
				? options.outboundDeliveryDispatcher
				: sentOutboundDeliveryDispatcher,
			nowMs: options.nowMs ?? harness.nowMs,
			...options,
		}),
	});
}

const sentOutboundDeliveryDispatcher: OutboundDeliveryDispatcher = async (prepared) => ({
	schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
	outboundRef: prepared.outboundRef,
	platformMessageId: "wa-default-msg",
	deliveryStatus: "sent",
	timestamps: {
		observedAt: "2026-06-04T00:00:00.000Z",
		sentAt: "2026-06-04T00:00:00.000Z",
	},
	retry: {
		attempt: 1,
		maxAttempts: prepared.retryPolicy.maxAttempts,
		idempotencyKey: prepared.idempotencyKey,
	},
});

function resolveFixtureConversation(conversationRef: string): RelayConversation {
	return fixtureConversation({
		token: conversationRef,
		conversationId: conversationRef,
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
		...createNotConfiguredTelclaudeMcpCapabilityClients(),
	};
}

function providerPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpProviderSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpProviderSideEffectPrepareInput {
	return {
		kind: "provider",
		actorId: "operator",
		approverActorId: "operator:provider-approver",
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

function outboundPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	const channel = "whatsapp";
	const requestedBody = "I'll pick up dinner at 19:00.";
	const resolvedDestination = {
		kind: "address" as const,
		addressRef: "+15551234567",
		conversationId: "whatsapp:+15551234567",
	};
	const preparedMediaRefs = [
		{
			quarantineId: "attachment:menu",
			contentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	];
	return {
		kind: "outbound" as const,
		actorId: "operator",
		approverActorId: "operator:outbound-approver",
		profileId: "ops",
		domain: "private" as const,
		channel,
		destination: "+15551234567",
		resolvedDestination,
		requestedBody,
		renderedBody: requestedBody,
		mediaRefs: ["attachment:menu"],
		preparedMediaRefs,
		conversationRef: "whatsapp:+15551234567",
		authorizationState: "authorized" as const,
		edgePreparedRef: "edge-outbound-1",
		edgePreparedHash: edgePreparedPayloadHash({
			channel,
			resolvedDestination,
			body: requestedBody,
			mediaRefs: preparedMediaRefs,
		}),
		approvalRequestId: "approval-outbound-1",
		approvalRevision: 1,
		approvalMetadata: { category: "family-logistics" },
		idempotencyKey: "idem-outbound-1",
		...overrides,
	};
}

function scheduledOutboundPrepareInput(): TelclaudeMcpScheduledOutboundSideEffectPrepareInput {
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
		idempotencyKey: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		householdReminderPolicy: {
			reminderId: "reminder-1",
			fireId: "reminder-fire-1",
			revision: 1,
			authorizationKind: "parent-confirmed",
			confirmedProposalHash:
				"sha256:1111111111111111111111111111111111111111111111111111111111111111",
			scheduleHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			contentHash: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			bindingFingerprint: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
			actorId: "household:whatsapp:parent-a",
			subjectUserId: "household:parent-a",
			profileId: "parent-a",
			recipientPrincipalHash:
				"sha256:5555555555555555555555555555555555555555555555555555555555555555",
			systemPolicyPrincipal: "telclaude:household-reminder-system",
			systemPolicyVersion: "phase0.v1",
		},
	};
}

function householdOutboundPrepareInput(
	overrides: Partial<Omit<TelclaudeMcpOutboundSideEffectPrepareInput, "kind">> = {},
): TelclaudeMcpOutboundSideEffectPrepareInput {
	return outboundPrepareInput({
		actorId: "household:whatsapp:parent-a",
		profileId: "parent-a",
		domain: "household",
		subjectUserId: "household:parent-a",
		householdReplyBinding: {
			bindingId: "parent-a",
			subjectUserId: "household:parent-a",
			senderPrincipalHash:
				"sha256:1111111111111111111111111111111111111111111111111111111111111111",
			recipientPrincipalHash:
				"sha256:1111111111111111111111111111111111111111111111111111111111111111",
			identityAssurance: "strong_link",
		},
		...overrides,
	});
}

function resolvedHouseholdReplyBinding(
	overrides: Partial<ResolvedWhatsAppHouseholdReplyBinding> = {},
): ResolvedWhatsAppHouseholdReplyBinding {
	return {
		bindingId: "parent-a",
		actorId: "household:whatsapp:parent-a",
		subjectUserId: "household:parent-a",
		profileId: "parent-a",
		principalId: "+15551234567",
		replyPrincipalId: "+15551234567",
		identityAssurance: "strong_link",
		pairingAttested: true,
		revoked: false,
		...overrides,
	};
}

function fixtureConversation(overrides: Partial<RelayConversation> = {}): RelayConversation {
	return {
		token: "whatsapp:+15551234567",
		channel: "whatsapp",
		conversationId: "whatsapp:+15551234567",
		threadId: "thread-private",
		profileId: "ops",
		domain: "private",
		mcpDomain: "private",
		edgeDomain: "private",
		routingSession: {
			sessionId: "session-private",
			routeKey: "route-private",
		},
		authorizationState: "authorized",
		humanPairingProvenance: false,
		authorizationScopes: ["message:reply"],
		members: [
			{
				actorId: "operator",
				channel: "whatsapp",
				principalId: "+15551234567",
				principalHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				role: "sender",
				identityAssurance: "strong_link",
				scopes: ["message:reply"],
				revoked: false,
			},
		],
		threadMessageIds: [],
		inboundCursor: null,
		auditIds: [],
		createdAtMs: 100_000,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		updatedAtMs: 100_000,
		...overrides,
	};
}

function fixtureInboundTurn(
	overrides: Partial<RelayConversationInboundTurn> = {},
): RelayConversationInboundTurn {
	return {
		ref: `turn_${"a".repeat(32)}`,
		conversationToken: "whatsapp:+15551234567",
		channel: "whatsapp",
		conversationId: "whatsapp:+15551234567",
		threadId: "thread-private",
		profileId: "ops",
		domain: "private",
		mcpDomain: "private",
		inboundMessageId: "message-private",
		senderActorId: "operator",
		senderPrincipalId: "+15551234567",
		createdAtMs: 100_000,
		expiresAtMs: null,
		revokedAtMs: null,
		revokeReason: null,
		...overrides,
	};
}

function canonicalBinding(binding: TelclaudeMcpSideEffectApprovalBinding): string {
	return JSON.stringify(sortKeysDeep(binding));
}

function claimsFromApprovalToken(token: string): Record<string, unknown> {
	const [, claimsB64] = token.split(".");
	return JSON.parse(Buffer.from(claimsB64, "base64url").toString("utf8")) as Record<
		string,
		unknown
	>;
}

class PrefixSigningVault {
	async signPayload(payload: string, prefix: string): Promise<{ type: string; signature: string }> {
		return { type: "sign-payload", signature: this.signatureFor(payload, prefix) };
	}

	verifySignature(payload: string, signature: string, prefix: string): boolean {
		return signature === this.signatureFor(payload, prefix);
	}

	private signatureFor(payload: string, prefix: string): string {
		return crypto.createHash("sha256").update(`${prefix}\n${payload}`).digest("base64url");
	}
}
