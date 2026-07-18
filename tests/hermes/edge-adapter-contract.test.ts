import { describe, expect, it } from "vitest";
import {
	ActorRefSchema,
	AttachmentRefSchema,
	ConversationRefSchema,
	DeliveryReceiptSchema,
	EDGE_ADAPTER_CONTRACT_VERSION,
	EDGE_ADAPTER_OPERATION_NAMES,
	EdgeAdapterOperationNameSchema,
	EdgeAdapterSchemaVersions,
	InboundEventSchema,
	OutboundDecisionSchema,
	OutboundRequestSchema,
	PreparedOutboundSchema,
	StatusViewSchema,
} from "../../src/hermes/edge-adapter-contract.js";
import { edgePreparedPayloadHash } from "../../src/hermes/edge-adapter-runtime.js";

const timestamp = "2026-05-31T09:00:00.000Z";
const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

describe("Hermes edge adapter contract", () => {
	it("exports the pinned base operation names", () => {
		expect(EDGE_ADAPTER_CONTRACT_VERSION).toBe("telclaude.hermes.edge-adapter-contract.v1");
		expect(EDGE_ADAPTER_OPERATION_NAMES).toEqual([
			"ingest",
			"prepareOutbound",
			"executeOutbound",
			"status",
			"ack",
		]);
		expect(EdgeAdapterOperationNameSchema.safeParse("prepareOutbound").success).toBe(true);
		expect(EdgeAdapterOperationNameSchema.safeParse("sendRaw").success).toBe(false);
	});

	it("accepts valid minimal payloads for every base contract shape", () => {
		const actorRef = validActorRef();
		const conversationRef = validConversationRef();
		const attachmentRef = validAttachmentRef();

		expect(ActorRefSchema.safeParse(actorRef).success).toBe(true);
		expect(ConversationRefSchema.safeParse(conversationRef).success).toBe(true);
		expect(AttachmentRefSchema.safeParse(attachmentRef).success).toBe(true);
		expect(
			InboundEventSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.inboundEvent,
				channel: "whatsapp",
				conversationRef,
				actorRef,
				receivedAt: timestamp,
				normalized: {
					text: "Please send the note",
					mediaRefs: [attachmentRef],
				},
				riskLabels: ["routine"],
				sourceAudit: {
					auditId: "audit-in-1",
					sourceEventId: "wa-event-1",
					platformMessageId: "wa-message-1",
					transport: "telclaude-edge",
				},
				ordering: {
					cursor: "cursor-1",
					sequence: 1,
					duplicateHandling: "first_seen",
				},
			}).success,
		).toBe(true);
		expect(
			OutboundRequestSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
				channel: "whatsapp",
				recipient: {
					kind: "thread",
					threadId: "family-thread",
				},
				requestedBody: "On my way",
				mediaRefs: [attachmentRef],
				conversationRef,
				correlationId: "corr-1",
			}).success,
		).toBe(true);
		expect(
			PreparedOutboundSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
				outboundRef: "outbound-1",
				channel: "whatsapp",
				resolvedDestination: {
					kind: "thread",
					threadId: "family-thread",
					conversationId: "wa-chat-1",
				},
				finalRenderedBody: "On my way",
				mediaRefs: [attachmentRef],
				authorizingActor: actorRef,
				edgePreparedHash: "a".repeat(64),
				policyResult: {
					decision: "allowed",
					reason: "existing allowlisted thread",
					rules: ["existing-thread"],
				},
				approvalRequirement: {
					required: false,
				},
				idempotencyKey: "idem-1",
				sideEffectLedgerRef: "ledger-1",
				createdAt: timestamp,
				retryPolicy: {
					maxAttempts: 3,
					backoff: "exponential",
					deadLetterAfterAttempts: 3,
				},
			}).success,
		).toBe(true);
		expect(
			PreparedOutboundSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
				outboundRef: "outbound-1",
				channel: "whatsapp",
				resolvedDestination: {
					kind: "thread",
					threadId: "family-thread",
					conversationId: "wa-chat-1",
				},
				finalRenderedBody: "On my way",
				mediaRefs: [attachmentRef],
				authorizingActor: actorRef,
				edgePreparedHash: "edge-prepared-hash-1",
				policyResult: {
					decision: "allowed",
					reason: "existing allowlisted thread",
					rules: ["existing-thread"],
				},
				approvalRequirement: {
					required: false,
				},
				idempotencyKey: "idem-1",
				sideEffectLedgerRef: "ledger-1",
				createdAt: timestamp,
				retryPolicy: {
					maxAttempts: 3,
					backoff: "exponential",
					deadLetterAfterAttempts: 3,
				},
			}).success,
		).toBe(false);
		expect(
			OutboundDecisionSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.outboundDecision,
				decision: "approval_required",
				reason: "new recipient",
				preparedOutboundRef: "outbound-1",
				approvalRequest: {
					requestId: "approval-1",
					revision: 1,
					renderedPreview: "Send WhatsApp to Dana: On my way",
					expiresAt: "2026-05-31T09:05:00.000Z",
				},
				decidedAt: timestamp,
			}).success,
		).toBe(true);
		expect(
			DeliveryReceiptSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
				outboundRef: "outbound-1",
				platformMessageId: "wa-message-2",
				deliveryStatus: "sent",
				timestamps: {
					observedAt: timestamp,
					sentAt: timestamp,
				},
				retry: {
					attempt: 1,
					maxAttempts: 3,
					idempotencyKey: "idem-1",
				},
			}).success,
		).toBe(true);
		expect(
			StatusViewSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.statusView,
				channel: "whatsapp",
				checkedAt: timestamp,
				setup: {
					status: "ready",
				},
				sidecar: {
					status: "up",
					healthRef: "health-1",
				},
				credentials: [
					{
						kind: "whatsapp-session",
						present: true,
						owner: "telclaude-edge",
						status: "present",
					},
				],
				rateBudget: {
					status: "available",
					remaining: 9,
					resetAt: "2026-05-31T09:10:00.000Z",
				},
			}).success,
		).toBe(true);
	});

	it.each([
		["outboundRef", { outboundRef: "model-chosen-ref" }],
		["authorizingActor", { authorizingActor: validActorRef() }],
		["policyResult", { policyResult: { decision: "allowed" } }],
		["approval state", { approvalState: "approved", approvalToken: "signed-token" }],
		["transport credentials", { transportCredentials: { token: "raw-platform-token" } }],
	])("rejects Hermes-supplied OutboundRequest fields for %s", (_label, unsafeFields) => {
		const parsed = OutboundRequestSchema.safeParse({
			schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
			channel: "whatsapp",
			recipient: {
				kind: "thread",
				threadId: "family-thread",
			},
			requestedBody: "On my way",
			mediaRefs: [],
			conversationRef: validConversationRef(),
			correlationId: "corr-1",
			...unsafeFields,
		});

		expect(parsed.success).toBe(false);
	});

	it("rejects raw secrets in status views", () => {
		expect(
			StatusViewSchema.safeParse({
				schemaVersion: EdgeAdapterSchemaVersions.statusView,
				channel: "whatsapp",
				checkedAt: timestamp,
				setup: {
					status: "ready",
				},
				sidecar: {
					status: "up",
				},
				credentials: [
					{
						kind: "whatsapp-session",
						present: true,
						owner: "telclaude-edge",
						status: "present",
						rawToken: "should-not-parse",
					},
				],
				rateBudget: {
					status: "available",
				},
				apiKey: "should-not-parse",
			}).success,
		).toBe(false);
	});

	it("keeps AttachmentRef ref-only", () => {
		expect(
			AttachmentRefSchema.safeParse({
				...validAttachmentRef(),
				rawBytes: "base64-content",
			}).success,
		).toBe(false);
		expect(
			AttachmentRefSchema.safeParse({
				...validAttachmentRef(),
				localPath: "/tmp/attachment.bin",
			}).success,
		).toBe(false);
		expect(
			AttachmentRefSchema.safeParse({
				...validAttachmentRef(),
				downloadUrl: "https://example.com/attachment.bin",
			}).success,
		).toBe(false);
	});

	it("accepts only a redacted filename and preserves the legacy prepared hash shape", () => {
		expect(
			AttachmentRefSchema.safeParse({
				...validAttachmentRef(),
				redactedFilename: "provider-statement.pdf",
			}).success,
		).toBe(true);
		expect(
			edgePreparedPayloadHash({
				channel: "whatsapp",
				resolvedDestination: {
					kind: "address",
					addressRef: "+15551234567",
					conversationId: "whatsapp:+15551234567",
				},
				body: "legacy",
				mediaRefs: [
					{
						quarantineId: "attachment:legacy",
						contentHash: `sha256:${"a".repeat(64)}`,
					},
				],
			}),
		).toBe("cdcdcc68745371113007924bf23ee3f152735f410d0baab1b40d59f198141e5b");
	});

	it("requires actor and conversation refs to carry scopes and revocation state", () => {
		const { scopes: _actorScopes, ...actorWithoutScopes } = validActorRef();
		const { revocation: _actorRevocation, ...actorWithoutRevocation } = validActorRef();
		const { authorization: _conversationAuthorization, ...conversationWithoutAuthorization } =
			validConversationRef();

		expect(ActorRefSchema.safeParse(actorWithoutScopes).success).toBe(false);
		expect(ActorRefSchema.safeParse(actorWithoutRevocation).success).toBe(false);
		expect(ConversationRefSchema.safeParse(conversationWithoutAuthorization).success).toBe(false);
	});
});

function validActorRef() {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.actorRef,
		actorId: "telegram:123",
		channelIdentity: {
			channel: "whatsapp",
			principalId: "wa:+15551234567",
			displayName: "Dana",
		},
		identityAssurance: "verified",
		scopes: [
			{
				scope: "message:reply",
				actions: ["send"],
				grantedAt: timestamp,
			},
		],
		revocation: {
			revoked: false,
		},
	};
}

function validConversationRef() {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.conversationRef,
		channel: "whatsapp",
		conversationId: "wa-chat-1",
		threadId: "family-thread",
		profileId: "tc-household",
		domain: "household",
		recipients: [
			{
				actorId: "telegram:123",
				channelIdentity: {
					channel: "whatsapp",
					principalId: "wa:+15551234567",
				},
				role: "sender",
			},
		],
		routingSession: {
			sessionId: "hermes-session-1",
			routeKey: "tc-household:whatsapp:family-thread",
		},
		authorization: {
			state: "authorized",
			scopes: ["message:read", "message:reply"],
			revoked: false,
		},
	};
}

function validAttachmentRef() {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
		quarantineId: "quarantine-1",
		mediaType: "image/png",
		scanState: "clean",
		sizeBytes: 128,
		contentHash: digest,
		trustLabel: "trusted",
		expiresAt: "2026-05-31T10:00:00.000Z",
		lifecycle: {
			state: "authorized",
			authorizedFor: ["tc-household"],
		},
	};
}
