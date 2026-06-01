import { z } from "zod";

const NonEmptyString = z.string().trim().min(1);
const IsoTimestamp = NonEmptyString;
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);

export const EDGE_ADAPTER_CONTRACT_VERSION = "telclaude.hermes.edge-adapter-contract.v1";
export const EdgeChannelSchema = z.enum(["whatsapp", "email", "agentmail", "social"]);
export const TrustDomainSchema = z.enum(["private", "household", "public", "public-social"]);

export const EDGE_ADAPTER_OPERATION_NAMES = [
	"ingest",
	"prepareOutbound",
	"executeOutbound",
	"status",
	"ack",
] as const;

export const EdgeAdapterOperationNameSchema = z.enum(EDGE_ADAPTER_OPERATION_NAMES);

export type EdgeAdapterOperationName = z.infer<typeof EdgeAdapterOperationNameSchema>;

export const EdgeAdapterSchemaVersions = {
	actorRef: "telclaude.hermes.edge.actor-ref.v1",
	conversationRef: "telclaude.hermes.edge.conversation-ref.v1",
	attachmentRef: "telclaude.hermes.edge.attachment-ref.v1",
	inboundEvent: "telclaude.hermes.edge.inbound-event.v1",
	outboundRequest: "telclaude.hermes.edge.outbound-request.v1",
	preparedOutbound: "telclaude.hermes.edge.prepared-outbound.v1",
	outboundDecision: "telclaude.hermes.edge.outbound-decision.v1",
	deliveryReceipt: "telclaude.hermes.edge.delivery-receipt.v1",
	statusView: "telclaude.hermes.edge.status-view.v1",
} as const;

const ChannelIdentitySchema = z
	.object({
		channel: EdgeChannelSchema,
		principalId: NonEmptyString,
		displayName: NonEmptyString.optional(),
	})
	.strict();

const ScopeGrantSchema = z
	.object({
		scope: NonEmptyString,
		actions: z.array(NonEmptyString).min(1),
		grantedAt: IsoTimestamp,
		expiresAt: IsoTimestamp.optional(),
	})
	.strict();

export const ActorRefSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.actorRef),
		actorId: NonEmptyString,
		channelIdentity: ChannelIdentitySchema,
		identityAssurance: z.enum(["channel_bound", "paired", "verified", "strong_link"]),
		scopes: z.array(ScopeGrantSchema),
		revocation: z
			.object({
				revoked: z.boolean(),
				revokedAt: IsoTimestamp.optional(),
				reason: NonEmptyString.optional(),
			})
			.strict(),
	})
	.strict();

export const ConversationRefSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.conversationRef),
		channel: EdgeChannelSchema,
		conversationId: NonEmptyString,
		threadId: NonEmptyString,
		profileId: NonEmptyString,
		domain: TrustDomainSchema,
		recipients: z.array(
			z
				.object({
					actorId: NonEmptyString,
					channelIdentity: ChannelIdentitySchema,
					role: z.enum(["sender", "recipient", "observer", "owner"]),
				})
				.strict(),
		),
		routingSession: z
			.object({
				sessionId: NonEmptyString,
				routeKey: NonEmptyString,
			})
			.strict(),
		authorization: z
			.object({
				state: z.enum(["authorized", "approval_required", "denied", "revoked"]),
				scopes: z.array(NonEmptyString),
				revoked: z.boolean(),
			})
			.strict(),
	})
	.strict();

export const AttachmentRefSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.attachmentRef),
		quarantineId: NonEmptyString,
		mediaType: NonEmptyString,
		scanState: z.enum(["pending", "clean", "blocked", "failed"]),
		sizeBytes: z.number().int().nonnegative(),
		contentHash: Sha256Digest,
		trustLabel: z.enum(["untrusted", "trusted", "suspicious", "blocked"]),
		expiresAt: IsoTimestamp,
		lifecycle: z
			.object({
				state: z.enum(["quarantined", "authorized", "expired", "denied"]),
				authorizedFor: z.array(NonEmptyString),
			})
			.strict(),
	})
	.strict();

export const InboundEventSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.inboundEvent),
		channel: EdgeChannelSchema,
		conversationRef: ConversationRefSchema,
		actorRef: ActorRefSchema,
		receivedAt: IsoTimestamp,
		normalized: z
			.object({
				text: z.string().optional(),
				mediaRefs: z.array(AttachmentRefSchema),
			})
			.strict(),
		riskLabels: z.array(NonEmptyString),
		sourceAudit: z
			.object({
				auditId: NonEmptyString,
				sourceEventId: NonEmptyString.optional(),
				platformMessageId: NonEmptyString.optional(),
				transport: NonEmptyString,
			})
			.strict(),
		ordering: z
			.object({
				cursor: NonEmptyString,
				sequence: z.number().int().nonnegative(),
				duplicateHandling: z.enum(["first_seen", "duplicate", "replayed"]),
			})
			.strict(),
	})
	.strict();

const OutboundRecipientSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("thread"),
			threadId: NonEmptyString,
		})
		.strict(),
	z
		.object({
			kind: z.literal("actor"),
			actorId: NonEmptyString,
		})
		.strict(),
	z
		.object({
			kind: z.literal("address"),
			addressRef: NonEmptyString,
		})
		.strict(),
]);

export const OutboundRequestSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.outboundRequest),
		channel: EdgeChannelSchema,
		recipient: OutboundRecipientSchema,
		requestedBody: z.string(),
		mediaRefs: z.array(AttachmentRefSchema),
		conversationRef: ConversationRefSchema,
		correlationId: NonEmptyString,
	})
	.strict();

const ResolvedDestinationSchema = z
	.object({
		kind: z.enum(["thread", "actor", "address"]),
		threadId: NonEmptyString.optional(),
		actorId: NonEmptyString.optional(),
		addressRef: NonEmptyString.optional(),
		conversationId: NonEmptyString.optional(),
	})
	.strict();

export const PreparedOutboundSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.preparedOutbound),
		outboundRef: NonEmptyString,
		channel: EdgeChannelSchema,
		resolvedDestination: ResolvedDestinationSchema,
		finalRenderedBody: z.string(),
		mediaRefs: z.array(AttachmentRefSchema),
		authorizingActor: ActorRefSchema,
		policyResult: z
			.object({
				decision: z.enum(["allowed", "approval_required", "denied"]),
				reason: NonEmptyString,
				rules: z.array(NonEmptyString).optional(),
			})
			.strict(),
		approvalRequirement: z
			.object({
				required: z.boolean(),
				reason: NonEmptyString.optional(),
				scope: NonEmptyString.optional(),
			})
			.strict(),
		idempotencyKey: NonEmptyString,
		sideEffectLedgerRef: NonEmptyString,
		createdAt: IsoTimestamp,
		retryPolicy: z
			.object({
				maxAttempts: z.number().int().positive(),
				backoff: z.enum(["none", "fixed", "exponential"]),
				deadLetterAfterAttempts: z.number().int().positive(),
			})
			.strict(),
	})
	.strict();

export const OutboundDecisionSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.outboundDecision),
		decision: z.enum(["allowed", "approval_required", "denied"]),
		reason: NonEmptyString,
		preparedOutboundRef: NonEmptyString.optional(),
		approvalRequest: z
			.object({
				requestId: NonEmptyString,
				revision: z.number().int().positive(),
				renderedPreview: z.string(),
				expiresAt: IsoTimestamp,
			})
			.strict()
			.optional(),
		decidedAt: IsoTimestamp,
	})
	.strict();

export const DeliveryReceiptSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.deliveryReceipt),
		outboundRef: NonEmptyString,
		platformMessageId: NonEmptyString.optional(),
		deliveryStatus: z.enum(["queued", "sent", "delivered", "read", "failed", "dead_lettered"]),
		timestamps: z
			.object({
				observedAt: IsoTimestamp,
				sentAt: IsoTimestamp.optional(),
				deliveredAt: IsoTimestamp.optional(),
				failedAt: IsoTimestamp.optional(),
			})
			.strict(),
		retry: z
			.object({
				attempt: z.number().int().positive(),
				maxAttempts: z.number().int().positive(),
				idempotencyKey: NonEmptyString,
			})
			.strict(),
	})
	.strict();

export const StatusViewSchema = z
	.object({
		schemaVersion: z.literal(EdgeAdapterSchemaVersions.statusView),
		channel: EdgeChannelSchema,
		checkedAt: IsoTimestamp,
		setup: z
			.object({
				status: z.enum(["ready", "degraded", "not_configured", "disabled"]),
				reason: NonEmptyString.optional(),
			})
			.strict(),
		sidecar: z
			.object({
				status: z.enum(["up", "degraded", "down"]),
				healthRef: NonEmptyString.optional(),
			})
			.strict(),
		credentials: z.array(
			z
				.object({
					kind: NonEmptyString,
					present: z.boolean(),
					owner: NonEmptyString,
					status: z.enum(["present", "missing", "expired", "revoked"]),
				})
				.strict(),
		),
		rateBudget: z
			.object({
				status: z.enum(["available", "limited", "exhausted", "unknown"]),
				remaining: z.number().int().nonnegative().optional(),
				resetAt: IsoTimestamp.optional(),
			})
			.strict(),
	})
	.strict();

export type ActorRef = z.infer<typeof ActorRefSchema>;
export type ConversationRef = z.infer<typeof ConversationRefSchema>;
export type AttachmentRef = z.infer<typeof AttachmentRefSchema>;
export type InboundEvent = z.infer<typeof InboundEventSchema>;
export type OutboundRequest = z.infer<typeof OutboundRequestSchema>;
export type PreparedOutbound = z.infer<typeof PreparedOutboundSchema>;
export type OutboundDecision = z.infer<typeof OutboundDecisionSchema>;
export type DeliveryReceipt = z.infer<typeof DeliveryReceiptSchema>;
export type StatusView = z.infer<typeof StatusViewSchema>;
