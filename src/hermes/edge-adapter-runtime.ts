import crypto from "node:crypto";
import type { OutboundDeliveryDispatcher } from "../relay/outbound-delivery-dispatcher.js";
import {
	type ActorRef,
	ActorRefSchema,
	type AttachmentRef,
	AttachmentRefSchema,
	type ConversationRef,
	ConversationRefSchema,
	type DeliveryReceipt,
	DeliveryReceiptSchema,
	type EdgeAdapterOperationName,
	EdgeAdapterSchemaVersions,
	type InboundEvent,
	InboundEventSchema,
	type OutboundRequest,
	OutboundRequestSchema,
	type PreparedOutbound,
	PreparedOutboundSchema,
	type StatusView,
	StatusViewSchema,
} from "./edge-adapter-contract.js";

type EdgeChannel = InboundEvent["channel"];
type TrustDomain = ConversationRef["domain"];

export type TelclaudeEdgeAttachmentInput = {
	readonly attachmentId: string;
	readonly mediaType: string;
	readonly sizeBytes: number;
	readonly rawBytes?: string;
	readonly localPath?: string;
	readonly downloadUrl?: string;
	readonly scanState?: AttachmentRef["scanState"];
	readonly trustLabel?: AttachmentRef["trustLabel"];
	readonly authorizedFor?: readonly string[];
};

export type TelclaudeEdgeInboundInput = {
	readonly channel: EdgeChannel;
	readonly domain: TrustDomain;
	readonly authorizedSender?: boolean;
	readonly actorId?: string;
	readonly principalId?: string;
	readonly identityAssurance?: ActorRef["identityAssurance"];
	readonly scopes?: ActorRef["scopes"];
	readonly revoked?: boolean;
	readonly conversationId?: string;
	readonly threadId?: string;
	readonly profileId?: string;
	readonly text?: string;
	readonly attachments?: readonly TelclaudeEdgeAttachmentInput[];
	readonly hermesRawCredential?: string;
};

export type TelclaudeEdgePrepareOutboundInput = {
	readonly request: unknown;
	readonly authorizingActor: ActorRef;
};

export type TelclaudeEdgeExecuteOutboundInput = {
	readonly preparedOutbound: unknown;
	readonly approvalToken?: string;
	readonly transportCredentials?: unknown;
};

export type TelclaudeHouseholdProviderAccessInput = {
	readonly actorRef: ActorRef;
	readonly conversationRef: ConversationRef;
	readonly providerAccount: string;
	readonly providerAccountBinding: "strong_link" | "number_only";
	readonly action: "read" | "prepare_write";
	readonly classification?: "benign" | "sensitive" | "urgent" | "emergency";
	readonly approved?: boolean;
	readonly privateMemorySource?: string;
};

export type TelclaudeChannelResourceAccessInput = {
	readonly channel: EdgeChannel;
	readonly requester: "hermes" | "telclaude-edge";
};

export type TelclaudeSocialPostPolicyInput = {
	readonly actorRef: ActorRef;
	readonly conversationRef: ConversationRef;
	readonly approved: boolean;
	readonly budgetRemaining: number;
	readonly privateMemorySource?: string;
};

export type TelclaudePublicSocialIsolationInput = {
	readonly actorRef: ActorRef;
	readonly conversationRef: ConversationRef;
	readonly workspaceMount?: string;
	readonly privateMemorySource?: string;
	readonly providerScope?: string;
	readonly budgetRemaining: number;
};

type PreparedBinding = {
	readonly idempotencyKey: string;
	readonly preparedHash: string;
};

export type EdgePreparedPayloadMediaRef = Pick<AttachmentRef, "quarantineId" | "contentHash">;

type QuarantinedAttachment = {
	readonly ref: AttachmentRef;
	readonly raw?: string;
	readonly localPath?: string;
	readonly downloadUrl?: string;
	readonly domain: TrustDomain;
};

export class TelclaudeEdgeRuntimeDeniedError extends Error {
	readonly control: string;

	constructor(control: string, detail: string) {
		super(detail);
		this.name = "TelclaudeEdgeRuntimeDeniedError";
		this.control = control;
	}
}

export function isTelclaudeEdgeRuntimeDeniedError(
	error: unknown,
	control?: string,
): error is TelclaudeEdgeRuntimeDeniedError {
	return (
		error instanceof TelclaudeEdgeRuntimeDeniedError &&
		(control === undefined || error.control === control)
	);
}

export class TelclaudeEdgeRuntime {
	private readonly now: () => string;
	private readonly deliver?: OutboundDeliveryDispatcher;
	private readonly attachments = new Map<string, QuarantinedAttachment>();
	private readonly prepared = new Map<string, PreparedBinding>();
	private readonly ledger = new Set<string>();
	private readonly operations: EdgeAdapterOperationName[] = [];
	private deniedAttemptCount = 0;

	constructor(input: { now?: () => string; deliver?: OutboundDeliveryDispatcher } = {}) {
		this.now = input.now ?? (() => new Date().toISOString());
		this.deliver = input.deliver;
	}

	registerAuthorizedAttachmentRef(input: {
		readonly ref: AttachmentRef;
		readonly domain: TrustDomain;
	}): AttachmentRef {
		const ref = AttachmentRefSchema.parse(input.ref);
		if (
			ref.scanState !== "clean" ||
			ref.trustLabel === "blocked" ||
			ref.lifecycle.state !== "authorized"
		) {
			this.deny("attachment.unscanned-denied", "Attachment has not passed edge quarantine");
		}
		this.attachments.set(ref.quarantineId, {
			ref,
			domain: input.domain,
		});
		return structuredClone(ref);
	}

	operationTrace(): readonly EdgeAdapterOperationName[] {
		return [...this.operations];
	}

	deniedAttempts(): number {
		return this.deniedAttemptCount;
	}

	ledgerEntries(): number {
		return this.ledger.size;
	}

	ingest(input: TelclaudeEdgeInboundInput): InboundEvent {
		this.operations.push("ingest");
		if (input.hermesRawCredential) {
			this.deny("credentials.raw-denied", "Hermes may not supply raw edge credentials");
		}
		if (input.authorizedSender === false) {
			this.denyUnauthorizedSender(input.channel);
		}
		const channel = input.channel;
		const domain = input.domain;
		const actorRef = this.actorRef(channel, {
			actorId: input.actorId,
			principalId: input.principalId,
			identityAssurance: input.identityAssurance,
			scopes: input.scopes,
			revoked: input.revoked,
		});
		const conversationRef = this.conversationRef(channel, domain, {
			actorId: actorRef.actorId,
			principalId: actorRef.channelIdentity.principalId,
			conversationId: input.conversationId,
			threadId: input.threadId,
			profileId: input.profileId,
		});
		const mediaRefs = (input.attachments ?? []).map((attachment) =>
			this.quarantineAttachment(attachment, domain, conversationRef.profileId),
		);
		const event = {
			schemaVersion: EdgeAdapterSchemaVersions.inboundEvent,
			channel,
			conversationRef,
			actorRef,
			receivedAt: this.now(),
			normalized: {
				...(input.text !== undefined ? { text: input.text } : {}),
				mediaRefs,
			},
			riskLabels: ["edge-runtime-normalized"],
			sourceAudit: {
				auditId: `${channel}-edge-audit-${sha256Short({ channel, domain, at: this.now() })}`,
				sourceEventId: `${channel}-event-${sha256Short({ channel, domain, actor: actorRef.actorId })}`,
				platformMessageId: `${channel}-message-${sha256Short({
					channel,
					thread: conversationRef.threadId,
				})}`,
				transport: "telclaude-edge-runtime",
			},
			ordering: {
				cursor: `${channel}-cursor-${sha256Short({
					channel,
					thread: conversationRef.threadId,
					at: this.now(),
				})}`,
				sequence: 1,
				duplicateHandling: "first_seen",
			},
		};
		return InboundEventSchema.parse(event);
	}

	prepareOutbound(input: TelclaudeEdgePrepareOutboundInput): PreparedOutbound {
		this.operations.push("prepareOutbound");
		const requestRecord = record(input.request);
		if ("authorizingActor" in requestRecord) {
			this.deny(
				"outbound.hermes-authority-denied",
				"Hermes may not attach authorizingActor to outbound requests",
			);
		}
		if ("transportCredentials" in requestRecord) {
			this.deny(
				"outbound.transport-credentials-denied",
				"Hermes may not attach transport credentials to outbound requests",
			);
		}
		if ("policyResult" in requestRecord) {
			this.deny(
				"outbound.policy-result-denied",
				"Hermes may not predeclare Telclaude edge policy results",
			);
		}
		if ("approvalToken" in requestRecord) {
			this.deny(
				"outbound.approval-token-denied",
				"Hermes may not supply edge approval tokens directly",
			);
		}
		this.assertNoRawMediaFields(requestRecord);
		this.assertConversationEnvelope(requestRecord);
		const request = OutboundRequestSchema.parse(input.request);
		const conversationRef = ConversationRefSchema.parse(request.conversationRef);
		const authorizingActor = ActorRefSchema.parse(input.authorizingActor);
		this.assertAuthorizingActor(authorizingActor, conversationRef);
		if (request.channel !== conversationRef.channel) {
			this.deny("outbound.recipient-body-bound", "Outbound channel does not match conversation");
		}
		if (
			conversationRef.authorization.state === "revoked" ||
			conversationRef.authorization.revoked
		) {
			this.deny("identity.revocation-enforced", "Conversation identity is revoked");
		}
		if (conversationRef.authorization.state !== "authorized") {
			this.deny(
				"outbound.policy-result-denied",
				"Conversation is not authorized for outbound send",
			);
		}
		const resolvedDestination = this.resolveDestination(request, conversationRef);
		for (const mediaRef of request.mediaRefs) {
			this.assertAttachmentUsable(mediaRef, conversationRef);
		}
		const preparedHash = edgePreparedPayloadHash({
			channel: request.channel,
			resolvedDestination,
			body: request.requestedBody,
			mediaRefs: request.mediaRefs,
		});
		const idempotencyKey = `edge-idem:${preparedHash}`;
		const outboundRef = `edge-out:${preparedHash.slice(0, 32)}`;
		const prepared = PreparedOutboundSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
			outboundRef,
			channel: request.channel,
			resolvedDestination,
			finalRenderedBody: request.requestedBody,
			mediaRefs: request.mediaRefs,
			authorizingActor,
			edgePreparedHash: preparedHash,
			policyResult: {
				decision: "allowed",
				reason: "Telclaude edge policy allowed existing authorized destination",
				rules: ["recipient-bound", "attachment-authorized", "edge-owned-execution"],
			},
			approvalRequirement: {
				required: false,
			},
			idempotencyKey,
			sideEffectLedgerRef: `edge-ledger:${preparedHash.slice(0, 32)}`,
			createdAt: this.now(),
			retryPolicy: {
				maxAttempts: 3,
				backoff: "exponential",
				deadLetterAfterAttempts: 3,
			},
		});
		this.prepared.set(prepared.outboundRef, { idempotencyKey, preparedHash });
		return prepared;
	}

	async executeOutbound(input: TelclaudeEdgeExecuteOutboundInput): Promise<DeliveryReceipt> {
		this.operations.push("executeOutbound");
		if (input.approvalToken) {
			this.deny(
				"outbound.approval-token-denied",
				"Hermes-supplied approval tokens are not accepted by edge execution",
			);
		}
		if (input.transportCredentials) {
			this.deny(
				"outbound.transport-credentials-denied",
				"Hermes may not supply transport credentials to edge execution",
			);
		}
		const prepared = PreparedOutboundSchema.parse(input.preparedOutbound);
		if (prepared.policyResult.decision !== "allowed") {
			this.deny("outbound.policy-result-denied", "Prepared outbound policy is not allowed");
		}
		const binding = this.prepared.get(prepared.outboundRef);
		if (!binding) {
			this.deny("outbound.recipient-body-bound", "Prepared outbound was not edge-issued");
		}
		const preparedHash = edgePreparedPayloadHash({
			channel: prepared.channel,
			resolvedDestination: prepared.resolvedDestination,
			body: prepared.finalRenderedBody,
			mediaRefs: prepared.mediaRefs,
		});
		if (
			binding.preparedHash !== preparedHash ||
			prepared.edgePreparedHash !== preparedHash ||
			binding.idempotencyKey !== prepared.idempotencyKey
		) {
			this.deny("outbound.recipient-body-bound", "Prepared outbound binding was mutated");
		}
		if (this.ledger.has(prepared.idempotencyKey)) {
			this.deny("outbound.replay-denied", "Prepared outbound idempotency key was already used");
		}
		this.ledger.add(prepared.idempotencyKey);
		if (this.deliver) {
			return DeliveryReceiptSchema.parse(await this.deliver(prepared));
		}
		return DeliveryReceiptSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.deliveryReceipt,
			outboundRef: prepared.outboundRef,
			platformMessageId: `edge-platform:${sha256Short(prepared.outboundRef)}`,
			deliveryStatus: "sent",
			timestamps: {
				observedAt: this.now(),
				sentAt: this.now(),
			},
			retry: {
				attempt: 1,
				maxAttempts: prepared.retryPolicy.maxAttempts,
				idempotencyKey: prepared.idempotencyKey,
			},
		});
	}

	status(channel: EdgeChannel): StatusView {
		this.operations.push("status");
		return StatusViewSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.statusView,
			channel,
			checkedAt: this.now(),
			setup: {
				status: "ready",
			},
			sidecar: {
				status: "up",
				healthRef: `edge-health:${channel}`,
			},
			credentials: [
				{
					kind: `${channel}-credential-ref`,
					present: true,
					owner: "telclaude-edge",
					status: "present",
				},
			],
			rateBudget: {
				status: "available",
				remaining: 99,
				resetAt: "2026-05-31T10:00:00.000Z",
			},
		});
	}

	ack(receipt: unknown): DeliveryReceipt {
		this.operations.push("ack");
		return DeliveryReceiptSchema.parse(receipt);
	}

	readAttachmentRaw(input: {
		readonly quarantineId: string;
		readonly requester: "hermes" | "telclaude-edge";
	}): string {
		if (input.requester !== "telclaude-edge") {
			this.deny("attachment.raw-bytes-denied", "Hermes may only receive attachment refs");
		}
		const quarantined = this.attachments.get(input.quarantineId);
		if (!quarantined) {
			this.deny("attachment.raw-bytes-denied", "Attachment quarantine ref is unknown");
		}
		return quarantined.raw ?? "";
	}

	accessChannelResource(input: TelclaudeChannelResourceAccessInput): {
		readonly resourceRef: string;
	} {
		if (input.requester !== "telclaude-edge") {
			switch (input.channel) {
				case "whatsapp":
					return this.deny(
						"whatsapp.direct-bridge-denied",
						"Hermes may not access the raw WhatsApp bridge",
					);
				case "email":
					return this.deny("email.direct-mailbox-denied", "Hermes may not access raw mailboxes");
				case "agentmail":
					return this.deny("agentmail.direct-key-denied", "Hermes may not access AgentMail keys");
				case "social":
					return this.deny(
						"social.private-memory-denied",
						"Hermes may not access public-social transport custody directly",
					);
			}
		}
		return {
			resourceRef: `${input.channel}-edge-resource:${sha256Short({
				channel: input.channel,
				requester: input.requester,
			})}`,
		};
	}

	authorizeHouseholdProviderAccess(input: TelclaudeHouseholdProviderAccessInput): {
		readonly releaseRef: string;
		readonly audit: {
			readonly decision: "allowed";
			readonly actorId: string;
			readonly domain: "household";
			readonly providerAccountRef: string;
			readonly action: "read" | "prepare_write";
			readonly classification: "benign" | "sensitive";
			readonly approved: boolean;
		};
	} {
		const actorRef = ActorRefSchema.parse(input.actorRef);
		const conversationRef = ConversationRefSchema.parse(input.conversationRef);
		const requestedClassification = input.classification ?? "benign";
		if (conversationRef.domain !== "household") {
			this.deny("household.private-memory-denied", "Provider access is not in household domain");
		}
		if (input.privateMemorySource) {
			this.deny(
				"household.private-memory-denied",
				"Household actors may not use private operator memory",
			);
		}
		if (!this.conversationHasActor(conversationRef, actorRef.actorId)) {
			this.deny(
				"household.cross-recipient-denied",
				"Household actor is not a scoped conversation recipient",
			);
		}
		if (actorRef.identityAssurance !== "strong_link") {
			this.deny("household.strong-link-required", "Provider access requires strong identity link");
		}
		if (input.providerAccountBinding !== "strong_link") {
			this.deny(
				"household.number-only-provider-denied",
				"Provider account cannot be released from phone-number-only identity",
			);
		}
		if (requestedClassification === "urgent" || requestedClassification === "emergency") {
			this.deny(
				"provider.urgent-health-misclassification-denied",
				"Urgent or emergency health requests must not be released as ordinary provider reads",
			);
		}
		const classification: "benign" | "sensitive" =
			input.action === "prepare_write" || requestedClassification === "sensitive"
				? "sensitive"
				: "benign";
		if (classification === "sensitive" && input.approved !== true) {
			this.deny(
				"provider.sensitive-release-approval-required",
				"Sensitive provider release requires explicit approval",
			);
		}
		if (!actorHasScopeAction(actorRef, "household:benign", input.action)) {
			this.deny("identity.forged-actor-denied", "Household actor lacks scoped provider action");
		}
		return {
			releaseRef: `household-provider:${sha256Short({
				actor: actorRef.actorId,
				conversation: conversationRef.conversationId,
				providerAccount: input.providerAccount,
				action: input.action,
			})}`,
			audit: {
				decision: "allowed",
				actorId: actorRef.actorId,
				domain: "household",
				providerAccountRef: `provider-account:${sha256Short(input.providerAccount)}`,
				action: input.action,
				classification,
				approved: input.approved === true,
			},
		};
	}

	authorizeSocialPost(input: TelclaudeSocialPostPolicyInput): {
		readonly postRef: string;
	} {
		const actorRef = ActorRefSchema.parse(input.actorRef);
		const conversationRef = ConversationRefSchema.parse(input.conversationRef);
		if (conversationRef.domain !== "public-social") {
			this.deny("social.private-memory-denied", "Social posting requires public-social domain");
		}
		if (input.privateMemorySource) {
			this.deny("social.private-memory-denied", "Social posting cannot read private memory");
		}
		if (!this.conversationHasActor(conversationRef, actorRef.actorId)) {
			this.deny("identity.forged-actor-denied", "Social actor is not bound to conversation");
		}
		if (!input.approved) {
			this.deny("social.unapproved-posting-denied", "Social posting requires edge approval");
		}
		if (input.budgetRemaining <= 0) {
			this.deny("social.budget-denied", "Social posting budget is exhausted");
		}
		return {
			postRef: `social-post:${sha256Short({
				actor: actorRef.actorId,
				conversation: conversationRef.conversationId,
			})}`,
		};
	}

	authorizePublicSocialIsolation(input: TelclaudePublicSocialIsolationInput): {
		readonly profileRef: string;
	} {
		const actorRef = ActorRefSchema.parse(input.actorRef);
		const conversationRef = ConversationRefSchema.parse(input.conversationRef);
		if (
			conversationRef.domain !== "public-social" ||
			conversationRef.profileId !== "tc-public-social"
		) {
			this.deny(
				"public-social.private-memory-denied",
				"Public-social work must route through the isolated public-social profile",
			);
		}
		if (!this.conversationHasActor(conversationRef, actorRef.actorId)) {
			this.deny("identity.forged-actor-denied", "Public-social actor is not bound to conversation");
		}
		if (input.workspaceMount) {
			this.deny(
				"public-social.private-workspace-denied",
				"Public-social profile may not mount the private workspace",
			);
		}
		if (input.privateMemorySource) {
			this.deny(
				"public-social.private-memory-denied",
				"Public-social profile may not read private memory",
			);
		}
		if (input.providerScope) {
			this.deny(
				"public-social.provider-scope-denied",
				"Public-social profile may not receive private provider scopes",
			);
		}
		if (input.budgetRemaining <= 0) {
			this.deny("public-social.budget-denied", "Public-social budget is exhausted");
		}
		return {
			profileRef: `public-social-profile:${sha256Short({
				actor: actorRef.actorId,
				conversation: conversationRef.conversationId,
			})}`,
		};
	}

	private actorRef(
		channel: EdgeChannel,
		input: {
			readonly actorId?: string;
			readonly principalId?: string;
			readonly identityAssurance?: ActorRef["identityAssurance"];
			readonly scopes?: ActorRef["scopes"];
			readonly revoked?: boolean;
		},
	): ActorRef {
		return ActorRefSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: input.actorId ?? `${channel}:actor:operator`,
			channelIdentity: {
				channel,
				principalId: input.principalId ?? `${channel}:principal:operator`,
				displayName: "Telclaude Edge Actor",
			},
			identityAssurance: input.identityAssurance ?? "verified",
			scopes: input.scopes ?? [
				{
					scope: "message:reply",
					actions: ["read", "send", "reply"],
					grantedAt: this.now(),
				},
			],
			revocation: {
				revoked: input.revoked ?? false,
				...(input.revoked ? { revokedAt: this.now(), reason: "runtime negative control" } : {}),
			},
		});
	}

	private conversationRef(
		channel: EdgeChannel,
		domain: TrustDomain,
		input: {
			readonly actorId: string;
			readonly principalId: string;
			readonly conversationId?: string;
			readonly threadId?: string;
			readonly profileId?: string;
		},
	): ConversationRef {
		const threadId = input.threadId ?? `${channel}:${domain}:thread:1`;
		const profileId =
			input.profileId ?? (domain === "public-social" ? "tc-public-social" : `tc-${domain}`);
		return ConversationRefSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.conversationRef,
			channel,
			conversationId: input.conversationId ?? `${channel}:${domain}:conversation:1`,
			threadId,
			profileId,
			domain,
			recipients: [
				{
					actorId: input.actorId,
					channelIdentity: {
						channel,
						principalId: input.principalId,
					},
					role: "sender",
				},
			],
			routingSession: {
				sessionId: `${domain}:${channel}:session:1`,
				routeKey: `${domain}:${channel}:${threadId}`,
			},
			authorization: {
				state: "authorized",
				scopes: ["message:read", "message:reply"],
				revoked: false,
			},
		});
	}

	private quarantineAttachment(
		input: TelclaudeEdgeAttachmentInput,
		domain: TrustDomain,
		profileId: string,
	): AttachmentRef {
		const contentHash =
			input.rawBytes || input.localPath || input.downloadUrl
				? sha256Digest({
						rawBytes: input.rawBytes ?? null,
						localPath: input.localPath ?? null,
						downloadUrl: input.downloadUrl ?? null,
					})
				: sha256Digest({ attachmentId: input.attachmentId });
		const scanState = input.scanState ?? "clean";
		const trustLabel = input.trustLabel ?? (scanState === "clean" ? "trusted" : "untrusted");
		const ref = AttachmentRefSchema.parse({
			schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
			quarantineId: `edge-quarantine:${sha256Short(input.attachmentId)}`,
			mediaType: input.mediaType,
			scanState,
			sizeBytes: input.sizeBytes,
			contentHash,
			trustLabel,
			expiresAt: "2026-05-31T10:00:00.000Z",
			lifecycle: {
				state: scanState === "clean" ? "authorized" : "quarantined",
				authorizedFor:
					input.authorizedFor !== undefined
						? [...input.authorizedFor]
						: [profileId, `tc-${domain}`],
			},
		});
		this.attachments.set(ref.quarantineId, {
			ref,
			raw: input.rawBytes,
			localPath: input.localPath,
			downloadUrl: input.downloadUrl,
			domain,
		});
		return ref;
	}

	private resolveDestination(
		request: OutboundRequest,
		conversationRef: ConversationRef,
	): PreparedOutbound["resolvedDestination"] {
		if (request.recipient.kind === "thread") {
			if (request.recipient.threadId !== conversationRef.threadId) {
				if (request.channel === "email") {
					this.deny("email.wrong-thread-denied", "Email reply thread is not edge-bound");
				}
				this.deny("outbound.recipient-body-bound", "Outbound thread is not bound to conversation");
			}
			return {
				kind: "thread",
				threadId: request.recipient.threadId,
				conversationId: conversationRef.conversationId,
			};
		}
		if (request.recipient.kind === "actor") {
			const actorId = request.recipient.actorId;
			const actor = conversationRef.recipients.find(
				(recipient) => recipient.actorId === actorId && isTargetableRecipientRole(recipient.role),
			);
			if (!actor) {
				if (conversationRef.domain === "household") {
					this.deny(
						"household.cross-recipient-denied",
						"Household outbound actor is not a scoped recipient",
					);
				}
				this.deny("outbound.recipient-body-bound", "Outbound actor is not bound to conversation");
			}
			return {
				kind: "actor",
				actorId,
				conversationId: conversationRef.conversationId,
			};
		}
		const addressRef = request.recipient.addressRef;
		const address = conversationRef.recipients.find(
			(recipient) =>
				recipient.channelIdentity.principalId === addressRef &&
				isTargetableRecipientRole(recipient.role),
		);
		if (!address) {
			if (conversationRef.domain === "household") {
				this.deny(
					"household.cross-recipient-denied",
					"Household outbound address is not a scoped recipient",
				);
			}
			this.deny("outbound.recipient-body-bound", "Outbound address is not bound to conversation");
		}
		return {
			kind: "address",
			addressRef,
			conversationId: conversationRef.conversationId,
		};
	}

	private assertAttachmentUsable(mediaRef: AttachmentRef, conversationRef: ConversationRef): void {
		const parsed = AttachmentRefSchema.parse(mediaRef);
		const quarantined = this.attachments.get(parsed.quarantineId);
		if (!quarantined || stableStringify(quarantined.ref) !== stableStringify(parsed)) {
			this.deny(
				"attachment.unknown-quarantine-denied",
				"Attachment quarantine ref was not edge-issued or was mutated",
			);
		}
		const stored = quarantined.ref;
		if (
			stored.scanState !== "clean" ||
			stored.trustLabel === "blocked" ||
			stored.lifecycle.state !== "authorized"
		) {
			this.deny("attachment.unscanned-denied", "Attachment has not passed edge quarantine");
		}
		const authorizedFor = new Set(stored.lifecycle.authorizedFor);
		if (
			!authorizedFor.has(conversationRef.profileId) &&
			!authorizedFor.has(`tc-${conversationRef.domain}`)
		) {
			this.deny(
				"attachment.cross-domain-reuse-denied",
				"Attachment quarantine ref is not authorized for this trust domain",
			);
		}
	}

	private assertConversationEnvelope(requestRecord: Record<string, unknown>): void {
		const conversation = record(requestRecord.conversationRef);
		if (!("authorization" in conversation)) {
			this.deny("identity.session-id-not-authority", "Session id is not an authorization grant");
		}
		if ("privateMemorySource" in conversation) {
			this.deny("household.private-memory-denied", "Conversation may not carry private memory");
		}
		const channel = requestRecord.channel;
		const recipients = conversation.recipients;
		if (Array.isArray(recipients)) {
			for (const recipient of recipients) {
				const identity = record(record(recipient).channelIdentity);
				if (identity.channel !== undefined && identity.channel !== channel) {
					this.deny(
						"identity.cross-channel-denied",
						"Conversation recipient channel does not match request channel",
					);
				}
			}
		}
	}

	private assertAuthorizingActor(actorRef: ActorRef, conversationRef: ConversationRef): void {
		if (actorRef.revocation.revoked) {
			this.deny("identity.revocation-enforced", "Authorizing actor is revoked");
		}
		if (actorRef.channelIdentity.channel !== conversationRef.channel) {
			this.deny("identity.cross-channel-denied", "Authorizing actor channel is not bound");
		}
		if (!this.conversationHasActor(conversationRef, actorRef.actorId)) {
			this.deny("identity.forged-actor-denied", "Authorizing actor is not bound to conversation");
		}
		if (!actorHasAnyAction(actorRef, ["send", "reply"])) {
			this.deny("identity.forged-actor-denied", "Authorizing actor lacks send/reply scope");
		}
	}

	private conversationHasActor(conversationRef: ConversationRef, actorId: string): boolean {
		return conversationRef.recipients.some((recipient) => recipient.actorId === actorId);
	}

	private denyUnauthorizedSender(channel: EdgeChannel): never {
		switch (channel) {
			case "whatsapp":
				return this.deny("whatsapp.unknown-sender-denied", "WhatsApp sender is not paired");
			case "agentmail":
				return this.deny(
					"agentmail.unauthorized-sender-denied",
					"AgentMail sender is not authorized",
				);
			case "email":
				return this.deny("email.wrong-thread-denied", "Email sender is not bound to the thread");
			case "social":
				return this.deny("social.unapproved-posting-denied", "Social sender is not approved");
		}
	}

	private assertNoRawMediaFields(requestRecord: Record<string, unknown>): void {
		const refs = requestRecord.mediaRefs;
		if (!Array.isArray(refs)) return;
		for (const ref of refs) {
			const media = record(ref);
			if ("rawBytes" in media) {
				this.deny("attachment.raw-bytes-denied", "Outbound media refs may not contain raw bytes");
			}
			if ("localPath" in media) {
				this.deny(
					"attachment.local-path-denied",
					"Outbound media refs may not contain local paths",
				);
			}
			if ("downloadUrl" in media) {
				this.deny(
					"attachment.download-url-denied",
					"Outbound media refs may not contain download URLs",
				);
			}
		}
	}

	private deny(control: string, detail: string): never {
		this.deniedAttemptCount += 1;
		throw new TelclaudeEdgeRuntimeDeniedError(control, detail);
	}
}

export function createTelclaudeEdgeRuntime(
	input: { now?: () => string } = {},
): TelclaudeEdgeRuntime {
	return new TelclaudeEdgeRuntime(input);
}

function record(value: unknown): Record<string, unknown> {
	return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function actorHasScopeAction(actorRef: ActorRef, scope: string, action: string): boolean {
	return actorRef.scopes.some((grant) => grant.scope === scope && grant.actions.includes(action));
}

function actorHasAnyAction(actorRef: ActorRef, actions: readonly string[]): boolean {
	const allowed = new Set(actions);
	return actorRef.scopes.some((grant) => grant.actions.some((action) => allowed.has(action)));
}

function isTargetableRecipientRole(role: ConversationRef["recipients"][number]["role"]): boolean {
	return role === "sender" || role === "recipient";
}

export function edgePreparedPayloadHash(input: {
	readonly channel: EdgeChannel;
	readonly resolvedDestination: PreparedOutbound["resolvedDestination"];
	readonly body: string;
	readonly mediaRefs: readonly EdgePreparedPayloadMediaRef[];
}): string {
	return sha256Hex({
		channel: input.channel,
		resolvedDestination: input.resolvedDestination,
		body: input.body,
		mediaRefs: input.mediaRefs.map((ref) => ({
			quarantineId: ref.quarantineId,
			contentHash: ref.contentHash,
		})),
	});
}

function sha256Digest(value: unknown): `sha256:${string}` {
	return `sha256:${sha256Hex(value)}`;
}

function sha256Short(value: unknown): string {
	return sha256Hex(value).slice(0, 16);
}

function sha256Hex(value: unknown): string {
	return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value: unknown): string {
	return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(sortJson);
	if (typeof value !== "object" || value === null) return value;
	return Object.fromEntries(
		Object.entries(value as Record<string, unknown>)
			.sort(([left], [right]) => left.localeCompare(right))
			.map(([key, nested]) => [key, sortJson(nested)]),
	);
}
