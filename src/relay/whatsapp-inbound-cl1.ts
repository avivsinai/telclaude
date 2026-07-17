import crypto from "node:crypto";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	type ActorRef,
	ActorRefSchema,
	type AttachmentRef,
	EdgeAdapterSchemaVersions,
	type InboundEvent,
	InboundEventSchema,
} from "../hermes/edge-adapter-contract.js";
import {
	type RelayConversation,
	type RelayConversationStore,
	relayConversationToConversationRef,
} from "../hermes/relay-conversation-store.js";
import { assessRisk, wrapExternalContent } from "../security/external-content.js";
import { normalizeWhatsAppAddressRef } from "../whatsapp/address.js";
import type { AttachmentQuarantineStore } from "./attachment-quarantine-store.js";

export { normalizeWhatsAppAddressRef } from "../whatsapp/address.js";

export const WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION = "telclaude.edge.whatsapp.inbound.v1";
export const DEFAULT_WHATSAPP_INBOUND_MAX_SKEW_MS = 5 * 60 * 1000;

const NonEmptyString = z.string().trim().min(1);

const WhatsAppInboundAttachmentSchema = z
	.object({
		mediaType: NonEmptyString,
		bytesBase64: NonEmptyString,
		scanState: z.enum(["pending", "clean", "blocked", "failed"]).optional(),
	})
	.strict();

export const WhatsAppInboundBridgeEventSchema = z
	.object({
		schemaVersion: z.literal(WHATSAPP_INBOUND_BRIDGE_SCHEMA_VERSION),
		eventId: NonEmptyString,
		messageId: NonEmptyString,
		cursorSequence: z.number().int().nonnegative(),
		chatKind: z.enum(["direct", "group"]),
		senderAddressRef: NonEmptyString,
		conversationKey: NonEmptyString,
		text: z.string().optional(),
		attachments: z.array(WhatsAppInboundAttachmentSchema).default([]),
		receivedAtMs: z.number().int().positive(),
	})
	.strict();

export type WhatsAppInboundBridgeEvent = z.infer<typeof WhatsAppInboundBridgeEventSchema>;

type WhatsAppIdentityResolutionBase = {
	readonly actorId: string;
	readonly profileId: string;
	readonly principalId: string;
	readonly displayName?: string;
	readonly identityAssurance: "strong_link";
	readonly authorizationScopes: readonly string[];
	readonly actorScopes: readonly ActorRef["scopes"][number][];
	readonly humanPairingProvenance: true;
};

export type WhatsAppIdentityResolution =
	| (WhatsAppIdentityResolutionBase & {
			readonly domain: "private";
	  })
	| (WhatsAppIdentityResolutionBase & {
			readonly domain: "household";
			readonly bindingId: string;
			readonly subjectUserId: string;
			readonly memorySource: `household:${string}`;
			readonly writableNamespace: `household:${string}`;
			readonly replyAddressRef: string;
			readonly expectedConversationKey: string;
			readonly conversationId: string;
	  });

export type WhatsAppIdentityResolver = (input: {
	readonly senderAddressRef: string;
	readonly event: WhatsAppInboundBridgeEvent;
}) => WhatsAppIdentityResolution | null;

export type WhatsAppInboundCl1Failure = {
	readonly ok: false;
	readonly code: string;
	readonly reason: string;
	readonly retryable: boolean;
};

export type WhatsAppInboundCl1Result =
	| {
			readonly ok: true;
			readonly duplicate: false;
			readonly intercepted: false;
			readonly event: InboundEvent;
			readonly conversation: RelayConversation;
			readonly turn: ReturnType<RelayConversationStore["mintInboundTurn"]>["turn"];
			readonly identity: WhatsAppIdentityResolution;
	  }
	| {
			readonly ok: true;
			readonly duplicate: false;
			readonly intercepted: true;
			readonly templateId: string;
	  }
	| {
			readonly ok: true;
			readonly duplicate: true;
			readonly duplicateHandling: "duplicate" | "replayed";
			readonly reason: string;
			readonly conversation?: RelayConversation;
	  }
	| WhatsAppInboundCl1Failure;

export type WhatsAppInboundCl1Pipeline = {
	ingest(input: {
		readonly event: unknown;
		readonly signature: string;
	}): Promise<WhatsAppInboundCl1Result>;
};

export type CreateOperatorWhatsAppIdentityResolverOptions = {
	readonly operatorAddressRefs: readonly string[];
	readonly profileId: string;
	readonly actorId?: string;
	readonly displayName?: string;
};

export type CreateWhatsAppInboundCl1PipelineOptions = {
	readonly signatureSecret: string;
	readonly conversationStore: RelayConversationStore;
	readonly quarantineStore: AttachmentQuarantineStore;
	readonly resolveIdentity: WhatsAppIdentityResolver;
	readonly nowMs?: () => number;
	readonly maxSkewMs?: number;
	readonly onInboundEvent?: (event: InboundEvent) => Promise<void>;
	readonly interceptBeforePersistence?: (input: {
		readonly event: WhatsAppInboundBridgeEvent;
		readonly identity: WhatsAppIdentityResolution;
		readonly conversation: RelayConversation | null;
	}) => Promise<
		{ readonly handled: false } | { readonly handled: true; readonly templateId: string }
	>;
};

export function createOperatorWhatsAppIdentityResolver(
	options: CreateOperatorWhatsAppIdentityResolverOptions,
): WhatsAppIdentityResolver {
	const allowed = new Set(
		options.operatorAddressRefs.map((entry) => normalizeWhatsAppAddressRef(entry)).filter(Boolean),
	);
	if (allowed.size === 0) {
		throw new Error("operator WhatsApp identity resolver requires at least one E.164 address");
	}
	const profileId = requiredTrimmed(options.profileId, "profileId");

	return ({ senderAddressRef }) => {
		const principalId = normalizeWhatsAppAddressRef(senderAddressRef);
		if (!principalId || !allowed.has(principalId)) return null;
		const actorId = options.actorId?.trim() || `operator:whatsapp:${hashShort(principalId)}`;
		const grantedAt = new Date(0).toISOString();
		return {
			actorId,
			profileId,
			domain: "private",
			principalId,
			...(options.displayName ? { displayName: options.displayName.trim() } : {}),
			identityAssurance: "strong_link",
			authorizationScopes: ["message:read", "message:reply"],
			actorScopes: [
				{ scope: "message:read", actions: ["read"], grantedAt },
				{ scope: "message:reply", actions: ["reply"], grantedAt },
			],
			humanPairingProvenance: true,
		};
	};
}

export function createWhatsAppInboundCl1Pipeline(
	options: CreateWhatsAppInboundCl1PipelineOptions,
): WhatsAppInboundCl1Pipeline {
	const signatureSecret = requiredTrimmed(options.signatureSecret, "signatureSecret");
	const nowMs = options.nowMs ?? Date.now;
	const maxSkewMs = options.maxSkewMs ?? DEFAULT_WHATSAPP_INBOUND_MAX_SKEW_MS;

	return {
		async ingest(input) {
			const parsed = WhatsAppInboundBridgeEventSchema.safeParse(input.event);
			if (!parsed.success) {
				return failure(
					"whatsapp_inbound_event_invalid",
					"WhatsApp inbound event failed strict CL-1 schema validation",
					false,
				);
			}
			const event = parsed.data;
			if (!verifyWhatsAppInboundBridgeEventSignature(event, input.signature, signatureSecret)) {
				return failure(
					"whatsapp_inbound_signature_invalid",
					"WhatsApp inbound bridge event signature is invalid",
					false,
				);
			}
			const now = nowMs();
			if (Math.abs(now - event.receivedAtMs) > maxSkewMs) {
				return failure(
					"whatsapp_inbound_signature_stale",
					"WhatsApp inbound bridge event timestamp is outside the accepted skew",
					false,
				);
			}
			if (event.chatKind !== "direct") {
				return failure(
					"whatsapp_inbound_group_unsupported",
					"WhatsApp group inbound is disabled until group CL-1 policy exists",
					false,
				);
			}
			const senderAddressRef = normalizeWhatsAppAddressRef(event.senderAddressRef);
			if (!senderAddressRef) {
				return failure(
					"whatsapp_inbound_sender_invalid",
					"WhatsApp inbound sender must be an E.164 number with optional whatsapp: prefix",
					false,
				);
			}
			const identity = options.resolveIdentity({ senderAddressRef, event });
			if (!identity) {
				return failure(
					"whatsapp_inbound_sender_unlinked",
					"WhatsApp inbound sender is not linked to an authorized identity",
					false,
				);
			}
			if (
				identity.domain === "household" &&
				event.conversationKey !== identity.expectedConversationKey
			) {
				return failure(
					"whatsapp_inbound_conversation_mismatch",
					"WhatsApp inbound conversation does not match the enrolled reply address",
					false,
				);
			}
			const conversationId = conversationIdFor(event, identity);
			const existing = options.conversationStore
				.list({ channel: "whatsapp" })
				.find((conversation) => conversation.conversationId === conversationId);
			if (existing?.threadMessageIds.includes(event.messageId)) {
				return {
					ok: true,
					duplicate: true,
					duplicateHandling: "duplicate",
					reason: "WhatsApp inbound message id was already processed",
					conversation: existing,
				};
			}
			const cursor = cursorFor(event.cursorSequence);
			if (existing?.inboundCursor) {
				const previous = parseCursorSequence(existing.inboundCursor);
				if (previous === null) {
					return failure(
						"whatsapp_inbound_cursor_untrusted",
						"Existing WhatsApp inbound cursor is not CL-1 comparable",
						false,
					);
				}
				if (event.cursorSequence <= previous) {
					return {
						ok: true,
						duplicate: true,
						duplicateHandling: "replayed",
						reason: "WhatsApp inbound cursor was replayed or moved backwards",
						conversation: existing,
					};
				}
			}
			const intercepted = await options.interceptBeforePersistence?.({
				event,
				identity,
				conversation: existing ?? null,
			});
			if (intercepted?.handled) {
				return {
					ok: true,
					duplicate: false,
					intercepted: true,
					templateId: intercepted.templateId,
				};
			}
			let decodedAttachments: {
				readonly bytes: Uint8Array;
				readonly mediaType: string;
				readonly scanState: WhatsAppInboundBridgeEvent["attachments"][number]["scanState"];
			}[];
			try {
				decodedAttachments = event.attachments.map((attachment) => ({
					bytes: decodeBase64Bytes(attachment.bytesBase64),
					mediaType: attachment.mediaType,
					scanState: attachment.scanState,
				}));
			} catch (error) {
				return failure(
					"whatsapp_inbound_attachment_invalid",
					error instanceof Error ? error.message : "WhatsApp inbound attachment is invalid",
					false,
				);
			}

			const { conversation } = options.conversationStore.resumeOrMint({
				channel: "whatsapp",
				conversationId,
				threadId: identity.domain === "household" ? identity.replyAddressRef : conversationId,
				profileId: identity.profileId,
				domain: identity.domain,
				authorizationState: "authorized",
				humanPairingProvenance: identity.humanPairingProvenance,
				authorizationScopes: identity.authorizationScopes,
				members: [
					{
						actorId: identity.actorId,
						principalId: identity.principalId,
						...(identity.displayName ? { displayName: identity.displayName } : {}),
						role: "sender",
						identityAssurance: identity.identityAssurance,
						scopes: ["message:reply", "whatsapp:reply"],
					},
				],
				threadMessageIds: [event.messageId],
				inboundCursor: cursor,
				auditIds: [auditIdFor(event)],
				nowMs: now,
			});
			let mediaRefs: AttachmentRef[];
			try {
				mediaRefs = decodedAttachments.map((attachment) =>
					options.quarantineStore.store({
						bytes: attachment.bytes,
						mediaType: attachment.mediaType,
						conversationToken: conversation.token,
						scanState: attachment.scanState ?? "pending",
						trustLabel: "untrusted",
					}),
				);
			} catch (error) {
				return failure(
					"whatsapp_inbound_attachment_invalid",
					error instanceof Error ? error.message : "WhatsApp inbound attachment quarantine failed",
					false,
				);
			}
			const turn = options.conversationStore.mintInboundTurn({
				conversationToken: conversation.token,
				inboundMessageId: event.messageId,
				senderActorId: identity.actorId,
				nowMs: now,
			}).turn;
			const inboundEvent = InboundEventSchema.parse({
				schemaVersion: EdgeAdapterSchemaVersions.inboundEvent,
				channel: "whatsapp",
				conversationRef: relayConversationToConversationRef(conversation),
				actorRef: actorRefForIdentity(identity, now),
				receivedAt: new Date(event.receivedAtMs).toISOString(),
				normalized: {
					...(event.text !== undefined
						? {
								text: wrapExternalContent(event.text, {
									source: "user-forwarded",
									serviceId: "whatsapp",
								}),
							}
						: {}),
					mediaRefs,
				},
				riskLabels: riskLabelsFor(event.text),
				sourceAudit: {
					auditId: auditIdFor(event),
					sourceEventId: event.eventId,
					platformMessageId: event.messageId,
					transport: "whatsapp-bridge",
				},
				ordering: {
					cursor,
					sequence: event.cursorSequence,
					duplicateHandling: "first_seen",
				},
			});
			await options.onInboundEvent?.(inboundEvent);
			return {
				ok: true,
				duplicate: false,
				intercepted: false,
				event: inboundEvent,
				conversation,
				turn,
				identity,
			};
		},
	};
}

export function signWhatsAppInboundBridgeEvent(event: unknown, secret: string): `sha256:${string}` {
	const digest = crypto
		.createHmac("sha256", requiredTrimmed(secret, "secret"))
		.update(canonicalJson(event))
		.digest("hex");
	return `sha256:${digest}`;
}

function verifyWhatsAppInboundBridgeEventSignature(
	event: WhatsAppInboundBridgeEvent,
	signature: string,
	secret: string,
): boolean {
	if (!/^sha256:[a-f0-9]{64}$/.test(signature)) return false;
	const expected = signWhatsAppInboundBridgeEvent(event, secret);
	return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function actorRefForIdentity(identity: WhatsAppIdentityResolution, nowMs: number): ActorRef {
	return ActorRefSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.actorRef,
		actorId: identity.actorId,
		channelIdentity: {
			channel: "whatsapp",
			principalId: identity.principalId,
			...(identity.displayName ? { displayName: identity.displayName } : {}),
		},
		identityAssurance: identity.identityAssurance,
		scopes: identity.actorScopes.map((scope) => ({
			...scope,
			grantedAt:
				scope.grantedAt === new Date(0).toISOString()
					? new Date(nowMs).toISOString()
					: scope.grantedAt,
		})),
		revocation: { revoked: false },
	});
}

function riskLabelsFor(text: string | undefined): string[] {
	const labels = ["cl1-risk-wrapped", "untrusted-inbound"];
	if (text !== undefined) {
		labels.push(`risk:${assessRisk(text).level}`);
	}
	return labels;
}

function conversationIdFor(
	event: WhatsAppInboundBridgeEvent,
	identity: WhatsAppIdentityResolution,
): string {
	return identity.domain === "household"
		? identity.conversationId
		: requiredTrimmed(event.conversationKey, "conversationKey");
}

function cursorFor(sequence: number): string {
	return `whatsapp-cursor:${sequence.toString().padStart(12, "0")}`;
}

function parseCursorSequence(cursor: string): number | null {
	const match = /^whatsapp-cursor:(\d{12,})$/.exec(cursor);
	if (!match) return null;
	return Number.parseInt(match[1], 10);
}

function auditIdFor(event: WhatsAppInboundBridgeEvent): string {
	return `wa-audit:${hashShort({ eventId: event.eventId, messageId: event.messageId })}`;
}

function decodeBase64Bytes(value: string): Uint8Array {
	const trimmed = value.trim();
	if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(trimmed)) {
		throw new Error("WhatsApp inbound attachment bytesBase64 is not valid base64");
	}
	const bytes = Buffer.from(trimmed, "base64");
	if (bytes.byteLength === 0) {
		throw new Error("WhatsApp inbound attachment base64 decoded to empty bytes");
	}
	return bytes;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(sortKeysDeep(value));
}

function hashShort(value: unknown): string {
	return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex").slice(0, 16);
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) throw new Error(`${field} is required`);
	return trimmed;
}

function failure(code: string, reason: string, retryable: boolean): WhatsAppInboundCl1Failure {
	return { ok: false, code, reason, retryable };
}
