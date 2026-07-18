import crypto from "node:crypto";
import type { TelclaudeConfig } from "../config/config.js";
import type { EffectiveOperatorProfile } from "../config/profiles.js";
import {
	ActorRefSchema,
	EdgeAdapterSchemaVersions,
	InboundEventSchema,
} from "../hermes/edge-adapter-contract.js";
import {
	type RelayConversation,
	type RelayConversationInboundTurn,
	type RelayConversationStore,
	relayConversationToConversationRef,
} from "../hermes/relay-conversation-store.js";
import { wrapExternalContent } from "../security/external-content.js";
import type {
	MediaActionConfirmation,
	MediaActionConfirmationPayload,
} from "./media-action-confirmation-store.js";
import type { WhatsAppIdentityResolution } from "./whatsapp-inbound-cl1.js";
import type {
	WhatsAppInboundDispatchInput,
	WhatsAppInboundDispatchResult,
} from "./whatsapp-inbound-dispatcher.js";

type WhatsAppInboundDispatch = (
	input: WhatsAppInboundDispatchInput,
) => Promise<WhatsAppInboundDispatchResult>;

export type MediaActionConfirmationDispatcher = {
	mintFreshTurn(input: {
		readonly confirmation: MediaActionConfirmation;
		readonly eventId: string;
		readonly messageId: string;
		readonly identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>;
		readonly conversation: RelayConversation;
	}): RelayConversationInboundTurn;
	dispatch(input: {
		readonly freshTurnRef: string;
		readonly payload: MediaActionConfirmationPayload;
		readonly confirmation: MediaActionConfirmation;
		readonly identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>;
		readonly conversation: RelayConversation;
		readonly config: Pick<TelclaudeConfig, "hermes">;
		readonly profile: EffectiveOperatorProfile;
	}): Promise<WhatsAppInboundDispatchResult>;
};

export function createMediaActionConfirmationDispatcher(options: {
	readonly conversationStore: RelayConversationStore;
	readonly dispatch: WhatsAppInboundDispatch;
	readonly nowMs?: () => number;
}): MediaActionConfirmationDispatcher {
	const nowMs = options.nowMs ?? Date.now;
	return {
		mintFreshTurn(input) {
			const now = nowMs();
			return options.conversationStore.mintInboundTurn({
				conversationToken: input.conversation.token,
				inboundMessageId: `media-confirmation:${eventDigest(input.eventId, input.messageId)}`,
				senderActorId: input.identity.actorId,
				expiresAtMs: input.confirmation.expiresAtMs,
				nowMs: now,
			}).turn;
		},

		async dispatch(input) {
			const turn = options.conversationStore.resolveAuthorizedInboundTurn(
				input.freshTurnRef,
				input.conversation.token,
				nowMs(),
			);
			if (!turn || turn.senderActorId !== input.identity.actorId) {
				throw new Error("media confirmation fresh turn is unavailable");
			}
			const now = nowMs();
			const event = InboundEventSchema.parse({
				schemaVersion: EdgeAdapterSchemaVersions.inboundEvent,
				channel: "whatsapp",
				conversationRef: relayConversationToConversationRef(input.conversation),
				actorRef: actorRef(input.identity, now),
				receivedAt: new Date(now).toISOString(),
				normalized: { text: confirmedActionText(input.payload), mediaRefs: [] },
				riskLabels: [
					"cl1-risk-wrapped",
					"untrusted-inbound",
					"media-derived-untrusted",
					"media-action-confirmed",
				],
				sourceAudit: {
					auditId: `media-confirmation:${input.confirmation.actionDigest}`,
					sourceEventId: input.confirmation.sourceDigest,
					platformMessageId: input.confirmation.derivedDigest,
					transport: "whatsapp-media-confirmation",
				},
				ordering: {
					cursor: `media-confirmation:${input.confirmation.actionDigest}`,
					sequence: 0,
					duplicateHandling: "first_seen",
				},
			});
			return options.dispatch({
				event,
				conversation: input.conversation,
				turn,
				identity: input.identity,
				config: input.config,
				profile: input.profile,
			});
		},
	};
}

function confirmedActionText(payload: MediaActionConfirmationPayload): string {
	const derivations = payload.envelopes
		.map((envelope) =>
			wrapExternalContent(envelope.text, {
				source: "user-forwarded",
				serviceId: `whatsapp-confirmed-${envelope.kind}`,
				foldHomoglyphs: false,
				maxLength: 16_000,
			}),
		)
		.join("\n\n");
	return [
		"<relay-confirmed-media-action>",
		"The household user confirmed exactly one consequential action derived from the quoted attachment content.",
		"Use the named relay tool once with exactly the canonical parameters below. Do not change the action or parameters.",
		`Canonical action: ${JSON.stringify(payload.action)}`,
		"<quoted-media-derived-content>",
		derivations,
		"</quoted-media-derived-content>",
		"</relay-confirmed-media-action>",
	].join("\n");
}

function actorRef(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	nowMs: number,
) {
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

function eventDigest(eventId: string, messageId: string): string {
	return crypto.createHash("sha256").update(`${eventId}\n${messageId}`).digest("hex");
}
