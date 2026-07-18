import crypto from "node:crypto";
import type { TelclaudeConfig } from "../config/config.js";
import type { EffectiveOperatorProfile } from "../config/profiles.js";
import type { RelayConversation } from "../hermes/relay-conversation-store.js";
import type { WhatsAppMediaActionConfirmationControlSender } from "./media-action-confirmation-control-sender.js";
import { mediaActionConfirmationCopy } from "./media-action-confirmation-copy.js";
import type { MediaActionConfirmationDispatcher } from "./media-action-confirmation-dispatcher.js";
import type {
	MediaActionConfirmationChoice,
	MediaActionConfirmationStore,
	MediaConfirmationOwner,
} from "./media-action-confirmation-store.js";
import type {
	WhatsAppIdentityResolution,
	WhatsAppInboundBridgeEvent,
} from "./whatsapp-inbound-cl1.js";

const MEDIA_CHOICE_ATTEMPTS = new Set([
	"1",
	"2",
	"כן",
	"לא",
	"אישור",
	"ביטול",
	"confirm",
	"cancel",
	"yes",
	"no",
]);

export type WhatsAppMediaActionConfirmationInterceptResult =
	| { readonly handled: false }
	| {
			readonly handled: true;
			readonly templateId: "choice_required" | "confirmed" | "rejected" | "expired" | "failed";
	  };

export type WhatsAppMediaActionConfirmationInterceptor = (input: {
	readonly event: WhatsAppInboundBridgeEvent;
	readonly identity: WhatsAppIdentityResolution;
	readonly conversation: RelayConversation | null;
}) => Promise<WhatsAppMediaActionConfirmationInterceptResult>;

export function createWhatsAppMediaActionConfirmationInterceptor(options: {
	readonly store: MediaActionConfirmationStore;
	readonly dispatcher: MediaActionConfirmationDispatcher;
	readonly sendControl: WhatsAppMediaActionConfirmationControlSender;
	readonly config: Pick<TelclaudeConfig, "hermes">;
	readonly eligibleBindingIds?: ReadonlySet<string>;
	readonly resolveProfile: (
		identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	) => EffectiveOperatorProfile | null;
	readonly nowMs?: () => number;
}): WhatsAppMediaActionConfirmationInterceptor {
	const nowMs = options.nowMs ?? Date.now;
	return async ({ event, identity, conversation }) => {
		if (identity.domain !== "household" || !isCurrentConversation(identity, conversation)) {
			return { handled: false };
		}
		if (options.eligibleBindingIds && !options.eligibleBindingIds.has(identity.bindingId)) {
			return { handled: false };
		}
		if (event.attachments.length > 0) return { handled: false };
		const owner = ownerFor(identity, conversation);
		const choice = parseWhatsAppMediaActionChoice(event.text);
		if (!choice) {
			const pending = options.store.peekPendingForOwner({ owner, nowMs: nowMs() });
			if (!pending || !isMediaChoiceAttempt(event.text)) return { handled: false };
			return sendTemplate(
				options.sendControl,
				identity,
				"choice_required",
				`${pending.confirmationId}:retry:${eventHash(event.eventId, event.messageId)}`,
			);
		}

		let mintedConfirmationId: string | null = null;
		const receipt = options.store.resolveChoice({
			owner,
			eventId: event.eventId,
			messageId: event.messageId,
			choice,
			nowMs: nowMs(),
			mintFreshTurn: (confirmation) => {
				mintedConfirmationId = confirmation.confirmationId;
				return options.dispatcher.mintFreshTurn({
					confirmation,
					eventId: event.eventId,
					messageId: event.messageId,
					identity,
					conversation,
				});
			},
		});
		if (!receipt) return { handled: false };
		if (receipt.newlyResolved && receipt.status === "confirmed") {
			const confirmation = options.store.inspectConfirmation(receipt.confirmationId);
			const profile = options.resolveProfile(identity);
			if (
				!confirmation ||
				!profile ||
				!receipt.payload ||
				!receipt.freshTurnRef ||
				mintedConfirmationId !== receipt.confirmationId
			) {
				throw new Error("media confirmation fresh dispatch binding failed");
			}
			const dispatched = await options.dispatcher.dispatch({
				freshTurnRef: receipt.freshTurnRef,
				payload: receipt.payload,
				confirmation,
				identity,
				conversation,
				config: options.config,
				profile,
			});
			if (!dispatched.ok) throw new Error("media confirmation action dispatch failed");
		}
		return sendTemplate(
			options.sendControl,
			identity,
			receipt.templateId,
			`${receipt.confirmationId}:resolve:${eventHash(event.eventId, event.messageId)}`,
		);
	};
}

export function parseWhatsAppMediaActionChoice(
	text: string | undefined,
): MediaActionConfirmationChoice | null {
	if (text === undefined || text.length > 32) return null;
	const normalized = text.normalize("NFKC").trim().toLowerCase();
	if (normalized === "1" || normalized === "כן" || normalized === "אישור") return "confirm";
	if (normalized === "2" || normalized === "לא" || normalized === "ביטול") return "reject";
	return null;
}

function isMediaChoiceAttempt(text: string | undefined): boolean {
	if (text === undefined || text.length > 32) return false;
	return MEDIA_CHOICE_ATTEMPTS.has(text.normalize("NFKC").trim().toLowerCase());
}

function isCurrentConversation(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	conversation: RelayConversation | null,
): conversation is RelayConversation {
	return (
		conversation?.channel === "whatsapp" &&
		conversation.domain === "household" &&
		conversation.authorizationState === "authorized" &&
		conversation.revokedAtMs === null &&
		conversation.humanPairingProvenance === true &&
		conversation.conversationId === identity.conversationId &&
		conversation.profileId === identity.profileId
	);
}

function ownerFor(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	conversation: RelayConversation,
): MediaConfirmationOwner {
	return {
		actorId: identity.actorId,
		subjectUserId: identity.subjectUserId,
		profileId: identity.profileId,
		bindingId: identity.bindingId,
		conversationId: conversation.conversationId,
		senderPrincipalHash: `sha256:${crypto
			.createHash("sha256")
			.update(identity.principalId)
			.digest("hex")}`,
	};
}

async function sendTemplate(
	sendControl: WhatsAppMediaActionConfirmationControlSender,
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	templateId: "choice_required" | "confirmed" | "rejected" | "expired" | "failed",
	deliveryRef: string,
): Promise<Extract<WhatsAppMediaActionConfirmationInterceptResult, { handled: true }>> {
	await sendControl({
		templateId,
		body: mediaActionConfirmationCopy(templateId, identity.addresseeGender),
		bindingId: identity.bindingId,
		deliveryRef,
	});
	return { handled: true, templateId };
}

function eventHash(eventId: string, messageId: string): string {
	return crypto.createHash("sha256").update(`${eventId}\n${messageId}`).digest("hex");
}
