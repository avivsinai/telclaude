import crypto from "node:crypto";
import type { RelayConversation } from "../hermes/relay-conversation-store.js";
import {
	type PendingProviderChallengeBindingEvidence,
	type PendingProviderChallengeClaim,
	type PendingProviderChallengeRegistry,
	pendingProviderChallengeRegistry,
} from "./pending-provider-challenge.js";
import type {
	WhatsAppIdentityResolution,
	WhatsAppInboundBridgeEvent,
} from "./whatsapp-inbound-cl1.js";

export const WHATSAPP_PROVIDER_CHALLENGE_COPY = Object.freeze({
	f: Object.freeze({
		challenge_sent: "שלחנו עכשיו קוד אימות ב-SMS. שלחי כאן רק את הספרות מההודעה.",
		challenge_type_digits: "תכתבי את המספרים בהודעה",
		challenge_invalid_format: "שלחי רק את קוד האימות בן 4 עד 8 הספרות.",
		challenge_success_repeat_request: "האימות הושלם. עכשיו שלחי שוב את הבקשה המקורית.",
		challenge_expired_restart: "קוד האימות פג. התחילי שוב את החיבור לשירות.",
		challenge_failed_restart: "לא הצלחנו לאמת את הקוד. התחילי שוב את החיבור לשירות.",
		challenge_unarmed_safety: "אין כרגע אימות שממתין לקוד. אל תשלחי קודי אימות בצ׳אט.",
	}),
	m: Object.freeze({
		challenge_sent: "שלחנו עכשיו קוד אימות ב-SMS. שלח כאן רק את הספרות מההודעה.",
		challenge_type_digits: "תכתוב את המספרים בהודעה",
		challenge_invalid_format: "שלח רק את קוד האימות בן 4 עד 8 הספרות.",
		challenge_success_repeat_request: "האימות הושלם. עכשיו שלח שוב את הבקשה המקורית.",
		challenge_expired_restart: "קוד האימות פג. התחל שוב את החיבור לשירות.",
		challenge_failed_restart: "לא הצלחנו לאמת את הקוד. התחל שוב את החיבור לשירות.",
		challenge_unarmed_safety: "אין כרגע אימות שממתין לקוד. אל תשלח קודי אימות בצ׳אט.",
	}),
});

export type WhatsAppProviderChallengeTemplateId = keyof typeof WHATSAPP_PROVIDER_CHALLENGE_COPY.f;

export function whatsAppProviderChallengeCopy(
	templateId: WhatsAppProviderChallengeTemplateId,
	addresseeGender: "f" | "m",
): string {
	const variants = WHATSAPP_PROVIDER_CHALLENGE_COPY[addresseeGender];
	if (!variants) throw new Error("provider challenge addressee gender is unavailable");
	return variants[templateId];
}

export type WhatsAppProviderChallengeControlSender = (input: {
	readonly templateId: WhatsAppProviderChallengeTemplateId;
	readonly body: string;
	readonly replyAddressRef: string;
	readonly bindingId: string;
}) => Promise<void>;

export type WhatsAppProviderChallengeResponder = (input: {
	readonly claim: PendingProviderChallengeClaim;
	readonly code: string;
}) => Promise<{ readonly status: "success" | "rejected" | "expired" | "error" }>;

export type WhatsAppProviderChallengeInterceptResult =
	| { readonly handled: false }
	| {
			readonly handled: true;
			readonly templateId: WhatsAppProviderChallengeTemplateId;
	  };

export type WhatsAppProviderChallengeInterceptor = (input: {
	readonly event: WhatsAppInboundBridgeEvent;
	readonly identity: WhatsAppIdentityResolution;
	readonly conversation: RelayConversation | null;
}) => Promise<WhatsAppProviderChallengeInterceptResult>;

export function createWhatsAppProviderChallengeInterceptor(options: {
	readonly respondToChallenge: WhatsAppProviderChallengeResponder;
	readonly sendControl: WhatsAppProviderChallengeControlSender;
	readonly registry?: PendingProviderChallengeRegistry;
	readonly nowMs?: () => number;
}): WhatsAppProviderChallengeInterceptor {
	const registry = options.registry ?? pendingProviderChallengeRegistry;
	const nowMs = options.nowMs ?? Date.now;

	return async ({ event, identity, conversation }) => {
		if (identity.domain !== "household") return { handled: false };
		const binding = bindingEvidence(identity, conversation);
		const otp = parseWhatsAppOtp(event.text);
		if (!binding) {
			return otp
				? sendTemplate(options.sendControl, identity, "challenge_unarmed_safety")
				: { handled: false };
		}

		const lookup = registry.peekForInbound(binding, nowMs());
		if (lookup.status === "none") {
			return otp
				? sendTemplate(options.sendControl, identity, "challenge_unarmed_safety")
				: { handled: false };
		}
		if (lookup.status === "expired") {
			return sendTemplate(options.sendControl, identity, "challenge_expired_restart");
		}
		if (lookup.status === "binding_mismatch") {
			registry.claimForInbound(binding, nowMs());
			return sendTemplate(options.sendControl, identity, "challenge_failed_restart");
		}
		if (hasAudio(event)) {
			return sendTemplate(options.sendControl, identity, "challenge_type_digits");
		}
		if (!otp) {
			return sendTemplate(options.sendControl, identity, "challenge_invalid_format");
		}

		const claimed = registry.claimForInbound(binding, nowMs());
		if (!claimed.ok) {
			return sendTemplate(
				options.sendControl,
				identity,
				claimed.status === "expired" ? "challenge_expired_restart" : "challenge_failed_restart",
			);
		}

		let status: "success" | "rejected" | "expired" | "error" = "error";
		try {
			({ status } = await options.respondToChallenge({ claim: claimed.claim, code: otp }));
		} catch {
			// The one-shot claim stays spent; provider errors never re-arm or expose secrets.
		}
		return sendTemplate(options.sendControl, identity, outcomeTemplate(status));
	};
}

function outcomeTemplate(
	status: "success" | "rejected" | "expired" | "error",
): WhatsAppProviderChallengeTemplateId {
	if (status === "success") return "challenge_success_repeat_request";
	if (status === "expired") return "challenge_expired_restart";
	return "challenge_failed_restart";
}

export function parseWhatsAppOtp(text: string | undefined): string | null {
	if (text === undefined || text.length > 64) return null;
	if ([...text].some((character) => /\p{Nd}/u.test(character) && !/[0-9]/.test(character))) {
		return null;
	}
	const normalized = text.normalize("NFKC").trim();
	const match =
		/^(?:([0-9]{4,8})|(?:(?:קוד(?:\s+ה?אימות)?|הקוד(?:\s+הוא)?|code|otp|verification\s+code)\s*[:-]?\s*([0-9]{4,8})[.!]?))$/iu.exec(
			normalized,
		);
	return match?.[1] ?? match?.[2] ?? null;
}

function bindingEvidence(
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	conversation: RelayConversation | null,
): PendingProviderChallengeBindingEvidence | null {
	if (
		conversation?.channel !== "whatsapp" ||
		conversation.domain !== "household" ||
		conversation.authorizationState !== "authorized" ||
		conversation.revokedAtMs !== null ||
		!conversation.humanPairingProvenance ||
		conversation.conversationId !== identity.conversationId ||
		conversation.profileId !== identity.profileId
	) {
		return null;
	}
	return {
		bindingId: identity.bindingId,
		actorId: identity.actorId,
		subjectUserId: identity.subjectUserId,
		profileId: identity.profileId,
		conversationToken: conversation.token,
		conversationId: conversation.conversationId,
		senderPrincipalHash: digest(identity.principalId),
	};
}

function hasAudio(event: WhatsAppInboundBridgeEvent): boolean {
	return event.attachments.some((attachment) =>
		attachment.mediaType.trim().toLowerCase().startsWith("audio/"),
	);
}

async function sendTemplate(
	sendControl: WhatsAppProviderChallengeControlSender,
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	templateId: WhatsAppProviderChallengeTemplateId,
): Promise<Extract<WhatsAppProviderChallengeInterceptResult, { handled: true }>> {
	await sendControl({
		templateId,
		body: whatsAppProviderChallengeCopy(templateId, identity.addresseeGender),
		replyAddressRef: identity.replyAddressRef,
		bindingId: identity.bindingId,
	});
	return { handled: true, templateId };
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
