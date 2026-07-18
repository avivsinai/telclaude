import crypto from "node:crypto";
import type { TelclaudeConfig } from "../config/config.js";
import { resolveWhatsAppHouseholdBindingById } from "../config/profiles.js";
import type {
	HouseholdReminderAuthority,
	HouseholdReminderBinding,
	HouseholdReminderConsentReceipt,
	Sha256Ref,
} from "./types.js";

export type HouseholdReminderContext = {
	readonly authority: HouseholdReminderAuthority;
	readonly binding: HouseholdReminderBinding;
	readonly consent: HouseholdReminderConsentReceipt;
	readonly addresseeGender: "f" | "m";
};

export function resolveHouseholdReminderContext(
	input: HouseholdReminderAuthority,
	config: TelclaudeConfig,
): HouseholdReminderContext | null {
	const bindingId = bindingIdFromSubject(input.subjectUserId);
	if (!bindingId) return null;
	const resolved = resolveWhatsAppHouseholdBindingById(bindingId, config);
	if (
		!config.householdReminders?.enabled ||
		!resolved ||
		resolved.remindersEnabled !== true ||
		resolved.actorId !== input.actorId ||
		resolved.subjectUserId !== input.subjectUserId ||
		resolved.profile.id !== input.profileId ||
		resolved.reminderConsent?.state !== "granted"
	) {
		return null;
	}
	return {
		addresseeGender: resolved.addresseeGender,
		authority: {
			actorId: resolved.actorId,
			subjectUserId: resolved.subjectUserId,
			profileId: resolved.profile.id,
		},
		binding: {
			bindingId: resolved.bindingId,
			conversationId: `whatsapp:household:${resolved.bindingId}`,
			senderPrincipalHash: digest(resolved.address),
			recipientPrincipalHash: digest(resolved.address),
		},
		consent: {
			state: "granted",
			ceremonyVersion: resolved.reminderConsent.ceremonyVersion,
			ceremonyHash: resolved.reminderConsent.ceremonyHash as Sha256Ref,
			verifiedChannelHash: resolved.reminderConsent.verifiedChannelHash as Sha256Ref,
			categories: { ...resolved.reminderConsent.categories },
			recordedAt: resolved.reminderConsent.recordedAt,
			operatorId: resolved.reminderConsent.operatorId,
		},
	};
}

function bindingIdFromSubject(subjectUserId: string): string | null {
	const prefix = "household:";
	if (!subjectUserId.startsWith(prefix)) return null;
	const bindingId = subjectUserId.slice(prefix.length).trim();
	return bindingId || null;
}

function digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
