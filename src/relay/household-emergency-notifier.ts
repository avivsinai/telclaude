import { getChildLogger } from "../logging.js";
import { redactHouseholdSinkText } from "../security/household-redactor.js";
import { redactSecrets } from "../security/output-filter.js";
import type { AdminAlert } from "../telegram/admin-alert.js";
import { classifyHouseholdEmergencyV1 } from "./household-emergency-classifier.js";
import type { HouseholdEmergencyControlSender } from "./household-emergency-control-sender.js";
import { householdEmergencyCopy } from "./household-emergency-copy.js";
import type {
	WhatsAppIdentityResolution,
	WhatsAppInboundBridgeEvent,
} from "./whatsapp-inbound-cl1.js";
import { parseWhatsAppOtp } from "./whatsapp-provider-challenge-interceptor.js";

const ALERT_WINDOW_MS = 5 * 60_000;
const TRIGGER_PREVIEW_CHARS = 800;
const logger = getChildLogger({ module: "household-emergency-notifier" });

type EmergencyAlertIncident = {
	readonly lastObservedAtMs: number;
	readonly repeatCount: number;
};

export type HouseholdEmergencyNotifier = (input: {
	readonly event: WhatsAppInboundBridgeEvent;
	readonly identity: WhatsAppIdentityResolution;
	readonly ensureConversation: () => unknown;
}) => Promise<
	| { readonly matched: false }
	| {
			readonly matched: true;
			readonly class: Exclude<ReturnType<typeof classifyHouseholdEmergencyV1>["class"], null>;
			readonly replySent: boolean;
	  }
>;

export function createHouseholdEmergencyNotifier(options: {
	readonly sendControl: HouseholdEmergencyControlSender;
	readonly sendAdminAlert: (alert: AdminAlert) => Promise<void>;
	readonly eligibleBindingIds?: ReadonlySet<string>;
	readonly nowMs?: () => number;
}): HouseholdEmergencyNotifier {
	const nowMs = options.nowMs ?? Date.now;
	const alertIncidents = new Map<string, EmergencyAlertIncident>();

	return async ({ event, identity, ensureConversation }) => {
		if (
			identity.domain !== "household" ||
			(options.eligibleBindingIds && !options.eligibleBindingIds.has(identity.bindingId)) ||
			parseWhatsAppOtp(event.text) !== null
		)
			return { matched: false };
		const classification = classifyHouseholdEmergencyV1(event.text, undefined);
		if (!classification.emergency) return { matched: false };

		let replySent = false;
		try {
			// This is intentionally synchronous and occurs before the first await so the
			// control sender can address even the first household conversation.
			ensureConversation();
			replySent = await options.sendControl({
				bindingId: identity.bindingId,
				replyAddressRef: identity.replyAddressRef,
				body: householdEmergencyCopy(identity.addresseeGender),
				eventMessageId: event.messageId,
			});
		} catch (error) {
			replySent = false;
			logger.warn(
				{
					bindingId: identity.bindingId,
					class: classification.class,
					error: redactSecrets(String(error)),
				},
				"household emergency reply failed",
			);
		}

		const incidentRef = `${identity.bindingId}\0${classification.class}`;
		const now = nowMs();
		const previousIncident = alertIncidents.get(incidentRef);
		const repeated =
			previousIncident !== undefined && now - previousIncident.lastObservedAtMs < ALERT_WINDOW_MS;
		const reservedIncident: EmergencyAlertIncident = {
			lastObservedAtMs: now,
			repeatCount: repeated ? previousIncident.repeatCount + 1 : 1,
		};
		alertIncidents.set(incidentRef, reservedIncident);
		const triggerText = triggerPreview(event.text ?? "");
		const repeatMetadata =
			repeated && previousIncident
				? [
						`repeat_count=${reservedIncident.repeatCount}`,
						`seconds_since_previous=${Math.max(0, Math.floor((now - previousIncident.lastObservedAtMs) / 1_000))}`,
					]
				: [];
		try {
			await options.sendAdminAlert({
				level: "error",
				title: repeated
					? `REPEATED household emergency signal — escalating (${reservedIncident.repeatCount}×)`
					: "Household emergency signal",
				message: [
					...repeatMetadata,
					`class=${classification.class}`,
					`parent=${identity.displayName?.trim() || identity.bindingId}`,
					`timestamp=${new Date(event.receivedAtMs).toISOString()}`,
					`reply_sent=${replySent}`,
					`trigger=${triggerText}`,
				].join("\n"),
			});
		} catch (error) {
			if (alertIncidents.get(incidentRef) === reservedIncident) {
				if (repeated && previousIncident) alertIncidents.set(incidentRef, previousIncident);
				else alertIncidents.delete(incidentRef);
			}
			logger.warn(
				{
					bindingId: identity.bindingId,
					class: classification.class,
					error: redactSecrets(String(error)),
				},
				"household emergency operator alert failed",
			);
		}

		return { matched: true, class: classification.class, replySent };
	};
}

function triggerPreview(value: string): string {
	const normalized = redactHouseholdSinkText(value).replace(/\s+/gu, " ").trim();
	const characters = Array.from(normalized);
	return characters.length <= TRIGGER_PREVIEW_CHARS
		? normalized
		: `${characters.slice(0, TRIGGER_PREVIEW_CHARS).join("")}…`;
}
