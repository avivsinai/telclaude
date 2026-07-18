import type { TelclaudeConfig } from "../config/config.js";
import type { RelayConversation } from "../hermes/relay-conversation-store.js";
import { resolveHouseholdReminderContext } from "../household-reminders/binding.js";
import {
	type HouseholdReminderConfirmationTemplateId,
	householdReminderConfirmationCopy,
} from "../household-reminders/copy.js";
import {
	getHouseholdReminderInterceptionReceipt,
	getPendingHouseholdReminderProposal,
	type HouseholdReminderInterceptionReceipt,
	markHouseholdReminderInterceptionReceiptAcked,
	resolveHouseholdReminderProposalWithInterceptionReceipt,
} from "../household-reminders/store.js";
import type { WhatsAppReminderConfirmationControlSender } from "./reminder-confirmation-control-sender.js";
import type {
	WhatsAppIdentityResolution,
	WhatsAppInboundBridgeEvent,
} from "./whatsapp-inbound-cl1.js";

const REMINDER_CHOICE_ATTEMPTS = new Set([
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

export type WhatsAppReminderConfirmationInterceptResult =
	| { readonly handled: false }
	| {
			readonly handled: true;
			readonly templateId: HouseholdReminderConfirmationTemplateId;
	  };

export type WhatsAppReminderConfirmationInterceptor = (input: {
	readonly event: WhatsAppInboundBridgeEvent;
	readonly identity: WhatsAppIdentityResolution;
	readonly conversation: RelayConversation | null;
}) => Promise<WhatsAppReminderConfirmationInterceptResult>;

export function createWhatsAppReminderConfirmationInterceptor(options: {
	readonly config: TelclaudeConfig;
	readonly sendControl: WhatsAppReminderConfirmationControlSender;
	readonly nowMs?: () => number;
}): WhatsAppReminderConfirmationInterceptor {
	const nowMs = options.nowMs ?? Date.now;
	return async ({ event, identity, conversation }) => {
		if (identity.domain !== "household" || !isCurrentConversation(identity, conversation)) {
			return { handled: false };
		}
		const context = resolveHouseholdReminderContext(
			{
				actorId: identity.actorId,
				subjectUserId: identity.subjectUserId,
				profileId: identity.profileId,
			},
			options.config,
		);
		if (!context || context.binding.conversationId !== identity.conversationId) {
			return { handled: false };
		}
		const existingReceipt = getHouseholdReminderInterceptionReceipt({
			eventId: event.eventId,
			messageId: event.messageId,
			authority: context.authority,
			binding: context.binding,
		});
		if (existingReceipt) {
			return acknowledgeReceipt(options.sendControl, identity, existingReceipt, nowMs());
		}
		const proposal = getPendingHouseholdReminderProposal(context.authority, context.binding);
		if (!proposal) return { handled: false };

		const choice = event.attachments.length === 0 ? parseWhatsAppReminderChoice(event.text) : null;
		if (!choice) {
			return event.attachments.length > 0 || isReminderChoiceAttempt(event.text)
				? sendTemplate(options.sendControl, identity, "choice_required")
				: { handled: false };
		}
		const receipt = resolveHouseholdReminderProposalWithInterceptionReceipt({
			eventId: event.eventId,
			messageId: event.messageId,
			proposalRef: proposal.ref,
			choice,
			...context,
			nowMs: nowMs(),
		});
		return receipt
			? acknowledgeReceipt(options.sendControl, identity, receipt, nowMs())
			: sendTemplate(options.sendControl, identity, "failed");
	};
}

export function parseWhatsAppReminderChoice(text: string | undefined): "confirm" | "reject" | null {
	if (text === "1") return "confirm";
	if (text === "2") return "reject";
	return null;
}

function isReminderChoiceAttempt(text: string | undefined): boolean {
	if (text === undefined || text.length > 32) return false;
	return REMINDER_CHOICE_ATTEMPTS.has(text.normalize("NFKC").trim().toLowerCase());
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

async function acknowledgeReceipt(
	sendControl: WhatsAppReminderConfirmationControlSender,
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	receipt: HouseholdReminderInterceptionReceipt,
	nowMs: number,
): Promise<Extract<WhatsAppReminderConfirmationInterceptResult, { handled: true }>> {
	if (receipt.status === "pending_ack") {
		await sendControl({
			templateId: receipt.templateId,
			body: householdReminderConfirmationCopy(receipt.templateId, identity.addresseeGender),
			replyAddressRef: identity.replyAddressRef,
			bindingId: identity.bindingId,
			deliveryRef: receipt.receiptId,
		});
		if (!markHouseholdReminderInterceptionReceiptAcked(receipt.receiptId, nowMs)) {
			throw new Error("household reminder interception ACK persistence failed");
		}
	}
	return { handled: true, templateId: receipt.templateId };
}

async function sendTemplate(
	sendControl: WhatsAppReminderConfirmationControlSender,
	identity: Extract<WhatsAppIdentityResolution, { domain: "household" }>,
	templateId: HouseholdReminderConfirmationTemplateId,
): Promise<Extract<WhatsAppReminderConfirmationInterceptResult, { handled: true }>> {
	await sendControl({
		templateId,
		body: householdReminderConfirmationCopy(templateId, identity.addresseeGender),
		replyAddressRef: identity.replyAddressRef,
		bindingId: identity.bindingId,
	});
	return { handled: true, templateId };
}
