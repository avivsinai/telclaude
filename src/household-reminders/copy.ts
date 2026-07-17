import type { HouseholdReminder, HouseholdReminderProposalAction } from "./types.js";

export const HOUSEHOLD_REMINDER_CONFIRMATION_COPY = Object.freeze({
	confirmed: "התזכורת נקבעה.",
	rejected: "התזכורת בוטלה.",
	unchanged: "לא שיניתי כלום; התזכורת נשארת כמו שהיא.",
	proposal_expired: "הבקשה פגה ולא בוצעה. אפשר לנסות שוב.",
	failed: "לא ביצעתי את הבקשה. אפשר לנסות שוב.",
	choice_required: "כדי להמשיך, שלחי בדיוק 1 או 2.\n1. אישור\n2. ביטול",
});

export type HouseholdReminderConfirmationTemplateId =
	keyof typeof HOUSEHOLD_REMINDER_CONFIRMATION_COPY;

export function householdReminderProposalPrompt(
	action: HouseholdReminderProposalAction,
	reminder: HouseholdReminder,
): string {
	const actionLine =
		action === "create"
			? "לאשר את התזכורת החד-פעמית?"
			: action === "update"
				? "לאשר את עדכון התזכורת?"
				: "לאשר את ביטול התזכורת?";
	const details =
		action === "cancel"
			? `תזכורת: ${reminder.text}`
			: `תזכורת: ${reminder.text}\nמועד: ${reminder.schedule.localDateTime} (שעון ישראל)`;
	return `${actionLine}\n${details}\n1. אישור\n2. ביטול`;
}
