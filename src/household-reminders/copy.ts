import type { HouseholdReminder, HouseholdReminderProposalAction } from "./types.js";

export const HOUSEHOLD_REMINDER_CONFIRMATION_COPY = Object.freeze({
	f: Object.freeze({
		confirmed: "התזכורת נקבעה.",
		rejected: "התזכורת בוטלה.",
		unchanged: "לא שיניתי כלום; התזכורת נשארת כמו שהיא.",
		proposal_expired: "הבקשה פגה ולא בוצעה. אפשר לנסות שוב.",
		failed: "לא ביצעתי את הבקשה. אפשר לנסות שוב.",
		choice_required: "כדי להמשיך, שלחי בדיוק 1 או 2.\n1. אישור\n2. ביטול",
	}),
	m: Object.freeze({
		confirmed: "התזכורת נקבעה.",
		rejected: "התזכורת בוטלה.",
		unchanged: "לא שיניתי כלום; התזכורת נשארת כמו שהיא.",
		proposal_expired: "הבקשה פגה ולא בוצעה. אפשר לנסות שוב.",
		failed: "לא ביצעתי את הבקשה. אפשר לנסות שוב.",
		choice_required: "כדי להמשיך, שלח בדיוק 1 או 2.\n1. אישור\n2. ביטול",
	}),
});

export type HouseholdReminderConfirmationTemplateId =
	keyof typeof HOUSEHOLD_REMINDER_CONFIRMATION_COPY.f;

export function householdReminderConfirmationCopy(
	templateId: HouseholdReminderConfirmationTemplateId,
	addresseeGender: "f" | "m",
): string {
	const variants = HOUSEHOLD_REMINDER_CONFIRMATION_COPY[addresseeGender];
	if (!variants) throw new Error("household reminder addressee gender is unavailable");
	return variants[templateId];
}

const HOUSEHOLD_REMINDER_PROPOSAL_ACTION_COPY = Object.freeze({
	f: Object.freeze({
		create: "האם תרצי לאשר את התזכורת החד-פעמית?",
		update: "האם תרצי לאשר את עדכון התזכורת?",
		cancel: "האם תרצי לאשר את ביטול התזכורת?",
	}),
	m: Object.freeze({
		create: "האם תרצה לאשר את התזכורת החד-פעמית?",
		update: "האם תרצה לאשר את עדכון התזכורת?",
		cancel: "האם תרצה לאשר את ביטול התזכורת?",
	}),
});

export function householdReminderProposalPrompt(
	action: HouseholdReminderProposalAction,
	reminder: HouseholdReminder,
	addresseeGender: "f" | "m",
): string {
	const variants = HOUSEHOLD_REMINDER_PROPOSAL_ACTION_COPY[addresseeGender];
	if (!variants) throw new Error("household reminder addressee gender is unavailable");
	const actionLine = variants[action];
	const details =
		action === "cancel"
			? `תזכורת: ${reminder.text}`
			: `תזכורת: ${reminder.text}\nמועד: ${reminder.schedule.localDateTime} (שעון ישראל)`;
	return `${actionLine}\n${details}\n1. אישור\n2. ביטול`;
}
