import { describe, expect, it } from "vitest";
import {
	householdAppointmentDerivedReminderNotice,
	householdReminderConfirmationCopy,
	householdReminderProposalPrompt,
} from "../../src/household-reminders/copy.js";
import { renderHouseholdReminderBody } from "../../src/household-reminders/render.js";
import { HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE } from "../../src/household-reminders/time.js";
import type { HouseholdReminder } from "../../src/household-reminders/types.js";
import {
	HOUSEHOLD_EMERGENCY_COPY,
	householdEmergencyCopy,
} from "../../src/relay/household-emergency-copy.js";
import {
	MEDIA_ACTION_CONFIRMATION_COPY,
	mediaActionConfirmationCopy,
} from "../../src/relay/media-action-confirmation-copy.js";
import {
	WHATSAPP_PROVIDER_CHALLENGE_COPY,
	whatsAppProviderChallengeCopy,
} from "../../src/relay/whatsapp-provider-challenge-interceptor.js";

const reminder = {
	id: "reminder-gender-golden",
	revision: 1,
	text: "בדיקה",
	schedule: { localDateTime: "2026-07-20T10:00" },
} as HouseholdReminder;

const MOTHER_COPY = {
	providerChallenge: {
		challenge_sent: "שלחנו עכשיו קוד אימות ב-SMS. שלחי כאן רק את הספרות מההודעה.",
		challenge_type_digits: "תכתבי את המספרים בהודעה",
		challenge_invalid_format: "שלחי רק את קוד האימות בן 4 עד 8 הספרות.",
		challenge_success_repeat_request: "האימות הושלם. עכשיו שלחי שוב את הבקשה המקורית.",
		challenge_expired_restart: "קוד האימות פג. התחילי שוב את החיבור לשירות.",
		challenge_failed_restart: "לא הצלחנו לאמת את הקוד. התחילי שוב את החיבור לשירות.",
		challenge_unarmed_safety: "אין כרגע אימות שממתין לקוד. אל תשלחי קודי אימות בצ׳אט.",
	},
	appointmentNotice: "אזכיר לך יום לפני התור. לביטול כתבי לי.",
	reminderProposal: {
		create:
			"האם תרצי לאשר את התזכורת החד-פעמית?\nתזכורת: בדיקה\nמועד: 2026-07-20T10:00 (שעון ישראל)\n1. אישור\n2. ביטול",
		update:
			"האם תרצי לאשר את עדכון התזכורת?\nתזכורת: בדיקה\nמועד: 2026-07-20T10:00 (שעון ישראל)\n1. אישור\n2. ביטול",
		cancel: "האם תרצי לאשר את ביטול התזכורת?\nתזכורת: בדיקה\n1. אישור\n2. ביטול",
	},
	reminderConfirmation: {
		confirmed: "התזכורת נקבעה.",
		rejected: "התזכורת בוטלה.",
		unchanged: "לא שיניתי כלום; התזכורת נשארת כמו שהיא.",
		proposal_expired: "הבקשה פגה ולא בוצעה. אפשר לנסות שוב.",
		failed: "לא ביצעתי את הבקשה. אפשר לנסות שוב.",
	},
	reminderDelivery: "תזכורת: בדיקה",
	mediaAction: {
		choice_required: "כדי להמשיך בפעולה שמבוססת על הקובץ, השיבי 1 לאישור או 2 לביטול.",
		confirmed: "האישור התקבל. הפעולה ממשיכה עכשיו.",
		rejected: "הפעולה בוטלה. המידע מהקובץ לא ישמש לביצוע הפעולה.",
		expired: "האישור פג. אם עדיין תרצי לבצע את הפעולה, בקשי אותה שוב.",
		failed: "לא הצלחנו לעבד את האישור. בקשי את הפעולה שוב.",
	},
	emergency:
		"אם זה מצב חירום רפואי, חייגי עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
	recurringDecline:
		"כרגע אפשר לקבוע רק תזכורת חד-פעמית. אני יכול לקבוע תזכורת חד-פעמית — למשל למחר ב-9:00.",
} as const;

const FATHER_COPY = {
	providerChallenge: {
		challenge_sent: "שלחנו עכשיו קוד אימות ב-SMS. שלח כאן רק את הספרות מההודעה.",
		challenge_type_digits: "תכתוב את המספרים בהודעה",
		challenge_invalid_format: "שלח רק את קוד האימות בן 4 עד 8 הספרות.",
		challenge_success_repeat_request: "האימות הושלם. עכשיו שלח שוב את הבקשה המקורית.",
		challenge_expired_restart: "קוד האימות פג. התחל שוב את החיבור לשירות.",
		challenge_failed_restart: "לא הצלחנו לאמת את הקוד. התחל שוב את החיבור לשירות.",
		challenge_unarmed_safety: "אין כרגע אימות שממתין לקוד. אל תשלח קודי אימות בצ׳אט.",
	},
	appointmentNotice: "אזכיר לך יום לפני התור. לביטול כתוב לי.",
	reminderProposal: {
		create:
			"האם תרצה לאשר את התזכורת החד-פעמית?\nתזכורת: בדיקה\nמועד: 2026-07-20T10:00 (שעון ישראל)\n1. אישור\n2. ביטול",
		update:
			"האם תרצה לאשר את עדכון התזכורת?\nתזכורת: בדיקה\nמועד: 2026-07-20T10:00 (שעון ישראל)\n1. אישור\n2. ביטול",
		cancel: "האם תרצה לאשר את ביטול התזכורת?\nתזכורת: בדיקה\n1. אישור\n2. ביטול",
	},
	reminderConfirmation: {
		confirmed: "התזכורת נקבעה.",
		rejected: "התזכורת בוטלה.",
		unchanged: "לא שיניתי כלום; התזכורת נשארת כמו שהיא.",
		proposal_expired: "הבקשה פגה ולא בוצעה. אפשר לנסות שוב.",
		failed: "לא ביצעתי את הבקשה. אפשר לנסות שוב.",
	},
	reminderDelivery: "תזכורת: בדיקה",
	mediaAction: {
		choice_required: "כדי להמשיך בפעולה שמבוססת על הקובץ, השב 1 לאישור או 2 לביטול.",
		confirmed: "האישור התקבל. הפעולה ממשיכה עכשיו.",
		rejected: "הפעולה בוטלה. המידע מהקובץ לא ישמש לביצוע הפעולה.",
		expired: "האישור פג. אם עדיין תרצה לבצע את הפעולה, בקש אותה שוב.",
		failed: "לא הצלחנו לעבד את האישור. בקש את הפעולה שוב.",
	},
	emergency:
		"אם זה מצב חירום רפואי, חייג עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
	recurringDecline:
		"כרגע אפשר לקבוע רק תזכורת חד-פעמית. אני יכול לקבוע תזכורת חד-פעמית — למשל למחר ב-9:00.",
} as const;

describe("household fixed Hebrew copy golden", () => {
	it("enumerates every keyed fixed-copy template", () => {
		expect(Object.keys(WHATSAPP_PROVIDER_CHALLENGE_COPY.f)).toEqual(
			Object.keys(MOTHER_COPY.providerChallenge),
		);
		expect(Object.keys(WHATSAPP_PROVIDER_CHALLENGE_COPY.m)).toEqual(
			Object.keys(FATHER_COPY.providerChallenge),
		);
		expect(Object.keys(MEDIA_ACTION_CONFIRMATION_COPY.f)).toEqual(
			Object.keys(MOTHER_COPY.mediaAction),
		);
		expect(Object.keys(MEDIA_ACTION_CONFIRMATION_COPY.m)).toEqual(
			Object.keys(FATHER_COPY.mediaAction),
		);
		expect(Object.keys(HOUSEHOLD_EMERGENCY_COPY)).toEqual(["f", "m"]);
	});

	it("pins every mother-facing byte across all fixed-copy surfaces", () => {
		expect(renderFixedCopy("f")).toEqual(MOTHER_COPY);
	});

	it("pins every father-facing byte across all fixed-copy surfaces", () => {
		expect(renderFixedCopy("m")).toEqual(FATHER_COPY);
	});

	it("keeps feminine imperative forms out of every father-facing output", () => {
		const fatherText = fixedCopyStrings(renderFixedCopy("m")).join("\n");
		for (const feminineForm of [
			"שלחי",
			"תכתבי",
			"לחצי",
			"בחרי",
			"כתבי",
			"הקלידי",
			"אישרי",
			"השיבי",
			"בקשי",
			"תרצי",
			"חייגי",
			"התחילי",
			"תשלחי",
		]) {
			expect(fatherText).not.toContain(feminineForm);
		}
	});

	it("keeps Gabriel's self-reference masculine for both parents", () => {
		for (const copy of [renderFixedCopy("f"), renderFixedCopy("m")]) {
			expect(copy.recurringDecline).toContain("אני יכול");
			expect(copy.recurringDecline).not.toContain("אני יכולה");
		}
	});
});

function renderFixedCopy(addresseeGender: "f" | "m") {
	return {
		providerChallenge: {
			challenge_sent: whatsAppProviderChallengeCopy("challenge_sent", addresseeGender),
			challenge_type_digits: whatsAppProviderChallengeCopy(
				"challenge_type_digits",
				addresseeGender,
			),
			challenge_invalid_format: whatsAppProviderChallengeCopy(
				"challenge_invalid_format",
				addresseeGender,
			),
			challenge_success_repeat_request: whatsAppProviderChallengeCopy(
				"challenge_success_repeat_request",
				addresseeGender,
			),
			challenge_expired_restart: whatsAppProviderChallengeCopy(
				"challenge_expired_restart",
				addresseeGender,
			),
			challenge_failed_restart: whatsAppProviderChallengeCopy(
				"challenge_failed_restart",
				addresseeGender,
			),
			challenge_unarmed_safety: whatsAppProviderChallengeCopy(
				"challenge_unarmed_safety",
				addresseeGender,
			),
		},
		appointmentNotice: householdAppointmentDerivedReminderNotice(addresseeGender),
		reminderProposal: {
			create: householdReminderProposalPrompt("create", reminder, addresseeGender),
			update: householdReminderProposalPrompt("update", reminder, addresseeGender),
			cancel: householdReminderProposalPrompt("cancel", reminder, addresseeGender),
		},
		reminderConfirmation: {
			confirmed: householdReminderConfirmationCopy("confirmed", addresseeGender),
			rejected: householdReminderConfirmationCopy("rejected", addresseeGender),
			unchanged: householdReminderConfirmationCopy("unchanged", addresseeGender),
			proposal_expired: householdReminderConfirmationCopy("proposal_expired", addresseeGender),
			failed: householdReminderConfirmationCopy("failed", addresseeGender),
		},
		reminderDelivery: renderHouseholdReminderBody(reminder),
		mediaAction: {
			choice_required: mediaActionConfirmationCopy("choice_required", addresseeGender),
			confirmed: mediaActionConfirmationCopy("confirmed", addresseeGender),
			rejected: mediaActionConfirmationCopy("rejected", addresseeGender),
			expired: mediaActionConfirmationCopy("expired", addresseeGender),
			failed: mediaActionConfirmationCopy("failed", addresseeGender),
		},
		emergency: householdEmergencyCopy(addresseeGender),
		recurringDecline: HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE,
	};
}

function fixedCopyStrings(value: unknown): string[] {
	if (typeof value === "string") return [value];
	if (!value || typeof value !== "object") return [];
	return Object.values(value).flatMap(fixedCopyStrings);
}
