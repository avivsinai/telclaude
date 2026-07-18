export const MEDIA_ACTION_CONFIRMATION_COPY = Object.freeze({
	f: Object.freeze({
		choice_required: "כדי להמשיך בפעולה שמבוססת על הקובץ, השיבי 1 לאישור או 2 לביטול.",
		confirmed: "האישור התקבל. הפעולה ממשיכה עכשיו.",
		rejected: "הפעולה בוטלה. המידע מהקובץ לא ישמש לביצוע הפעולה.",
		expired: "האישור פג. אם עדיין תרצי לבצע את הפעולה, בקשי אותה שוב.",
		failed: "לא הצלחנו לעבד את האישור. בקשי את הפעולה שוב.",
	}),
	m: Object.freeze({
		choice_required: "כדי להמשיך בפעולה שמבוססת על הקובץ, השב 1 לאישור או 2 לביטול.",
		confirmed: "האישור התקבל. הפעולה ממשיכה עכשיו.",
		rejected: "הפעולה בוטלה. המידע מהקובץ לא ישמש לביצוע הפעולה.",
		expired: "האישור פג. אם עדיין תרצה לבצע את הפעולה, בקש אותה שוב.",
		failed: "לא הצלחנו לעבד את האישור. בקש את הפעולה שוב.",
	}),
});

export type MediaActionConfirmationTemplateId = keyof typeof MEDIA_ACTION_CONFIRMATION_COPY.f;

export function mediaActionConfirmationCopy(
	templateId: MediaActionConfirmationTemplateId,
	addresseeGender: "f" | "m",
): string {
	const variants = MEDIA_ACTION_CONFIRMATION_COPY[addresseeGender];
	if (!variants) throw new Error("media confirmation addressee gender is unavailable");
	return variants[templateId];
}
