import { describe, expect, it } from "vitest";
import {
	householdReminderConfirmationCopy,
	householdReminderProposalPrompt,
} from "../../src/household-reminders/copy.js";
import type { HouseholdReminder } from "../../src/household-reminders/types.js";

describe("household reminder gendered fixed copy", () => {
	it("selects exact male and female confirmation guidance", () => {
		expect(householdReminderConfirmationCopy("choice_required", "f")).toBe(
			"כדי להמשיך, שלחי בדיוק 1 או 2.\n1. אישור\n2. ביטול",
		);
		expect(householdReminderConfirmationCopy("choice_required", "m")).toBe(
			"כדי להמשיך, שלח בדיוק 1 או 2.\n1. אישור\n2. ביטול",
		);
	});

	it("selects exact male and female proposal prompts", () => {
		expect(householdReminderProposalPrompt("create", reminder, "f")).toContain(
			"האם תרצי לאשר את התזכורת החד-פעמית?",
		);
		expect(householdReminderProposalPrompt("create", reminder, "m")).toContain(
			"האם תרצה לאשר את התזכורת החד-פעמית?",
		);
	});

	it.each([
		["confirmed", "התזכורת נקבעה."],
		["rejected", "התזכורת בוטלה."],
		["unchanged", "לא שיניתי כלום; התזכורת נשארת כמו שהיא."],
		["proposal_expired", "הבקשה פגה ולא בוצעה. אפשר לנסות שוב."],
		["failed", "לא ביצעתי את הבקשה. אפשר לנסות שוב."],
	] as const)("pins gender-neutral %s copy in both tables", (templateId, expected) => {
		expect(householdReminderConfirmationCopy(templateId, "f")).toBe(expected);
		expect(householdReminderConfirmationCopy(templateId, "m")).toBe(expected);
	});

	it.each([
		["create", "האם תרצי לאשר את התזכורת החד-פעמית?", "האם תרצה לאשר את התזכורת החד-פעמית?"],
		["update", "האם תרצי לאשר את עדכון התזכורת?", "האם תרצה לאשר את עדכון התזכורת?"],
		["cancel", "האם תרצי לאשר את ביטול התזכורת?", "האם תרצה לאשר את ביטול התזכורת?"],
	] as const)("pins %s proposal prompt for both variants", (action, female, male) => {
		expect(householdReminderProposalPrompt(action, reminder, "f")).toContain(female);
		expect(householdReminderProposalPrompt(action, reminder, "m")).toContain(male);
	});
});

const reminder = {
	id: "reminder-gender-copy",
	revision: 1,
	text: "בדיקה",
	schedule: { localDateTime: "2026-07-20T10:00:00" },
} as HouseholdReminder;
