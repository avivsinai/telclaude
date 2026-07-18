import crypto from "node:crypto";
import type { HouseholdReminder } from "./types.js";

export function renderHouseholdReminderBody(reminder: HouseholdReminder): string {
	return `תזכורת: ${reminder.text}`;
}

export function householdReminderWhatsAppMessageId(idempotencyKey: string): string {
	const digest = crypto.createHash("sha256").update(idempotencyKey).digest("hex").slice(0, 32);
	return `TCREMINDER${digest}`;
}
