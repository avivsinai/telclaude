import { describe, expect, it } from "vitest";
import {
	HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE,
	resolveJerusalemOneShot,
} from "../../src/household-reminders/time.js";

describe("household reminder Jerusalem one-shot resolution", () => {
	it("freezes a valid wall time to its UTC instant and offset", () => {
		const resolved = resolveJerusalemOneShot("2026-03-27T03:30", {
			nowMs: Date.parse("2026-03-26T00:00:00.000Z"),
		});

		expect(resolved).toEqual({
			timeZone: "Asia/Jerusalem",
			localDateTime: "2026-03-27T03:30",
			resolvedAtMs: Date.parse("2026-03-27T00:30:00.000Z"),
			resolvedAt: "2026-03-27T00:30:00.000Z",
			offsetMinutes: 180,
		});
	});

	it("rejects the spring gap instead of silently shifting it", () => {
		expect(() =>
			resolveJerusalemOneShot("2026-03-27T02:30", {
				nowMs: Date.parse("2026-03-26T00:00:00.000Z"),
			}),
		).toThrow(/does not exist/i);
	});

	it("rejects the autumn overlap instead of choosing an offset", () => {
		expect(() =>
			resolveJerusalemOneShot("2026-10-25T01:30", {
				nowMs: Date.parse("2026-10-24T00:00:00.000Z"),
			}),
		).toThrow(/ambiguous/i);
	});

	it("rejects past, invalid, sub-minute, and over-horizon values", () => {
		const nowMs = Date.parse("2026-01-01T00:00:00.000Z");
		expect(() => resolveJerusalemOneShot("2025-12-31T23:00", { nowMs })).toThrow(/future/i);
		expect(() => resolveJerusalemOneShot("2026-02-30T09:00", { nowMs })).toThrow(/invalid/i);
		expect(() => resolveJerusalemOneShot("2026-01-02T09:00:30", { nowMs })).toThrow(/minute/i);
		expect(() => resolveJerusalemOneShot("2027-01-02T09:00", { nowMs })).toThrow(/365 days/i);
	});

	it("offers a one-shot alternative when recurring schedules are declined", () => {
		expect(HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE).toContain("חד-פעמית");
		expect(HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE).toContain("למחר ב-9:00");
	});
});
