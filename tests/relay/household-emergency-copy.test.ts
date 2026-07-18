import { describe, expect, it } from "vitest";
import {
	HOUSEHOLD_EMERGENCY_COPY,
	householdEmergencyCopy,
} from "../../src/relay/household-emergency-copy.js";

describe("household emergency copy", () => {
	it("renders byte-exact fixed female and male 101 guidance", () => {
		expect(householdEmergencyCopy("f")).toBe(
			"אם זה מצב חירום רפואי, חייגי עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
		);
		expect(householdEmergencyCopy("m")).toBe(
			"אם זה מצב חירום רפואי, חייג עכשיו 101. אני לא שירות חירום ואי אפשר להסתמך עליי במצב חירום.",
		);
	});

	it("keeps the reviewed copy immutable and free of dynamic or internal data", () => {
		expect(Object.isFrozen(HOUSEHOLD_EMERGENCY_COPY)).toBe(true);
		expect(Object.isFrozen(HOUSEHOLD_EMERGENCY_COPY.f)).toBe(true);
		expect(Object.isFrozen(HOUSEHOLD_EMERGENCY_COPY.m)).toBe(true);

		const rendered = JSON.stringify(HOUSEHOLD_EMERGENCY_COPY);
		expect(rendered).not.toMatch(
			/bindingId|displayName|conversation|messageId|eventId|turn_|sha256|ledger|approval/iu,
		);
	});
});
