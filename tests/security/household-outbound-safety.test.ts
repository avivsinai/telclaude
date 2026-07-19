import { describe, expect, it } from "vitest";
import {
	classifyHouseholdOutboundSafetyV1,
	HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION,
} from "../../src/security/household-outbound-safety.js";

describe("classifyHouseholdOutboundSafetyV1", () => {
	it("pins the classifier version", () => {
		expect(HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION).toBe("household_outbound_safety_v1");
	});

	it.each([
		["financial Hebrew", "בבקשה לשלם את התשלום בכרטיס אשראי", "financial"],
		["financial English", "Please wire money to this bank account", "financial"],
		["definite Hebrew payment", "התשלום מחכה בכרטיס האשראי", "financial"],
		["credential Hebrew", "שלחי לי את קוד האימות ואת הסיסמה", "credential"],
		["credential English", "Reply with your OTP verification code", "credential"],
		["URL", "Open https://example.com/verify", "external_link"],
		["shortener", "See bit.ly/account-check", "external_link"],
		["bare shortener", "Go to t.co/account-check", "external_link"],
		["Hebrew scam action", "לחצי כאן כדי לאשר חשבון", "scam_action"],
		["grammatical Hebrew scam action", "אמתִי את החשבון", "scam_action"],
		["English scam action", "Click here to verify account", "scam_action"],
	] as const)("flags %s", (_label, text, reason) => {
		const result = classifyHouseholdOutboundSafetyV1(text);
		expect(result.safeForAutoGrant).toBe(false);
		expect(result.reasonCodes).toContain(reason);
	});

	it("normalizes NFKC, combining marks, and bidi controls before matching", () => {
		const result = classifyHouseholdOutboundSafetyV1(
			"ｃｌｉｃｋ\u202E he\u0301re to verify account",
		);
		expect(result.safeForAutoGrant).toBe(false);
		expect(result.reasonCodes).toContain("scam_action");
	});

	it.each([
		["oversized text", "x".repeat(8_001)],
		["invalid Unicode", "bad\ud800text"],
	] as const)("fails closed for %s", (_label, text) => {
		const result = classifyHouseholdOutboundSafetyV1(text);
		expect(result.safeForAutoGrant).toBe(false);
		expect(result.reasonCodes).toContain("classifier_fail_closed");
	});

	it.each([
		["moved reminder", "העברתי את התזכורת למחר"],
		["bare English transfer", "Transfer the call to me when you can"],
		["building code", "הקוד לבניין הוא 1234"],
		["benign urgency now", "אני אזכיר לך עכשיו"],
		["benign urgency immediately", "אני אזכיר לך מיד"],
		["English urgency", "Call me now when you are free"],
		["weather", "מחר יהיה נעים, בערך 24 מעלות"],
		["health", "הבדיקה יצאה תקינה, תנוחי היום"],
		["greeting", "בוקר טוב אמא, איך ישנת?"],
	] as const)("keeps benign lookalike auto-grant-safe: %s", (_label, text) => {
		expect(classifyHouseholdOutboundSafetyV1(text)).toEqual({
			classifierVersion: HOUSEHOLD_OUTBOUND_SAFETY_CLASSIFIER_VERSION,
			safeForAutoGrant: true,
			reasonCodes: [],
		});
	});

	it("escalates even a legitimate link because all links require human review", () => {
		expect(classifyHouseholdOutboundSafetyV1("הנה האתר הרשמי: https://www.gov.il")).toMatchObject({
			safeForAutoGrant: false,
			reasonCodes: ["external_link"],
		});
	});
});
