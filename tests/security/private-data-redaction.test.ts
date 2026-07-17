import { describe, expect, it } from "vitest";
import { filterOutput, redactSecrets } from "../../src/security/output-filter.js";
import { StreamingRedactor } from "../../src/security/streaming-redactor.js";

describe("provider private-data redaction", () => {
	it.each([
		["הקוד הוא 123456", "[REDACTED:otp_code]"],
		["קוד אימות: 1234", "[REDACTED:otp_code]"],
		["תשתמשי בקוד 123456", "תשתמשי [REDACTED:otp_code]"],
		["שהקוד הוא 567890", "[REDACTED:otp_code]"],
		["לקוד: 8765", "[REDACTED:otp_code]"],
		["OTP = 87654321", "[REDACTED:otp_code]"],
		["verification code: 654321", "verification [REDACTED:otp_code]"],
	])("redacts context-anchored OTP input %s", (input, expected) => {
		const otp = input.match(/[0-9]{4,8}/)?.[0];
		const result = filterOutput(input);

		expect(redactSecrets(input)).toBe(expected);
		expect(result.matches.map((match) => match.pattern)).toContain("otp_code");
		expect(otp).toBeDefined();
		expect(JSON.stringify(result)).not.toContain(otp);
		expect(result.matches.find((match) => match.pattern === "otp_code")?.redactedMatch).not.toMatch(
			/[0-9]/,
		);
	});

	it.each([
		"הפגישה בשנת 2026 בשעה 1230",
		"קודם 123456 דיברנו על זה",
		"decode 123456 bytes",
		"מספר ההזמנה הוא 123456",
	])("does not classify unanchored short numbers as OTP input: %s", (input) => {
		expect(redactSecrets(input)).toBe(input);
		expect(filterOutput(input).matches.map((match) => match.pattern)).not.toContain("otp_code");
	});

	it.each([
		"123456782",
		"039284286",
	])("redacts a checksum-valid nine-digit Israeli ID: %s", (id) => {
		const input = `תעודת זהות ${id}`;
		const result = filterOutput(input);

		expect(redactSecrets(input)).toBe("תעודת זהות [REDACTED:israeli_id]");
		expect(result.matches.map((match) => match.pattern)).toContain("israeli_id");
		expect(JSON.stringify(result)).not.toContain(id);
		expect(
			result.matches.find((match) => match.pattern === "israeli_id")?.redactedMatch,
		).not.toMatch(/[0-9]/);
	});

	it.each([
		"123456783",
		"039284287",
		"000000000",
		"12345678",
		"0123456789",
	])("does not redact a non-ID numeric value: %s", (value) => {
		expect(redactSecrets(value)).toBe(value);
		expect(filterOutput(value).matches.map((match) => match.pattern)).not.toContain("israeli_id");
	});

	it.each([
		{
			name: "OTP",
			chunks: ["הקוד הוא 12", "3456"],
			expected: "[REDACTED:otp_code]",
			pattern: "otp_code",
		},
		{
			name: "Israeli ID",
			chunks: ["תעודת זהות 12345", "6782"],
			expected: "תעודת זהות [REDACTED:israeli_id]",
			pattern: "israeli_id",
		},
	])("redacts a chunk-split $name on the streaming path", ({ chunks, expected, pattern }) => {
		const redactor = new StreamingRedactor(100);

		const output = chunks.map((chunk) => redactor.processChunk(chunk)).join("") + redactor.flush();

		expect(output).toBe(expected);
		expect(redactor.getStats().patternsMatched).toContain(pattern);
	});
});
