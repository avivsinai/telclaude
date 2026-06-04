import { describe, expect, it } from "vitest";
import {
	type ComposeEmailMimeInput,
	composeEmailMime,
	EmailHeaderInjectionError,
} from "../../../src/relay/email/mime-compose.js";

const base: ComposeEmailMimeInput = {
	from: "agent@relay.test",
	to: ["alice@example.test"],
	subject: "Hi",
	textBody: "hello",
	messageId: "<m1@relay.test>",
	date: "Wed, 04 Jun 2026 00:00:00 +0000",
};

describe("composeEmailMime", () => {
	it("builds a CRLF text/plain message with base64 body and the expected headers", () => {
		const mime = composeEmailMime(base);
		expect(mime).toContain("From: agent@relay.test\r\n");
		expect(mime).toContain("To: alice@example.test\r\n");
		expect(mime).toContain("Subject: Hi\r\n");
		expect(mime).toContain("Message-ID: <m1@relay.test>\r\n");
		expect(mime).toContain('Content-Type: text/plain; charset="utf-8"\r\n');
		expect(mime).toContain("Content-Transfer-Encoding: base64\r\n");
		// base64("hello") === "aGVsbG8="
		expect(mime).toContain("aGVsbG8=");
		// CRLF only — no bare LF.
		expect(mime.split("\n").every((line) => line === "" || line.endsWith("\r"))).toBe(true);
	});

	it("RFC 2047 encodes a non-ASCII subject", () => {
		const mime = composeEmailMime({ ...base, subject: "Schöne Grüße 🦉" });
		expect(mime).toContain("Subject: =?UTF-8?B?");
		expect(mime).not.toContain("Schöne");
	});

	it("includes In-Reply-To and References when provided", () => {
		const mime = composeEmailMime({
			...base,
			inReplyTo: "<prev@example.test>",
			references: ["<root@example.test>", "<prev@example.test>"],
		});
		expect(mime).toContain("In-Reply-To: <prev@example.test>\r\n");
		expect(mime).toContain("References: <root@example.test> <prev@example.test>\r\n");
	});

	it("builds multipart/mixed with a base64 attachment part", () => {
		const mime = composeEmailMime({
			...base,
			attachments: [
				{ filename: "note.txt", mediaType: "text/plain", bytes: new TextEncoder().encode("abc") },
			],
		});
		expect(mime).toContain("Content-Type: multipart/mixed; boundary=");
		expect(mime).toContain('Content-Disposition: attachment; filename="note.txt"');
		// base64("abc") === "YWJj"
		expect(mime).toContain("YWJj");
		expect(mime).toMatch(/--tc-mime-[0-9a-f]{32}--\r\n$/);
	});

	it("throws empty-recipient", () => {
		expect(() => composeEmailMime({ ...base, to: [] })).toThrow(/at least one recipient/);
	});

	describe("header injection is rejected (not sanitized)", () => {
		const crlf = "\r\nBcc: evil@attacker.test";
		const cases: Array<[string, ComposeEmailMimeInput]> = [
			["To", { ...base, to: [`alice@example.test${crlf}`] }],
			["From", { ...base, from: `agent@relay.test${crlf}` }],
			["Subject", { ...base, subject: `Hi${crlf}` }],
			["Message-ID", { ...base, messageId: `<m1@relay.test>${crlf}` }],
			["In-Reply-To", { ...base, inReplyTo: `<p@x.test>${crlf}` }],
			["References", { ...base, references: [`<r@x.test>${crlf}`] }],
			[
				"attachment filename",
				{
					...base,
					attachments: [
						{ filename: `n.txt${crlf}`, mediaType: "text/plain", bytes: new Uint8Array([1]) },
					],
				},
			],
			[
				"attachment Content-Type",
				{
					...base,
					attachments: [
						{ filename: "n.txt", mediaType: `text/plain${crlf}`, bytes: new Uint8Array([1]) },
					],
				},
			],
		];
		for (const [field, input] of cases) {
			it(`rejects CRLF in ${field}`, () => {
				expect(() => composeEmailMime(input)).toThrow(EmailHeaderInjectionError);
			});
		}

		it("rejects a bare control character (e.g. NUL) in a header", () => {
			expect(() => composeEmailMime({ ...base, subject: String.fromCharCode(97, 0, 98) })).toThrow(
				EmailHeaderInjectionError,
			);
		});
	});
});
