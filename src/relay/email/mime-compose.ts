import { randomBytes } from "node:crypto";

/**
 * CRLF-safe RFC 5322 / MIME message composer for the outbound email connector.
 *
 * Security boundary: every header value is REJECTED (not sanitized) if it
 * contains CR/LF or other control characters — this is the email header /
 * SMTP-command injection guard. Header values come from the relay-built
 * recipient + a relay-generated Message-ID; the body goes only in the body
 * part, base64-encoded, so it can never break out into headers.
 */

const CRLF = "\r\n";
// RFC 5322 line-length limit for folded content lines.
const MAX_LINE = 76;

/** True if the value contains a C0 control character or DEL (the injection vector). */
function hasControlChar(value: string): boolean {
	for (let i = 0; i < value.length; i += 1) {
		const code = value.charCodeAt(i);
		if (code < 0x20 || code === 0x7f) return true;
	}
	return false;
}

/** True if the value contains any byte outside printable ASCII (0x20-0x7e). */
function hasNonAscii(value: string): boolean {
	for (let i = 0; i < value.length; i += 1) {
		const code = value.charCodeAt(i);
		if (code < 0x20 || code > 0x7e) return true;
	}
	return false;
}

export class EmailHeaderInjectionError extends Error {
	constructor(field: string) {
		super(`email header injection denied: ${field} contains a control character`);
		this.name = "EmailHeaderInjectionError";
	}
}

export interface EmailAttachmentPart {
	readonly filename: string;
	readonly mediaType: string;
	readonly bytes: Uint8Array;
}

export interface ComposeEmailMimeInput {
	readonly from: string;
	readonly to: readonly string[];
	readonly subject: string;
	readonly textBody: string;
	/** Relay-generated Message-ID (e.g. <id@host>). */
	readonly messageId: string;
	readonly inReplyTo?: string;
	readonly references?: readonly string[];
	readonly attachments?: readonly EmailAttachmentPart[];
	/** RFC 5322 Date header value; injectable for deterministic tests. */
	readonly date?: string;
}

function assertHeaderSafe(value: string, field: string): string {
	if (hasControlChar(value)) {
		throw new EmailHeaderInjectionError(field);
	}
	return value;
}

/** RFC 2047 encode a header value containing non-ASCII as a single base64 word. */
function encodeHeaderWord(value: string): string {
	if (!hasNonAscii(value)) return value;
	const b64 = Buffer.from(value, "utf-8").toString("base64");
	return `=?UTF-8?B?${b64}?=`;
}

/** Split a base64 string into CRLF-folded lines of at most MAX_LINE chars. */
function foldBase64(b64: string): string {
	const lines: string[] = [];
	for (let i = 0; i < b64.length; i += MAX_LINE) {
		lines.push(b64.slice(i, i + MAX_LINE));
	}
	return lines.join(CRLF);
}

function header(name: string, value: string): string {
	return `${name}: ${value}`;
}

/**
 * Build a complete raw RFC822 message (CRLF line endings). Throws
 * {@link EmailHeaderInjectionError} if any header-bound value carries CR/LF or
 * control characters. The caller base64url-encodes the result for the Gmail API
 * or writes it to the SMTP DATA stream.
 */
export function composeEmailMime(input: ComposeEmailMimeInput): string {
	if (input.to.length === 0) {
		throw new Error("email compose denied: at least one recipient is required");
	}
	const from = assertHeaderSafe(input.from, "From");
	const to = input.to.map((addr) => assertHeaderSafe(addr, "To"));
	const messageId = assertHeaderSafe(input.messageId, "Message-ID");
	// Subject: validate the raw value for control chars, then RFC 2047 encode.
	const subject = encodeHeaderWord(assertHeaderSafe(input.subject, "Subject"));
	const date = assertHeaderSafe(input.date ?? new Date().toUTCString(), "Date");

	const headers: string[] = [
		header("From", from),
		header("To", to.join(", ")),
		header("Subject", subject),
		header("Message-ID", messageId),
		header("Date", date),
		header("MIME-Version", "1.0"),
	];
	if (input.inReplyTo) {
		headers.push(header("In-Reply-To", assertHeaderSafe(input.inReplyTo, "In-Reply-To")));
	}
	if (input.references && input.references.length > 0) {
		const refs = input.references.map((r) => assertHeaderSafe(r, "References")).join(" ");
		headers.push(header("References", refs));
	}

	const bodyB64 = foldBase64(Buffer.from(input.textBody, "utf-8").toString("base64"));
	const attachments = input.attachments ?? [];

	if (attachments.length === 0) {
		headers.push(header("Content-Type", 'text/plain; charset="utf-8"'));
		headers.push(header("Content-Transfer-Encoding", "base64"));
		return `${headers.join(CRLF)}${CRLF}${CRLF}${bodyB64}${CRLF}`;
	}

	const boundary = `tc-mime-${randomBytes(16).toString("hex")}`;
	headers.push(header("Content-Type", `multipart/mixed; boundary="${boundary}"`));

	const parts: string[] = [];
	parts.push(
		[
			`--${boundary}`,
			'Content-Type: text/plain; charset="utf-8"',
			"Content-Transfer-Encoding: base64",
			"",
			bodyB64,
		].join(CRLF),
	);
	for (const attachment of attachments) {
		const filename = assertHeaderSafe(attachment.filename, "attachment filename");
		const mediaType = assertHeaderSafe(attachment.mediaType, "attachment Content-Type");
		const encodedName = encodeHeaderWord(filename);
		const attB64 = foldBase64(Buffer.from(attachment.bytes).toString("base64"));
		parts.push(
			[
				`--${boundary}`,
				`Content-Type: ${mediaType}`,
				"Content-Transfer-Encoding: base64",
				`Content-Disposition: attachment; filename="${encodedName}"`,
				"",
				attB64,
			].join(CRLF),
		);
	}
	const closing = `--${boundary}--`;
	return `${headers.join(CRLF)}${CRLF}${CRLF}${parts.join(`${CRLF}${CRLF}`)}${CRLF}${closing}${CRLF}`;
}
