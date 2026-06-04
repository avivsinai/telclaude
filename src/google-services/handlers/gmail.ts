/**
 * Gmail handler — dispatches FetchRequest actions to the Gmail API.
 */

import { google } from "googleapis";
import { createGoogleAuth, formatError } from "../handler-utils.js";
import type { FetchRequest, FetchResponse } from "../types.js";

export async function handleGmail(
	request: FetchRequest,
	accessToken: string,
): Promise<FetchResponse> {
	const auth = createGoogleAuth(accessToken);
	const gmail = google.gmail({ version: "v1", auth });

	switch (request.action) {
		case "search":
			return handleSearch(gmail, request.params);
		case "read_message":
			return handleReadMessage(gmail, request.params);
		case "read_thread":
			return handleReadThread(gmail, request.params);
		case "list_labels":
			return handleListLabels(gmail);
		case "download_attachment":
			return handleDownloadAttachment(gmail, request.params);
		case "create_draft":
			return handleCreateDraft(gmail, request.params);
		case "send":
			return handleSend(gmail, request.params);
		default:
			return { status: "error", error: `Unknown Gmail action: ${request.action}`, attachments: [] };
	}
}

type Gmail = ReturnType<typeof google.gmail>;

/**
 * Maximum attachment download size. The sidecar runs at mem_limit 256M and base64
 * encoding adds ~1.33x, so an uncapped large attachment would OOM-crash the
 * process — a single-request availability attack. 25 MiB matches Gmail's own send
 * limit and stays well within the memory budget even with the base64 copy.
 */
const MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024;

/**
 * Maximum size of an outbound `send` message (decoded). 25 MiB matches Gmail's
 * own send limit and stays within the sidecar's 256M memory budget. Enforced on
 * the base64url length BEFORE the API call so a single request cannot OOM-crash
 * the process.
 */
const MAX_SEND_BYTES = 25 * 1024 * 1024;

async function handleSearch(gmail: Gmail, params: Record<string, unknown>): Promise<FetchResponse> {
	try {
		const res = await gmail.users.messages.list({
			userId: "me",
			q: params.q as string,
			maxResults: (params.maxResults as number) ?? 10,
			pageToken: params.pageToken as string | undefined,
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleReadMessage(
	gmail: Gmail,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await gmail.users.messages.get({
			userId: "me",
			id: params.messageId as string,
			format: (params.format as "full" | "metadata" | "minimal") ?? "full",
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleReadThread(
	gmail: Gmail,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await gmail.users.threads.get({
			userId: "me",
			id: params.threadId as string,
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleListLabels(gmail: Gmail): Promise<FetchResponse> {
	try {
		const res = await gmail.users.labels.list({ userId: "me" });
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleDownloadAttachment(
	gmail: Gmail,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await gmail.users.messages.attachments.get({
			userId: "me",
			messageId: params.messageId as string,
			id: params.attachmentId as string,
		});
		// `size` is the decoded byte count. Reject oversized attachments before
		// decoding so a single request cannot exhaust the sidecar's 256M budget.
		const declaredSize = typeof res.data.size === "number" ? res.data.size : null;
		if (declaredSize !== null && declaredSize > MAX_DOWNLOAD_BYTES) {
			return {
				status: "error",
				error: `Attachment exceeds ${MAX_DOWNLOAD_BYTES}-byte download limit (size ${declaredSize})`,
				attachments: [],
			};
		}
		const rawData = res.data.data ?? "";
		// base64url decodes to 3 bytes per 4 chars; guard against a missing or
		// understated `size` before allocating the decoded + normalized copies.
		const decodedBytes = Math.floor((rawData.length * 3) / 4);
		if (decodedBytes > MAX_DOWNLOAD_BYTES) {
			return {
				status: "error",
				error: `Attachment exceeds ${MAX_DOWNLOAD_BYTES}-byte download limit`,
				attachments: [],
			};
		}
		// Gmail API returns base64url; normalize to standard base64 for provider proxy
		const b64 = rawData ? rawData.replace(/-/g, "+").replace(/_/g, "/") : "";
		return {
			status: "ok",
			data: { size: res.data.size },
			attachments: [{ inline: b64, size: res.data.size }],
		};
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleCreateDraft(
	gmail: Gmail,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const to = sanitizeRfc822HeaderValue(params.to);
		const subject = sanitizeRfc822HeaderValue(params.subject);
		const cc = params.cc ? sanitizeRfc822HeaderValue(params.cc) : "";
		const body = typeof params.body === "string" ? params.body : "";
		if (!to || !subject) {
			return { status: "error", error: "Invalid draft headers", attachments: [] };
		}
		const headers = [
			`To: ${to}`,
			`Subject: ${subject}`,
			cc ? `Cc: ${cc}` : null,
			"Content-Type: text/plain; charset=utf-8",
			"",
			body,
		]
			.filter(Boolean)
			.join("\r\n");
		const raw = Buffer.from(headers).toString("base64url");
		const res = await gmail.users.drafts.create({
			userId: "me",
			requestBody: { message: { raw } },
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

/**
 * Send a pre-composed message. The relay builds the CRLF-safe RFC822 message
 * (header injection rejected, single membership-validated recipient) and
 * base64url-encodes it; the approval token's paramsHash binds this exact `raw`,
 * so the sidecar sends bytes the relay authorized and does NOT re-parse headers
 * or re-derive recipients. We only validate the encoding and bound the size.
 */
async function handleSend(gmail: Gmail, params: Record<string, unknown>): Promise<FetchResponse> {
	const raw = typeof params.raw === "string" ? params.raw : "";
	// A base64url string of length % 4 === 1 cannot encode any byte sequence —
	// reject it alongside non-alphabet input before touching the Gmail API.
	if (!raw || !isBase64Url(raw) || raw.length % 4 === 1) {
		return {
			status: "error",
			error: "send requires a non-empty base64url `raw` message",
			attachments: [],
		};
	}
	// base64url decodes to ~3 bytes per 4 chars; reject oversized messages before
	// the API call so a single request cannot exhaust the sidecar's 256M budget.
	const decodedBytes = Math.floor((raw.length * 3) / 4);
	if (decodedBytes > MAX_SEND_BYTES) {
		return {
			status: "error",
			error: `Message exceeds ${MAX_SEND_BYTES}-byte send limit`,
			attachments: [],
		};
	}
	try {
		const res = await gmail.users.messages.send({
			userId: "me",
			requestBody: { raw },
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

/** True if every character is in the unpadded base64url alphabet (A-Za-z0-9-_). */
function isBase64Url(value: string): boolean {
	for (let i = 0; i < value.length; i += 1) {
		const c = value.charCodeAt(i);
		const isUpper = c >= 0x41 && c <= 0x5a;
		const isLower = c >= 0x61 && c <= 0x7a;
		const isDigit = c >= 0x30 && c <= 0x39;
		const isDash = c === 0x2d;
		const isUnderscore = c === 0x5f;
		if (!(isUpper || isLower || isDigit || isDash || isUnderscore)) return false;
	}
	return true;
}

function sanitizeRfc822HeaderValue(value: unknown): string {
	if (typeof value !== "string") return "";
	return value.replace(/[\r\n]+/g, " ").trim();
}
