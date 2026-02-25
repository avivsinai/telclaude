/**
 * Gmail handler — dispatches FetchRequest actions to the Gmail API.
 */

import { google } from "googleapis";
import type { FetchRequest, FetchResponse } from "../types.js";

export async function handleGmail(
	request: FetchRequest,
	accessToken: string,
): Promise<FetchResponse> {
	const auth = new google.auth.OAuth2();
	auth.setCredentials({ access_token: accessToken });
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
		default:
			return { status: "error", error: `Unknown Gmail action: ${request.action}`, attachments: [] };
	}
}

type Gmail = ReturnType<typeof google.gmail>;

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
		return {
			status: "ok",
			data: { size: res.data.size },
			attachments: [{ inline: res.data.data, size: res.data.size }],
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
		const headers = [
			`To: ${params.to as string}`,
			`Subject: ${params.subject as string}`,
			params.cc ? `Cc: ${params.cc as string}` : null,
			"Content-Type: text/plain; charset=utf-8",
			"",
			params.body as string,
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

function formatError(err: unknown): string {
	if (err instanceof Error) return err.message;
	return String(err);
}
