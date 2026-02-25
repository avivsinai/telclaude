/**
 * Drive handler — dispatches FetchRequest actions to the Google Drive API.
 */

import { google } from "googleapis";
import type { FetchRequest, FetchResponse } from "../types.js";

export async function handleDrive(
	request: FetchRequest,
	accessToken: string,
): Promise<FetchResponse> {
	const auth = new google.auth.OAuth2();
	auth.setCredentials({ access_token: accessToken });
	const drive = google.drive({ version: "v3", auth });

	switch (request.action) {
		case "search":
			return handleSearch(drive, request.params);
		case "list_files":
			return handleListFiles(drive, request.params);
		case "read_metadata":
			return handleReadMetadata(drive, request.params);
		case "download":
			return handleDownload(drive, request.params);
		case "list_shared":
			return handleListShared(drive, request.params);
		default:
			return { status: "error", error: `Unknown Drive action: ${request.action}`, attachments: [] };
	}
}

type Drive = ReturnType<typeof google.drive>;

async function handleSearch(drive: Drive, params: Record<string, unknown>): Promise<FetchResponse> {
	try {
		const res = await drive.files.list({
			q: params.q as string,
			pageSize: (params.maxResults as number) ?? 10,
			pageToken: params.pageToken as string | undefined,
			fields: "nextPageToken, files(id, name, mimeType, size, modifiedTime, owners, webViewLink)",
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleListFiles(
	drive: Drive,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const folderId = (params.folderId as string) ?? "root";
		const res = await drive.files.list({
			q: `'${folderId}' in parents and trashed = false`,
			pageSize: (params.maxResults as number) ?? 10,
			pageToken: params.pageToken as string | undefined,
			fields: "nextPageToken, files(id, name, mimeType, size, modifiedTime)",
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleReadMetadata(
	drive: Drive,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await drive.files.get({
			fileId: params.fileId as string,
			fields: "id, name, mimeType, size, modifiedTime, owners, webViewLink, description",
		});
		return { status: "ok", data: res.data, attachments: [] };
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleDownload(
	drive: Drive,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await drive.files.get(
			{ fileId: params.fileId as string, alt: "media" },
			{ responseType: "arraybuffer" },
		);
		const buf = Buffer.from(res.data as ArrayBuffer);
		return {
			status: "ok",
			data: { size: buf.length },
			attachments: [{ inline: buf.toString("base64"), size: buf.length }],
		};
	} catch (err) {
		return { status: "error", error: formatError(err), attachments: [] };
	}
}

async function handleListShared(
	drive: Drive,
	params: Record<string, unknown>,
): Promise<FetchResponse> {
	try {
		const res = await drive.files.list({
			q: "sharedWithMe = true and trashed = false",
			pageSize: (params.maxResults as number) ?? 10,
			pageToken: params.pageToken as string | undefined,
			fields: "nextPageToken, files(id, name, mimeType, size, modifiedTime, owners)",
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
