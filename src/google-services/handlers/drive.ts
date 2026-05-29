/**
 * Drive handler — dispatches FetchRequest actions to the Google Drive API.
 */

import type { Readable } from "node:stream";
import { google } from "googleapis";
import { createGoogleAuth, formatError } from "../handler-utils.js";
import type { FetchRequest, FetchResponse } from "../types.js";

export async function handleDrive(
	request: FetchRequest,
	accessToken: string,
): Promise<FetchResponse> {
	const auth = createGoogleAuth(accessToken);
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
const DRIVE_FILE_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Maximum download size. The sidecar runs at mem_limit 256M and base64 encoding
 * adds ~1.33x, so an uncapped multi-GB download would OOM-crash the process — a
 * single-request availability attack. 25 MiB raw stays well within the memory
 * budget even with the base64 copy and several requests in flight, and covers
 * legitimate Gmail attachments (Gmail's own send limit is 25 MB) plus typical
 * Drive documents.
 */
const MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024;

function normalizeFolderId(value: unknown): string | null {
	if (value === undefined || value === null) return "root";
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	if (!trimmed) return "root";
	if (trimmed === "root") return "root";
	return DRIVE_FILE_ID_PATTERN.test(trimmed) ? trimmed : null;
}

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
		const folderId = normalizeFolderId(params.folderId);
		if (!folderId) {
			return { status: "error", error: "Invalid folderId", attachments: [] };
		}
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
		const fileId = params.fileId as string;

		// Cheap pre-check: reject if the declared size already exceeds the cap.
		// `size` is absent for files that have no blob size (folders, shortcuts,
		// Google Workspace editor files), so this is best-effort — the streaming
		// counter below is the authoritative limit.
		const meta = await drive.files.get({ fileId, fields: "size" });
		const declaredSize = meta.data.size ? Number(meta.data.size) : null;
		if (
			declaredSize !== null &&
			Number.isFinite(declaredSize) &&
			declaredSize > MAX_DOWNLOAD_BYTES
		) {
			return {
				status: "error",
				error: `File exceeds ${MAX_DOWNLOAD_BYTES}-byte download limit (size ${declaredSize})`,
				attachments: [],
			};
		}

		// Stream the media and abort once the running byte count passes the cap,
		// so a missing/understated metadata size cannot lead to unbounded buffering.
		const res = await drive.files.get({ fileId, alt: "media" }, { responseType: "stream" });
		const stream = res.data as Readable;
		const chunks: Buffer[] = [];
		let total = 0;
		try {
			for await (const chunk of stream) {
				const buf = chunk as Buffer;
				total += buf.length;
				if (total > MAX_DOWNLOAD_BYTES) {
					stream.destroy();
					return {
						status: "error",
						error: `File exceeds ${MAX_DOWNLOAD_BYTES}-byte download limit`,
						attachments: [],
					};
				}
				chunks.push(buf);
			}
		} catch (streamErr) {
			stream.destroy();
			throw streamErr;
		}
		const buf = Buffer.concat(chunks, total);
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
