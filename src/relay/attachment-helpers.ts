/**
 * Shared attachment helpers used by provider-proxy and capabilities.
 *
 * Extracted from provider-proxy.ts and capabilities.ts which had
 * identical implementations of filename sanitization, attachment
 * filename generation, and documents directory management.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { getMediaOutboxDirSync } from "../media/store.js";

export const MIME_EXTENSION_MAP: Record<string, string> = {
	"application/pdf": ".pdf",
	"application/json": ".json",
	"image/png": ".png",
	"image/jpeg": ".jpg",
	"image/jpg": ".jpg",
	"image/webp": ".webp",
	"text/plain": ".txt",
};

export function sanitizeFilename(input?: string): string {
	if (!input || typeof input !== "string") {
		return "attachment";
	}
	const base = path.basename(input.trim());
	const normalized = base.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "");
	if (!normalized || normalized === "." || normalized === "..") {
		return "attachment";
	}
	return normalized;
}

export function buildAttachmentFilename(filename?: string, mimeType?: string): string {
	const safe = sanitizeFilename(filename);
	const extFromName = path.extname(safe);
	const fallbackExt = mimeType ? (MIME_EXTENSION_MAP[mimeType] ?? "") : "";
	const ext = extFromName || fallbackExt;
	const stem = (extFromName ? safe.slice(0, -extFromName.length) : safe) || "attachment";
	const suffix = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
	const truncatedStem = stem.slice(0, 80);
	return `${truncatedStem}-${suffix}${ext}`;
}

export async function ensureDocumentsDir(): Promise<string> {
	const outboxRoot = getMediaOutboxDirSync();
	const documentsDir = path.join(outboxRoot, "documents");
	await fs.promises.mkdir(documentsDir, { recursive: true, mode: 0o700 });
	return documentsDir;
}
