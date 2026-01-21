/**
 * Provider proxy for attachment interception.
 *
 * Routes provider API calls through the relay, intercepts responses,
 * strips inline base64 attachments, stores them, and returns refs.
 *
 * This prevents Claude from accessing raw attachment bytes directly.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { type ExternalProviderConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { getMediaOutboxDirSync } from "../media/store.js";
import { validateProviderBaseUrl } from "../providers/provider-validation.js";
import { createAttachmentRef } from "../storage/attachment-refs.js";

const logger = getChildLogger({ module: "provider-proxy" });

const MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024; // 20MB
const DEFAULT_PROXY_TIMEOUT_MS = 30_000;

export type ProviderProxyRequest = {
	providerId: string;
	path: string;
	method?: string;
	body?: string;
	userId?: string;
};

export type ProviderProxyResponse = {
	status: "ok" | "error";
	data?: unknown;
	error?: string;
};

type ProviderAttachment = {
	id: string;
	filename: string;
	mimeType?: string;
	size?: number;
	inline?: string;
	textContent?: string;
	expiresAt?: string;
};

type RewrittenAttachment = {
	id: string;
	filename: string;
	mimeType?: string;
	size?: number;
	ref: string;
	textContent?: string;
	expiresAt?: string;
};

const MIME_EXTENSION_MAP: Record<string, string> = {
	"application/pdf": ".pdf",
	"image/png": ".png",
	"image/jpeg": ".jpg",
	"image/jpg": ".jpg",
	"image/webp": ".webp",
	"text/plain": ".txt",
	"application/json": ".json",
};

function sanitizeFilename(input?: string): string {
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

function buildAttachmentFilename(filename?: string, mimeType?: string): string {
	const safe = sanitizeFilename(filename);
	const extFromName = path.extname(safe);
	const fallbackExt = mimeType ? (MIME_EXTENSION_MAP[mimeType] ?? "") : "";
	const ext = extFromName || fallbackExt;
	const stem = (extFromName ? safe.slice(0, -extFromName.length) : safe) || "attachment";
	const suffix = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
	const truncatedStem = stem.slice(0, 80);
	return `${truncatedStem}-${suffix}${ext}`;
}

async function ensureDocumentsDir(): Promise<string> {
	const outboxRoot = getMediaOutboxDirSync();
	const documentsDir = path.join(outboxRoot, "documents");
	await fs.promises.mkdir(documentsDir, { recursive: true, mode: 0o700 });
	return documentsDir;
}

/**
 * Estimate base64 decoded size without decoding.
 * This prevents memory spikes from large attachments.
 */
function estimateBase64Size(base64: string): number {
	// Remove padding
	const padding = (base64.match(/=+$/) || [""])[0].length;
	// Each 4 base64 chars = 3 bytes, minus padding
	return Math.floor((base64.length * 3) / 4) - padding;
}

/**
 * Process a single attachment: decode, validate, store, create ref.
 */
async function processAttachment(
	attachment: ProviderAttachment,
	actorUserId: string,
	providerId: string,
): Promise<RewrittenAttachment> {
	const { id, filename, mimeType, size, inline, textContent, expiresAt } = attachment;

	// If no inline content, return as-is (no ref)
	if (!inline || typeof inline !== "string") {
		return { id, filename, mimeType, size, ref: "", textContent, expiresAt };
	}

	// Validate base64 format
	const trimmed = inline.trim();
	if (!/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
		logger.warn({ attachmentId: id, providerId }, "invalid base64 format");
		return { id, filename, mimeType, size, ref: "", textContent, expiresAt };
	}

	// Check size BEFORE decoding (Codex requirement: avoid memory spikes)
	const estimatedSize = estimateBase64Size(trimmed);
	if (estimatedSize > MAX_ATTACHMENT_SIZE) {
		logger.warn({ attachmentId: id, providerId, estimatedSize }, "attachment too large");
		throw new Error(`Attachment too large: ${estimatedSize} bytes`);
	}

	// Decode
	const buffer = Buffer.from(trimmed, "base64");
	if (buffer.length === 0) {
		logger.warn({ attachmentId: id, providerId }, "empty attachment after decode");
		return { id, filename, mimeType, size, ref: "", textContent, expiresAt };
	}

	// Store in outbox
	const safeFilename = buildAttachmentFilename(filename, mimeType);
	const documentsDir = await ensureDocumentsDir();
	const filepath = path.join(documentsDir, safeFilename);

	await fs.promises.writeFile(filepath, buffer, { mode: 0o600 });

	// Create ref
	const refRecord = createAttachmentRef({
		actorUserId,
		providerId,
		filepath,
		filename: filename || safeFilename,
		mimeType: mimeType || null,
		size: buffer.length,
	});

	logger.info(
		{ attachmentId: id, ref: refRecord.ref, filename: safeFilename, size: buffer.length },
		"attachment stored and ref created",
	);

	return {
		id,
		filename: filename || safeFilename,
		mimeType,
		size: buffer.length,
		ref: refRecord.ref,
		textContent,
		expiresAt,
	};
}

/**
 * Rewrite provider response to strip inline attachments and add refs.
 */
async function rewriteResponse(
	data: unknown,
	actorUserId: string,
	providerId: string,
): Promise<unknown> {
	if (!data || typeof data !== "object") {
		return data;
	}

	const response = data as Record<string, unknown>;

	// Check for attachments array
	const attachments = response.attachments;
	if (!Array.isArray(attachments) || attachments.length === 0) {
		return data;
	}

	// Process each attachment
	const rewrittenAttachments: RewrittenAttachment[] = [];

	for (const attachment of attachments) {
		if (!attachment || typeof attachment !== "object") {
			continue;
		}

		try {
			const rewritten = await processAttachment(
				attachment as ProviderAttachment,
				actorUserId,
				providerId,
			);
			rewrittenAttachments.push(rewritten);
		} catch (err) {
			logger.error(
				{ attachmentId: (attachment as ProviderAttachment).id, error: String(err) },
				"failed to process attachment",
			);
			// Include original without inline on error
			const orig = attachment as ProviderAttachment;
			rewrittenAttachments.push({
				id: orig.id,
				filename: orig.filename,
				mimeType: orig.mimeType,
				size: orig.size,
				ref: "",
				textContent: orig.textContent,
				expiresAt: orig.expiresAt,
			});
		}
	}

	return {
		...response,
		attachments: rewrittenAttachments,
	};
}

/**
 * Proxy a request to a provider and rewrite the response.
 */
export async function proxyProviderRequest(
	request: ProviderProxyRequest,
): Promise<ProviderProxyResponse> {
	const { providerId, path: requestPath, method = "POST", body, userId } = request;

	// Validate provider ID
	if (!providerId || typeof providerId !== "string") {
		return { status: "error", error: "Missing provider ID" };
	}

	// Validate path
	if (!requestPath || typeof requestPath !== "string") {
		return { status: "error", error: "Missing request path" };
	}

	// Normalize path
	const normalizedPath = requestPath.startsWith("/") ? requestPath : `/${requestPath}`;

	// Look up provider
	const config = loadConfig();
	const provider = config.providers?.find((p: ExternalProviderConfig) => p.id === providerId);
	if (!provider) {
		return { status: "error", error: "Provider not found" };
	}

	// Validate and resolve provider URL
	let providerUrl: URL;
	try {
		const { url } = await validateProviderBaseUrl(provider.baseUrl);
		providerUrl = new URL(normalizedPath, url);
	} catch (err) {
		logger.warn({ providerId, error: String(err) }, "provider URL validation failed");
		return { status: "error", error: "Provider not available" };
	}

	// Prepare headers
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		Accept: "application/json",
		// Signal to provider that this request comes through the relay proxy,
		// which handles attachment storage/delivery. Provider can return inline content.
		"x-relay-proxy": "true",
	};

	// Add actor user ID header if provided
	if (userId) {
		headers["x-actor-user-id"] = userId;
	}

	// Make request
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), DEFAULT_PROXY_TIMEOUT_MS);

	let response: Response;
	try {
		response = await fetch(providerUrl.toString(), {
			method: method.toUpperCase(),
			headers,
			body: method.toUpperCase() !== "GET" ? body : undefined,
			signal: controller.signal,
		});
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		logger.warn({ providerId, path: normalizedPath, error: reason }, "provider request failed");
		return { status: "error", error: "Provider request failed" };
	} finally {
		clearTimeout(timeout);
	}

	// Check content type (only rewrite JSON)
	const contentType = response.headers.get("content-type") || "";
	if (!contentType.includes("application/json")) {
		// Non-JSON: return error (don't passthrough binary/streaming)
		logger.warn({ providerId, contentType }, "provider returned non-JSON response");
		return { status: "error", error: "Provider returned non-JSON response" };
	}

	// Parse response
	let data: unknown;
	try {
		const text = await response.text();
		data = JSON.parse(text);
	} catch (err) {
		logger.warn({ providerId, error: String(err) }, "failed to parse provider response");
		return { status: "error", error: "Invalid provider response" };
	}

	// Check for provider-level error
	if (!response.ok) {
		const errorData = data as Record<string, unknown>;
		return {
			status: "error",
			error: (errorData.error as string) || `Provider error: ${response.status}`,
		};
	}

	// Rewrite response to strip inline attachments
	const actorUserId = userId || "unknown";
	try {
		const rewritten = await rewriteResponse(data, actorUserId, providerId);
		return { status: "ok", data: rewritten };
	} catch (err) {
		logger.error({ providerId, error: String(err) }, "failed to rewrite response");
		return { status: "error", error: "Failed to process attachments" };
	}
}
