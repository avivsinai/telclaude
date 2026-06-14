/**
 * Provider proxy for attachment interception.
 *
 * Routes provider API calls through the relay, intercepts responses,
 * strips inline base64 attachments, stores them, and returns refs.
 *
 * This prevents Claude from accessing raw attachment bytes directly.
 */

import fs from "node:fs";
import path from "node:path";

import { type ExternalProviderConfig, loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { validateProviderBaseUrl } from "../providers/provider-validation.js";
import { createAttachmentRef } from "../storage/attachment-refs.js";
import { buildAttachmentFilename, ensureDocumentsDir } from "./attachment-helpers.js";
import { buildProviderSidecarRelayAuthHeaders } from "./provider-sidecar-auth.js";

const logger = getChildLogger({ module: "provider-proxy" });

const MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024; // 20MB
const DEFAULT_PROXY_TIMEOUT_MS = 30_000;
const PROVIDER_CHALLENGE_PENDING_ERROR =
	"Provider challenge pending; check the relay-rendered operator prompt.";
const CANONICAL_PROVIDER_SERVICE_ALIASES: Record<string, readonly string[]> = {
	bank: ["poalim", "massad"],
};
const MODEL_VISIBLE_SECRET_RESPONSE_FIELDS = new Set([
	"interacturl",
	"novncurl",
	"screenshot",
	"preview",
]);
const MODEL_VISIBLE_SECRET_RESPONSE_FIELD_PATTERN =
	/(?:interact|novnc)[_-]?url$|(?:screenshot|preview)$/i;
const VISUAL_PAYLOAD_FIELD_PATTERN = /(?:image|thumb|thumbnail|snapshot|frame)$/i;
const TOKEN_BEARING_URL_PARAM_PATTERN =
	/(^|[_-])(access|auth|bearer|challenge|session|singleuse|single_use|one[_-]?time)?[_-]?(token|jwt|signature|sig|secret|code)$/i;
const INTERACTIVE_URL_PATH_PATTERN = /(challenge|interactive|interact|novnc|vnc|browser)/i;
const URL_SUBSTRING_PATTERN = /https?:\/\/[^\s<>"'`]+/gi;
const OPAQUE_BASE64_MIN_LENGTH = 256;
const REDACT_PROVIDER_VALUE = Symbol("redact-provider-value");

export type ProviderProxyRequest = {
	providerId: string;
	path: string;
	method?: string;
	body?: string;
	userId?: string;
	/** Signed approval token for action-type requests */
	approvalToken?: string;
	/**
	 * "preapproved-ledger" means the request already passed Hermes side-effect
	 * approval and must not create a legacy /approve nonce on provider denial.
	 */
	approvalMode?: "interactive" | "preapproved-ledger";
};

export type ProviderProxyResponse = {
	status: "ok" | "error";
	data?: unknown;
	error?: string;
	errorCode?: string;
	approvalNonce?: string;
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

type ConfiguredProviderResolution = {
	readonly provider: ExternalProviderConfig;
	readonly serviceAlias?: string;
};

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

	// Look up provider. Hermes authority scopes use canonical provider ids such as
	// "bank", while a configured sidecar can expose implementation-specific
	// services such as "poalim".
	const config = loadConfig();
	const resolvedProvider = resolveConfiguredProvider(config.providers, providerId);
	if (!resolvedProvider) {
		return { status: "error", error: "Provider not found" };
	}
	const { provider, serviceAlias } = resolvedProvider;
	const requestBody = rewriteProviderRequestBody(body, providerId, serviceAlias);

	// Validate and resolve provider URL
	let providerUrl: URL;
	try {
		const { url } = await validateProviderBaseUrl(provider.baseUrl);
		providerUrl = new URL(normalizedPath, url);
	} catch (err) {
		logger.warn({ providerId, error: String(err) }, "provider URL validation failed");
		return { status: "error", error: "Provider not available" };
	}

	const fetchMethod = method.toUpperCase();
	const outgoingBody = fetchMethod !== "GET" ? requestBody : undefined;
	const providerRequestPath = `${providerUrl.pathname}${providerUrl.search}`;

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

	// Forward approval token for action-type requests
	if (request.approvalToken) {
		headers["x-approval-token"] = request.approvalToken;
	}

	Object.assign(
		headers,
		await buildProviderSidecarRelayAuthHeaders({
			provider,
			method: fetchMethod,
			path: providerRequestPath,
			rawBody: outgoingBody ?? "",
		}),
	);

	// Make request
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), DEFAULT_PROXY_TIMEOUT_MS);

	let response: Response;
	try {
		response = await fetch(providerUrl.toString(), {
			method: fetchMethod,
			headers,
			body: outgoingBody,
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
	if (isProviderChallengePending(response.status, data)) {
		return {
			status: "error",
			errorCode: "challenge_pending",
			error: PROVIDER_CHALLENGE_PENDING_ERROR,
			data: sanitizeProviderChallengePayload(data),
		};
	}

	if (!response.ok) {
		const errorData = data as Record<string, unknown>;
		const errorCode = errorData.errorCode as string | undefined;

		// Intercept approval_required: create pending approval for /approve flow
		if (
			response.status === 403 &&
			errorCode === "approval_required" &&
			request.approvalMode !== "preapproved-ledger"
		) {
			const { createProviderApproval } = await import("./provider-approval.js");
			try {
				const parsedBody = requestBody ? JSON.parse(requestBody) : {};
				// Derive service/action from body fields or URL path (/v1/:service/:action)
				let service = parsedBody.service as string | undefined;
				let action = parsedBody.action as string | undefined;
				if (!service || !action) {
					const pathSegments = request.path.replace(/^\/v1\//, "").split("/");
					if (pathSegments.length >= 2) {
						service = service || pathSegments[0];
						action = action || pathSegments[1];
					}
				}
				const nonce = createProviderApproval(
					request,
					{
						service: service ?? "",
						action: action ?? "",
						params: parsedBody.params ?? {},
					},
					userId || "unknown",
				);
				return {
					status: "error",
					errorCode: "approval_required",
					error: sanitizeProviderVisibleError(errorData.error, "Action requires approval"),
					approvalNonce: nonce,
				};
			} catch (err) {
				logger.warn({ providerId, error: String(err) }, "failed to create provider approval");
			}
		}

		return {
			status: "error",
			errorCode,
			error: sanitizeProviderVisibleError(errorData.error, `Provider error: ${response.status}`),
		};
	}

	// Rewrite response to strip inline attachments
	const actorUserId = userId || "unknown";
	try {
		const rewritten = await rewriteResponse(data, actorUserId, providerId);
		return { status: "ok", data: sanitizeProviderModelVisiblePayload(rewritten) };
	} catch (err) {
		logger.error({ providerId, error: String(err) }, "failed to rewrite response");
		return { status: "error", error: "Failed to process attachments" };
	}
}

function resolveConfiguredProvider(
	providers: readonly ExternalProviderConfig[] | undefined,
	providerId: string,
): ConfiguredProviderResolution | undefined {
	const exactProvider = providers?.find((provider) => provider.id === providerId);
	if (exactProvider) return { provider: exactProvider };

	const directServiceProvider = providers?.find((provider) =>
		providerHandlesService(provider, providerId),
	);
	if (directServiceProvider) return { provider: directServiceProvider };

	for (const serviceAlias of CANONICAL_PROVIDER_SERVICE_ALIASES[providerId] ?? []) {
		const aliasProvider = providers?.find(
			(provider) => provider.id === serviceAlias || providerHandlesService(provider, serviceAlias),
		);
		if (aliasProvider) return { provider: aliasProvider, serviceAlias };
	}

	return undefined;
}

function providerHandlesService(provider: ExternalProviderConfig, service: string): boolean {
	return Array.isArray(provider.services) && provider.services.includes(service);
}

function rewriteProviderRequestBody(
	body: string | undefined,
	providerId: string,
	serviceAlias: string | undefined,
): string | undefined {
	if (!body || !serviceAlias) return body;
	try {
		const parsed = JSON.parse(body) as unknown;
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return body;
		const fields = parsed as Record<string, unknown>;
		if (fields.service !== providerId) return body;
		return JSON.stringify({
			...fields,
			service: serviceAlias,
		});
	} catch {
		return body;
	}
}

function isProviderChallengePending(statusCode: number, data: unknown): boolean {
	if (statusCode === 202) return true;
	if (!data || typeof data !== "object" || Array.isArray(data)) return false;
	const record = data as Record<string, unknown>;
	return record.status === "challenge_pending" || record.errorCode === "challenge_pending";
}

function sanitizeProviderChallengePayload(data: unknown): unknown {
	return sanitizeProviderModelVisiblePayload(data);
}

function sanitizeProviderModelVisiblePayload(data: unknown): unknown {
	if (Array.isArray(data)) {
		const sanitizedItems: unknown[] = [];
		for (const item of data) {
			const sanitized = sanitizeProviderModelVisiblePayload(item);
			if (sanitized !== REDACT_PROVIDER_VALUE) {
				sanitizedItems.push(sanitized);
			}
		}
		return sanitizedItems;
	}
	if (typeof data === "string" && containsTokenBearingInteractiveUrl(data)) {
		return REDACT_PROVIDER_VALUE;
	}
	if (!data || typeof data !== "object") {
		return data;
	}

	const sanitized: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
		if (isModelVisibleSecretProviderField(key, value)) {
			continue;
		}
		const sanitizedValue = sanitizeProviderModelVisiblePayload(value);
		if (sanitizedValue === REDACT_PROVIDER_VALUE) {
			continue;
		}
		sanitized[key] = sanitizedValue;
	}
	return sanitized;
}

function isModelVisibleSecretProviderField(key: string, value: unknown): boolean {
	if (isProviderSecretFieldName(key)) {
		return true;
	}
	if (typeof value !== "string") {
		return false;
	}
	if (containsTokenBearingInteractiveUrl(value)) {
		return true;
	}
	return isPotentialVisualPayloadField(key) && isLargeOpaqueBase64(value);
}

function sanitizeProviderVisibleError(value: unknown, fallback: string): string {
	if (typeof value !== "string" || !value.trim()) {
		return fallback;
	}
	const sanitized = sanitizeProviderModelVisiblePayload(value);
	return sanitized === REDACT_PROVIDER_VALUE ? fallback : value;
}

function isProviderSecretFieldName(key: string): boolean {
	const normalized = key.toLowerCase();
	return (
		MODEL_VISIBLE_SECRET_RESPONSE_FIELDS.has(normalized) ||
		MODEL_VISIBLE_SECRET_RESPONSE_FIELD_PATTERN.test(normalized)
	);
}

function isPotentialVisualPayloadField(key: string): boolean {
	return VISUAL_PAYLOAD_FIELD_PATTERN.test(key.toLowerCase());
}

function containsTokenBearingInteractiveUrl(value: string): boolean {
	if (isTokenBearingInteractiveUrl(value)) {
		return true;
	}
	for (const match of value.matchAll(URL_SUBSTRING_PATTERN)) {
		if (isTokenBearingInteractiveUrl(trimUrlCandidate(match[0]))) {
			return true;
		}
	}
	return false;
}

function trimUrlCandidate(value: string): string {
	return value.replace(/[),.;:!?]+$/g, "");
}

function isLargeOpaqueBase64(value: string): boolean {
	const trimmed = value.trim();
	const withoutDataPrefix = trimmed.replace(/^data:[^;]+;base64,/i, "");
	const compact = withoutDataPrefix.replace(/\s+/g, "");
	if (compact.length < OPAQUE_BASE64_MIN_LENGTH) {
		return false;
	}
	return /^[A-Za-z0-9+/]+={0,2}$/.test(compact);
}

function isTokenBearingInteractiveUrl(value: string): boolean {
	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch {
		return false;
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		return false;
	}

	const hasTokenParam = Array.from(parsed.searchParams.keys()).some((key) =>
		TOKEN_BEARING_URL_PARAM_PATTERN.test(key),
	);
	if (hasTokenParam) {
		return true;
	}
	if (!INTERACTIVE_URL_PATH_PATTERN.test(parsed.pathname)) {
		return false;
	}
	return parsed.pathname.split("/").some((segment) => /^[A-Za-z0-9_-]{16,}$/.test(segment));
}
