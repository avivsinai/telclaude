import crypto from "node:crypto";
import { getChildLogger } from "../../logging.js";
import type { MemorySnapshotRequest } from "../../memory/rpc.js";
import { handleMemoryPropose, handleMemorySnapshot } from "../../memory/rpc.js";
import {
	isSocialMemorySource,
	isTelegramMemorySource,
	telegramMemorySource,
} from "../../memory/source.js";
import type { MemoryCategory, TrustLevel } from "../../memory/types.js";
import { isValidCategory, isValidTrust } from "../../memory/validation.js";
import { type ProviderProxyRequest, proxyProviderRequest } from "../../relay/provider-proxy.js";
import { redactSecrets } from "../../security/output-filter.js";
import { type AttachmentRef, validateAttachmentRef } from "../../storage/attachment-refs.js";
import type {
	TelclaudeMcpAttachmentGetRequest,
	TelclaudeMcpAuditNoteRequest,
	TelclaudeMcpMemorySearchRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
	TelclaudeMcpProviderReadRequest,
} from "./bridge.js";
import type { TelclaudeLiveMcpRelayClients } from "./live-server.js";
import type { TelclaudeMcpSideEffectLedger } from "./side-effect-ledger.js";

const logger = getChildLogger({ module: "hermes-live-relay-clients" });

type ProviderProxy = (request: ProviderProxyRequest) => Promise<{
	status: "ok" | "error";
	data?: unknown;
	error?: string;
	errorCode?: string;
}>;

type AttachmentValidator = typeof validateAttachmentRef;

export type TelclaudeLiveMcpAuditEntry = {
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: string;
	readonly endpointId: string;
	readonly kind: string;
	readonly payload: Record<string, unknown>;
};

export type CreateTelclaudeLiveMcpRelayClientsOptions = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly providerProxy?: ProviderProxy;
	readonly validateAttachment?: AttachmentValidator;
	readonly auditNote?: (entry: TelclaudeLiveMcpAuditEntry) => void | Promise<void>;
	readonly makeApprovalRequestId?: () => string;
};

const ALLOWED_MEMORY_FILTER_KEYS = new Set(["categories", "trust"]);
const PROVIDER_PATH = "/v1/fetch";

export function createTelclaudeLiveMcpRelayClients(
	options: CreateTelclaudeLiveMcpRelayClientsOptions,
): TelclaudeLiveMcpRelayClients {
	const provider = options.providerProxy ?? proxyProviderRequest;
	const attachmentValidator = options.validateAttachment ?? validateAttachmentRef;
	const auditNote = options.auditNote ?? defaultAuditNote;
	const makeApprovalRequestId =
		options.makeApprovalRequestId ?? (() => `mcp-approval-${crypto.randomUUID()}`);

	return {
		async providerRead(request) {
			assertAuthorityMemoryBoundary(request);
			const response = await provider({
				providerId: request.service,
				path: PROVIDER_PATH,
				method: "POST",
				body: JSON.stringify(providerFetchBody(request)),
				userId: request.actorId,
			});
			if (response.status === "error") {
				throw new Error(`provider read failed: ${providerErrorCode(response)}`);
			}
			return response.data ?? {};
		},

		async providerPrepareWrite(request) {
			assertAuthorityMemoryBoundary(request);
			const record = options.ledger.prepare({
				kind: "provider",
				actorId: request.actorId,
				approverActorId: request.actorId,
				profileId: request.profileId,
				domain: request.domain,
				service: request.service,
				action: request.action,
				params: request.params,
				providerAccountRef: `${request.service}:primary`,
				approvalRequestId: makeApprovalRequestId(),
				approvalRevision: 1,
				wysiwysRender: providerApprovalRender(request),
				...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {}),
			});
			return { actionRef: record.ref, approvalRequestId: record.approvalRequestId };
		},

		async memorySearch(request) {
			assertAuthorityMemoryBoundary(request);
			const filters = parseMemorySearchFilters(request.filters);
			const result = handleMemorySnapshot({
				...filters,
				sources: [request.memorySource],
				limit: request.limit,
			});
			if (!result.ok) throw new Error(result.error);
			const query = request.query.trim().toLowerCase();
			return {
				entries: result.value.entries.filter((entry) => memoryEntryMatches(entry, query)),
			};
		},

		async memoryWrite(request) {
			assertAuthorityMemoryBoundary(request);
			const result = handleMemoryPropose(
				{
					entries: [
						{
							id: request.id,
							category: request.category,
							content: request.content,
							metadata: request.metadata,
						},
					],
					userId: request.actorId,
				},
				{ source: request.memorySource, userId: request.actorId },
			);
			if (!result.ok) throw new Error(result.error);
			return result.value;
		},

		async attachmentGet(request: TelclaudeMcpAttachmentGetRequest) {
			assertAuthorityMemoryBoundary(request);
			const result = attachmentValidator(request.ref, { actorUserId: request.actorId });
			if (!result.valid) throw new Error(`attachment unavailable: ${result.reason}`);
			return attachmentMetadata(result.attachment);
		},

		async outboundPrepare(request) {
			assertAuthorityMemoryBoundary(request);
			const record = options.ledger.prepare({
				kind: "outbound",
				actorId: request.actorId,
				approverActorId: request.actorId,
				profileId: request.profileId,
				domain: request.domain,
				channel: request.channel,
				destination: request.recipient,
				renderedBody: request.content,
				mediaRefs: request.mediaRefs,
				conversationRef: `${request.channel}:${request.recipient}`,
				approvalRequestId: makeApprovalRequestId(),
				approvalRevision: 1,
				approvalMetadata: {
					source: "hermes-live-mcp",
					endpointId: request.endpointId,
					networkNamespace: request.networkNamespace,
				},
			});
			return { outboundRef: record.ref, approvalRequestId: record.approvalRequestId };
		},

		async auditNote(request: TelclaudeMcpAuditNoteRequest) {
			assertAuthorityMemoryBoundary(request);
			const entry = {
				actorId: request.actorId,
				profileId: request.profileId,
				domain: request.domain,
				endpointId: request.endpointId,
				kind: request.kind,
				payload: sanitizePayload(request.payload),
			};
			await auditNote(entry);
			return { stored: true };
		},
	};
}

function providerFetchBody(
	request: TelclaudeMcpProviderReadRequest | TelclaudeMcpProviderPrepareWriteRequest,
): { service: string; action: string; params: Record<string, unknown> } {
	const split = request.action.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_.:-]+)$/);
	return {
		service: split?.[1] ?? request.service,
		action: split?.[2] ?? request.action,
		params: request.params,
	};
}

function providerApprovalRender(request: TelclaudeMcpProviderPrepareWriteRequest): string {
	return `${request.service}.${request.action}`;
}

function providerErrorCode(response: { errorCode?: string; error?: string }): string {
	return redactSecrets(response.errorCode || response.error || "provider_unavailable");
}

function parseMemorySearchFilters(
	filters: TelclaudeMcpMemorySearchRequest["filters"],
): Pick<MemorySnapshotRequest, "categories" | "trust"> {
	if (!filters) return {};
	const unsupported = Object.keys(filters).filter((key) => !ALLOWED_MEMORY_FILTER_KEYS.has(key));
	if (unsupported.length > 0) {
		throw new Error(`memory filters denied: ${unsupported.sort().join(", ")}`);
	}
	return {
		categories: parseStringList<MemoryCategory>(filters.categories, isValidCategory, "category"),
		trust: parseStringList<TrustLevel>(filters.trust, isValidTrust, "trust"),
	};
}

function parseStringList<T extends string>(
	value: unknown,
	isValid: (value: string) => boolean,
	label: string,
): T[] | undefined {
	if (value === undefined) return undefined;
	const list = Array.isArray(value) ? value : [value];
	if (!list.every((entry) => typeof entry === "string" && entry.trim())) {
		throw new Error("memory filter values must be non-empty strings");
	}
	return list.map((entry) => {
		const trimmed = (entry as string).trim();
		if (!isValid(trimmed)) {
			throw new Error(`invalid memory ${label} filter: ${trimmed}`);
		}
		return trimmed as T;
	});
}

function memoryEntryMatches(
	entry: { content: string; metadata?: Record<string, unknown> },
	query: string,
): boolean {
	if (!query) return true;
	return (
		entry.content.toLowerCase().includes(query) ||
		(entry.metadata ? JSON.stringify(entry.metadata).toLowerCase().includes(query) : false)
	);
}

function attachmentMetadata(attachment: AttachmentRef): Record<string, unknown> {
	return {
		ref: attachment.ref,
		providerId: attachment.providerId,
		filename: attachment.filename,
		mimeType: attachment.mimeType,
		size: attachment.size,
		createdAt: attachment.createdAt,
		expiresAt: attachment.expiresAt,
	};
}

async function defaultAuditNote(entry: TelclaudeLiveMcpAuditEntry): Promise<void> {
	logger.info(
		{
			actorId: entry.actorId,
			profileId: entry.profileId,
			domain: entry.domain,
			endpointId: entry.endpointId,
			kind: entry.kind,
			payload: entry.payload,
		},
		"Hermes live MCP audit note",
	);
}

function assertAuthorityMemoryBoundary(request: {
	readonly domain: string;
	readonly profileId: string;
	readonly memorySource: string;
}): void {
	if (request.domain === "social" || request.domain === "public") {
		if (!isSocialMemorySource(request.memorySource)) {
			throw new Error("live MCP social authority must use social memory source");
		}
		return;
	}
	if (!isTelegramMemorySource(request.memorySource)) {
		throw new Error("live MCP private authority must use telegram profile memory source");
	}
	const expected = telegramMemorySource(request.profileId);
	if (request.memorySource !== expected) {
		throw new Error(`live MCP private authority memory source must be ${expected}`);
	}
}

function sanitizePayload(value: unknown): Record<string, unknown> {
	const sanitized = sanitizeUnknown(value);
	if (!sanitized || typeof sanitized !== "object" || Array.isArray(sanitized)) return {};
	return sanitized as Record<string, unknown>;
}

function sanitizeUnknown(value: unknown): unknown {
	if (typeof value === "string") return redactSecrets(value).slice(0, 2_000);
	if (Array.isArray(value)) return value.slice(0, 50).map(sanitizeUnknown);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value as Record<string, unknown>).map(([key, child]) => [
			key,
			sanitizeUnknown(child),
		]),
	);
}
