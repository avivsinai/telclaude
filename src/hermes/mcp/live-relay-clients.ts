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
import {
	type AttachmentRef as StoredAttachmentRef,
	validateAttachmentRef,
} from "../../storage/attachment-refs.js";
import {
	EdgeAdapterSchemaVersions,
	type AttachmentRef as EdgeAttachmentRef,
	type PreparedOutbound,
} from "../edge-adapter-contract.js";
import { TelclaudeEdgeRuntime } from "../edge-adapter-runtime.js";
import {
	assertTargetableReplyIntent,
	createRelayConversationStore,
	type RelayConversation,
	type RelayConversationInboundTurn,
	type RelayConversationReplyIntent,
	type RelayConversationStore,
	relayAuthorityActorRefFor,
	relayConversationToConversationRef,
	targetableRelayConversationMembers,
} from "../relay-conversation-store.js";
import type {
	TelclaudeMcpAttachmentGetRequest,
	TelclaudeMcpAuditNoteRequest,
	TelclaudeMcpMemorySearchRequest,
	TelclaudeMcpOutboundPrepareRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
	TelclaudeMcpProviderReadRequest,
} from "./bridge.js";
import type { TelclaudeLiveMcpRelayClients } from "./live-server.js";
import {
	providerAccountRefFor,
	providerApprovalRenderFor,
	resolveTelclaudeProviderOperation,
} from "./provider-routing.js";
import type {
	TelclaudeMcpSideEffectLedger,
	TelclaudeMcpSideEffectRecord,
} from "./side-effect-ledger.js";

const logger = getChildLogger({ module: "hermes-live-relay-clients" });

type ProviderProxy = (request: ProviderProxyRequest) => Promise<{
	status: "ok" | "error";
	data?: unknown;
	error?: string;
	errorCode?: string;
}>;

type AttachmentValidator = typeof validateAttachmentRef;
type OutboundMediaResolver = (
	refs: readonly string[],
	context: {
		readonly request: TelclaudeMcpOutboundPrepareRequest;
		readonly conversation: RelayConversation;
	},
) => readonly EdgeAttachmentRef[] | Promise<readonly EdgeAttachmentRef[]>;

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
	readonly providerWriteApproverActorId?: string;
	readonly outboundApproverActorId?: string;
	readonly conversationStore?: RelayConversationStore;
	readonly edgeRuntime?: TelclaudeEdgeRuntime;
	readonly resolveOutboundMediaRefs?: OutboundMediaResolver;
	readonly requestSideEffectApproval?: (
		record: TelclaudeMcpSideEffectRecord,
	) => void | Promise<void>;
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
	const providerWriteApproverActorId = optionalTrimmed(options.providerWriteApproverActorId);
	const outboundApproverActorId = optionalTrimmed(options.outboundApproverActorId);
	const conversationStore = options.conversationStore ?? createRelayConversationStore();
	const edgeRuntime = options.edgeRuntime ?? new TelclaudeEdgeRuntime();
	const resolveOutboundMediaRefs =
		options.resolveOutboundMediaRefs ?? defaultResolveOutboundMediaRefs;

	return {
		async providerRead(request) {
			assertAuthorityMemoryBoundary(request);
			const operation = resolveTelclaudeProviderOperation(request);
			assertProviderOperationPolicy(operation);
			const response = await provider({
				providerId: operation.providerId,
				path: PROVIDER_PATH,
				method: "POST",
				body: JSON.stringify(providerFetchBody(operation)),
				userId: request.actorId,
			});
			if (response.status === "error") {
				throw new Error(`provider read failed: ${providerErrorCode(response)}`);
			}
			return response.data ?? {};
		},

		async providerPrepareWrite(request) {
			assertAuthorityMemoryBoundary(request);
			const operation = resolveTelclaudeProviderOperation(request);
			assertProviderOperationPolicy(operation);
			const record = options.ledger.prepare({
				kind: "provider",
				actorId: request.actorId,
				approverActorId: providerWriteApproverFor(providerWriteApproverActorId, request.actorId),
				profileId: request.profileId,
				domain: request.domain,
				providerId: operation.providerId,
				service: operation.service,
				action: operation.action,
				params: operation.params,
				providerAccountRef: providerAccountRefFor(operation),
				approvalRequestId: makeApprovalRequestId(),
				approvalRevision: 1,
				wysiwysRender: providerApprovalRenderFor(operation),
				...(request.turnConversationRef
					? { turnConversationRef: request.turnConversationRef }
					: {}),
				...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {}),
			});
			await requestHumanApproval(options.ledger, record, options.requestSideEffectApproval);
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
			const conversation = resolveOutboundConversation(conversationStore, request);
			assertOutboundConversationScope(request, conversation);
			const replyIntent = request.replyIntent ?? defaultReplyIntent(conversation);
			assertTargetableReplyIntent(conversation, replyIntent);
			const approverActorId = outboundApproverFor(outboundApproverActorId, request.actorId);
			const turn = resolveOutboundTurnAuthority(conversationStore, request, conversation);
			const mediaRefs = await resolveOutboundMediaRefs(request.mediaRefs, {
				request,
				conversation,
			});
			const prepared = edgeRuntime.prepareOutbound({
				authorizingActor: relayAuthorityActorRefFor(conversation),
				request: {
					schemaVersion: EdgeAdapterSchemaVersions.outboundRequest,
					channel: conversation.channel,
					recipient: replyIntent,
					requestedBody: request.body,
					mediaRefs,
					conversationRef: relayConversationToConversationRef(conversation),
					correlationId: outboundCorrelationId(request, conversation, replyIntent),
				},
			});
			const record = options.ledger.prepare({
				kind: "outbound",
				actorId: request.actorId,
				approverActorId,
				profileId: request.profileId,
				domain: request.domain,
				channel: prepared.channel,
				destination: destinationForPreparedOutbound(prepared),
				resolvedDestination: prepared.resolvedDestination,
				requestedBody: request.body,
				renderedBody: prepared.finalRenderedBody,
				mediaRefs: request.mediaRefs,
				preparedMediaRefs: prepared.mediaRefs.map((mediaRef) => ({
					quarantineId: mediaRef.quarantineId,
					contentHash: mediaRef.contentHash,
				})),
				conversationRef: conversation.token,
				authorizationState: conversation.authorizationState,
				edgePreparedRef: prepared.outboundRef,
				edgePreparedHash: prepared.edgePreparedHash,
				approvalRequestId: makeApprovalRequestId(),
				approvalRevision: 1,
				approvalMetadata: {
					source: "hermes-live-mcp",
					endpointId: request.endpointId,
					networkNamespace: request.networkNamespace,
					edgeSideEffectLedgerRef: prepared.sideEffectLedgerRef,
					...outboundAutoGrantProvenance(conversation, request.actorId),
				},
				turnConversationRef: turn.ref,
				idempotencyKey: prepared.idempotencyKey,
			});
			await requestHumanApproval(options.ledger, record, options.requestSideEffectApproval);
			return {
				outboundRef: record.ref,
				approvalRequestId: record.approvalRequestId,
				edgePreparedRef: prepared.outboundRef,
				edgePreparedHash: prepared.edgePreparedHash,
			};
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

async function requestHumanApproval(
	ledger: TelclaudeMcpSideEffectLedger,
	record: TelclaudeMcpSideEffectRecord,
	requestSideEffectApproval:
		| ((record: TelclaudeMcpSideEffectRecord) => void | Promise<void>)
		| undefined,
): Promise<void> {
	if (!requestSideEffectApproval) return;
	try {
		await requestSideEffectApproval(record);
	} catch (error) {
		ledger.revoke(record.ref, "side-effect approval request failed");
		throw error;
	}
}

function providerFetchBody(
	request: Pick<
		TelclaudeMcpProviderReadRequest | TelclaudeMcpProviderPrepareWriteRequest,
		"service" | "action" | "params"
	>,
): { service: string; action: string; params: Record<string, unknown> } {
	return {
		service: request.service,
		action: request.action,
		params: request.params,
	};
}

function providerErrorCode(response: { errorCode?: string; error?: string }): string {
	return redactSecrets(response.errorCode || response.error || "provider_unavailable");
}

function resolveOutboundConversation(
	store: RelayConversationStore,
	request: TelclaudeMcpOutboundPrepareRequest,
): RelayConversation {
	const conversation = store.resolveAuthorized(request.conversationToken);
	if (!conversation) {
		throw new Error("outbound conversation unavailable or unauthorized");
	}
	return conversation;
}

function assertOutboundConversationScope(
	request: TelclaudeMcpOutboundPrepareRequest,
	conversation: RelayConversation,
): void {
	if (conversation.profileId !== request.profileId) {
		throw new Error("outbound conversation profile mismatch");
	}
	if (conversation.mcpDomain !== request.domain) {
		throw new Error("outbound conversation domain mismatch");
	}
	if (!request.outboundChannels.includes(conversation.channel)) {
		throw new Error(`outbound channel denied: ${conversation.channel}`);
	}
	const targetableMembers = targetableRelayConversationMembers(conversation);
	if (targetableMembers.length === 0) {
		throw new Error("outbound conversation has no reply-capable members");
	}
	if (!targetableMembers.some((member) => member.actorId === request.actorId)) {
		throw new Error("outbound actor is not a reply-capable conversation member");
	}
}

function resolveOutboundTurnAuthority(
	store: RelayConversationStore,
	request: TelclaudeMcpOutboundPrepareRequest,
	conversation: RelayConversation,
): RelayConversationInboundTurn {
	if (!request.turnConversationRef) {
		throw new Error("outbound turn authority required");
	}
	const turn = store.resolveAuthorizedInboundTurn(request.turnConversationRef, conversation.token);
	if (!turn) {
		throw new Error("outbound turn authority unavailable or unauthorized");
	}
	if (
		turn.conversationToken !== conversation.token ||
		turn.channel !== conversation.channel ||
		turn.conversationId !== conversation.conversationId ||
		turn.profileId !== request.profileId ||
		turn.mcpDomain !== request.domain ||
		turn.senderActorId !== request.actorId
	) {
		throw new Error("outbound turn authority mismatch");
	}
	return turn;
}

function outboundAutoGrantProvenance(
	conversation: RelayConversation,
	actorId: string,
): {
	readonly pairedProvenance: boolean;
	readonly replyCapableActorSeat: boolean;
	readonly actorIdentityAssurance: string | null;
} {
	const actorSeat = targetableRelayConversationMembers(conversation).find(
		(member) => member.actorId === actorId,
	);
	return {
		pairedProvenance: conversation.humanPairingProvenance === true,
		replyCapableActorSeat: actorSeat?.scopes.includes("message:reply") === true,
		actorIdentityAssurance: actorSeat?.identityAssurance ?? null,
	};
}

function defaultReplyIntent(conversation: RelayConversation): RelayConversationReplyIntent {
	return { kind: "thread", threadId: conversation.threadId };
}

async function defaultResolveOutboundMediaRefs(
	refs: readonly string[],
): Promise<readonly EdgeAttachmentRef[]> {
	if (refs.length > 0) {
		throw new Error("outbound mediaRefs require an edge attachment resolver");
	}
	return [];
}

function destinationForPreparedOutbound(prepared: PreparedOutbound): string {
	const destination = prepared.resolvedDestination;
	switch (destination.kind) {
		case "thread":
			return destination.threadId ?? prepared.channel;
		case "actor":
			return destination.actorId ?? prepared.channel;
		case "address":
			return destination.addressRef ?? prepared.channel;
	}
}

function outboundCorrelationId(
	request: TelclaudeMcpOutboundPrepareRequest,
	conversation: RelayConversation,
	replyIntent: RelayConversationReplyIntent,
): string {
	const hash = crypto
		.createHash("sha256")
		.update(
			JSON.stringify({
				conversationToken: request.conversationToken,
				endpointId: request.endpointId,
				threadId: conversation.threadId,
				replyIntent,
				body: request.body,
				mediaRefs: request.mediaRefs,
			}),
		)
		.digest("hex")
		.slice(0, 32);
	return `mcp-outbound:${hash}`;
}

function assertProviderOperationPolicy(request: {
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
}): void {
	if (request.providerId === "clalit" && containsUrgentHealthSignal(request)) {
		throw new Error("provider policy denied: urgent_health_escalation_required");
	}
}

function containsUrgentHealthSignal(value: unknown): boolean {
	const text = JSON.stringify(value).toLowerCase();
	return [
		"emergency",
		"urgent",
		"chest pain",
		"shortness of breath",
		"stroke",
		"heart attack",
		"suicidal",
	].some((term) => text.includes(term));
}

function providerWriteApproverFor(
	providerWriteApproverActorId: string | undefined,
	actorId: string,
): string {
	if (!providerWriteApproverActorId) {
		throw new Error(
			"provider write approval denied: providerWriteApproverActorId is not configured",
		);
	}
	if (providerWriteApproverActorId === actorId.trim()) {
		throw new Error(
			"provider write approval denied: providerWriteApproverActorId must differ from actorId",
		);
	}
	return providerWriteApproverActorId;
}

function outboundApproverFor(outboundApproverActorId: string | undefined, actorId: string): string {
	if (!outboundApproverActorId) {
		throw new Error("outbound approval denied: outboundApproverActorId is not configured");
	}
	if (outboundApproverActorId === actorId.trim()) {
		throw new Error("outbound approval denied: outboundApproverActorId must differ from actorId");
	}
	return outboundApproverActorId;
}

function optionalTrimmed(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed && trimmed.length > 0 ? trimmed : undefined;
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

function attachmentMetadata(attachment: StoredAttachmentRef): Record<string, unknown> {
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
