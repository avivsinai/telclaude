import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { loadConfig, type TelclaudeConfig } from "../../config/config.js";
import { getHomeTarget } from "../../config/sessions.js";
import { validateCronExpression } from "../../cron/parse.js";
import { addCronJob, getCronJob, listCronJobs, removeCronJob } from "../../cron/store.js";
import type { CronJob, CronSchedule } from "../../cron/types.js";
import { upsertCuratorItem } from "../../curator/store.js";
import {
	type HouseholdReminderContext,
	resolveHouseholdReminderContext,
} from "../../household-reminders/binding.js";
import { householdReminderProposalPrompt } from "../../household-reminders/copy.js";
import {
	listHouseholdReminders,
	prepareHouseholdReminderCancellation,
	prepareHouseholdReminderCreate,
	prepareHouseholdReminderUpdate,
} from "../../household-reminders/store.js";
import {
	HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE,
	resolveJerusalemOneShot,
} from "../../household-reminders/time.js";
import type { HouseholdReminder } from "../../household-reminders/types.js";
import { getChildLogger } from "../../logging.js";
import type { MemorySnapshotRequest } from "../../memory/rpc.js";
import { handleMemoryPropose, handleMemorySnapshot } from "../../memory/rpc.js";
import {
	isHouseholdMemorySource,
	isSocialMemorySource,
	isTelegramMemorySource,
	telegramMemorySource,
} from "../../memory/source.js";
import type { MemoryCategory, TrustLevel } from "../../memory/types.js";
import { isValidCategory, isValidTrust } from "../../memory/validation.js";
import { assertHouseholdPhase0ProviderActionAllowed } from "../../providers/household-clalit-policy.js";
import type { AttachmentQuarantineStore } from "../../relay/attachment-quarantine-store.js";
import type {
	BrowserActExecutorSurface,
	BrowserActSurfaceRequest,
} from "../../relay/browser-act-relay-surface.js";
import type { BrowseRequest, BrowseResult } from "../../relay/browser-broker.js";
import { browserAuthorityDomainFromMcp } from "../../relay/browser-cookie-store.js";
import {
	type MediaActionConfirmationGate,
	MediaActionConfirmationRequiredError,
	type MediaActionToolName,
} from "../../relay/media-action-confirmation-store.js";
import { type ProviderProxyRequest, proxyProviderRequest } from "../../relay/provider-proxy.js";
import type { WhatsAppHouseholdReplyBindingResolver } from "../../relay/whatsapp-household-bindings.js";
import { fetchWithGuard } from "../../sandbox/fetch-guard.js";
import { wrapExternalContent } from "../../security/external-content.js";
import { redactSecrets } from "../../security/output-filter.js";
import { assertSafeWebEgress } from "../../security/web-egress-preflight.js";
import {
	githubGetTree,
	githubListRefs,
	githubListRepos,
	githubReadFile,
} from "../../services/github-repo-read.js";
import { generateImage } from "../../services/image-generation.js";
import {
	consumeRateLimit,
	enforceRateLimit,
	type FeatureRateLimitConfig,
} from "../../services/multimedia-rate-limit.js";
import { textToSpeech } from "../../services/tts.js";
import { searchWeb } from "../../services/web-search.js";
import {
	createAttachmentRef,
	type AttachmentRef as StoredAttachmentRef,
	validateAttachmentRef,
} from "../../storage/attachment-refs.js";
import {
	EdgeAdapterSchemaVersions,
	type AttachmentRef as EdgeAttachmentRef,
	AttachmentRefSchema as EdgeAttachmentRefSchema,
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
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpBridgeDependencies,
	TelclaudeMcpBrowseRequest,
	TelclaudeMcpBrowserActPrepareRequest,
	TelclaudeMcpBrowserActRequest,
	TelclaudeMcpDomain,
	TelclaudeMcpGithubGetTreeRequest,
	TelclaudeMcpGithubListRefsRequest,
	TelclaudeMcpGithubListReposRequest,
	TelclaudeMcpGithubReadFileRequest,
	TelclaudeMcpImageGenerateRequest,
	TelclaudeMcpMemorySearchRequest,
	TelclaudeMcpOutboundPrepareRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
	TelclaudeMcpProviderReadRequest,
	TelclaudeMcpScheduleCancelRequest,
	TelclaudeMcpScheduleCreateRequest,
	TelclaudeMcpScheduleInput,
	TelclaudeMcpScheduleListRequest,
	TelclaudeMcpScheduleUpdateRequest,
	TelclaudeMcpSkillRequestRequest,
	TelclaudeMcpToolName,
	TelclaudeMcpTtsRequest,
	TelclaudeMcpWebFetchRequest,
	TelclaudeMcpWebSearchRequest,
} from "./bridge.js";
import type { TelclaudeLiveMcpRelayClients } from "./live-server.js";
import {
	providerAccountRefFor,
	providerApprovalRenderFor,
	resolveTelclaudeProviderOperation,
} from "./provider-routing.js";
import type {
	TelclaudeMcpHouseholdReplyBinding,
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

/**
 * Resolves the relay-owned schedule owner for an authority. The ownerId is the
 * key under which a home target is stored, so a job created with it delivers to
 * the operator's own home chat. This is derived SERVER-SIDE from the authority
 * stamp; the agent never supplies an ownerId, chatId, threadId, or delivery
 * target. Returns null when the authority has no resolvable home target.
 */
export type ScheduleOwnerResolver = (
	request: TelclaudeMcpAuthorityStamp,
) => { readonly ownerId: string } | null;
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

/** The relay-owned browser broker surface tc_browse drives (read-only slice). */
export type BrowseExecutor = {
	browse(request: BrowseRequest): Promise<BrowseResult>;
};

export type CreateTelclaudeLiveMcpRelayClientsOptions = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly providerProxy?: ProviderProxy;
	readonly validateAttachment?: AttachmentValidator;
	readonly auditNote?: (entry: TelclaudeLiveMcpAuditEntry) => void | Promise<void>;
	readonly makeApprovalRequestId?: () => string;
	readonly providerWriteApproverActorId?: string;
	readonly outboundApproverActorId?: string;
	/** Distinct human approver actor for a staged browser write (must differ from actor). */
	readonly browserWriteApproverActorId?: string;
	readonly conversationStore?: RelayConversationStore;
	readonly edgeRuntime?: TelclaudeEdgeRuntime;
	readonly resolveOutboundMediaRefs?: OutboundMediaResolver;
	/** Re-resolves the relay-owned household pairing before preparing a reply. */
	readonly resolveHouseholdReplyBinding?: WhatsAppHouseholdReplyBindingResolver;
	readonly requestSideEffectApproval?: (
		record: TelclaudeMcpSideEffectRecord,
	) => void | Promise<void>;
	/** Rate limit for tc_web_fetch / tc_web_search; defaults to config `web`. */
	readonly webRateLimit?: FeatureRateLimitConfig;
	/** Injectable HTTP boundary for the web-search provider (tests only). */
	readonly webSearchFetch?: typeof fetch;
	/**
	 * Relay-owned browser broker backing tc_browse. Omitted until a live
	 * tc-browser endpoint is wired — tc_browse then fails closed with a typed
	 * not-configured error rather than silently succeeding.
	 */
	readonly browser?: BrowseExecutor;
	/**
	 * Relay-owned interactive browser-act surface backing tc_browse_act /
	 * tc_browse_act_prepare. Omitted until a live tc-browser endpoint is wired —
	 * the act tools then fail closed with a typed not-configured error. The
	 * committing-act EXECUTE path is served separately by the ledger's
	 * browser-write committer (injected at the live MCP server), not here.
	 */
	readonly browserAct?: BrowserActExecutorSurface;
	/**
	 * Resolves the schedule owner for an authority (schedule tools). Defaults to
	 * a home-target-backed resolver that keys off the authority's subjectUserId.
	 */
	readonly resolveScheduleOwner?: ScheduleOwnerResolver;
	/** Injectable config for household reminder binding/consent resolution. */
	readonly householdReminderConfig?: TelclaudeConfig;
	/** Optional dark-state guard for consequential actions derived from inbound media. */
	readonly mediaActionConfirmationGate?: MediaActionConfirmationGate;
};

const ALLOWED_MEMORY_FILTER_KEYS = new Set(["categories", "trust"]);
const PROVIDER_PATH = "/v1/fetch";
const DEFAULT_WEB_FETCH_TIMEOUT_MS = 30_000;
const WEB_FETCH_BYTES_PER_CHAR = 4;
export const OUTBOUND_MEDIA_QUARANTINE_TTL_MS = 15 * 60 * 1000;
/** Filing a Curator item is cheap but operator attention is not: keep it tight. */
const SKILL_REQUEST_RATE_LIMIT: FeatureRateLimitConfig = {
	maxPerHourPerUser: 5,
	maxPerDayPerUser: 20,
};

/** Authenticated private-repo traversal can pull a lot of context into the model;
 * keep it bounded but generous for a single operator browsing their own repos. */
const GITHUB_READ_RATE_LIMIT: FeatureRateLimitConfig = {
	maxPerHourPerUser: 120,
	maxPerDayPerUser: 600,
};
/** Cap on wrapped GitHub payload chars; the service already byte-caps file reads. */
const GITHUB_WRAP_MAX_CHARS = 200_000;

export class TelclaudeLiveMcpToolNotConfiguredError extends Error {
	readonly code = "mcp_tool_not_configured";

	constructor(toolName: TelclaudeMcpToolName) {
		super(`live MCP tool not configured: ${toolName}`);
		this.name = "TelclaudeLiveMcpToolNotConfiguredError";
	}
}

export class TelclaudeLiveMcpUnsupportedContentError extends Error {
	readonly code = "mcp_web_fetch_unsupported_content";

	constructor(contentType: string) {
		super(`web fetch unsupported content type: ${contentType || "(none)"}`);
		this.name = "TelclaudeLiveMcpUnsupportedContentError";
	}
}

/**
 * Typed wrapper for media-service failures (tc_image_generate / tc_tts). The
 * cause message is secret-redacted and truncated so an upstream provider error
 * can never echo key material or a stack trace back to the contained runtime.
 */
export class TelclaudeLiveMcpMediaGenerationError extends Error {
	readonly code = "mcp_media_generation_failed";

	constructor(toolName: TelclaudeMcpToolName, cause: unknown) {
		super(`${toolName} failed: ${sanitizedErrorMessage(cause)}`);
		this.name = "TelclaudeLiveMcpMediaGenerationError";
	}
}

function sanitizedErrorMessage(cause: unknown): string {
	const message = cause instanceof Error ? cause.message : String(cause);
	return redactSecrets(message).slice(0, 300);
}

/**
 * The authority has no resolvable home target, so a home-delivered reminder
 * cannot be created or owned. The operator must run /sethome first. The error
 * carries no chat/owner identifiers.
 */
export class TelclaudeLiveMcpScheduleOwnerError extends Error {
	readonly code = "mcp_schedule_owner_unresolved";

	constructor() {
		super(
			"schedule denied: no home target is set for this operator. Ask the operator to run /sethome in the chat where reminders should land.",
		);
		this.name = "TelclaudeLiveMcpScheduleOwnerError";
	}
}

/** A schedule input failed validation (bad timestamp, interval, or cron expr). */
export class TelclaudeLiveMcpScheduleValidationError extends Error {
	readonly code = "mcp_schedule_invalid";

	constructor(reason: string) {
		super(`schedule denied: ${reason}`);
		this.name = "TelclaudeLiveMcpScheduleValidationError";
	}
}

/** The referenced job does not exist or is owned by a different authority. */
export class TelclaudeLiveMcpScheduleNotFoundError extends Error {
	readonly code = "mcp_schedule_not_found";

	constructor() {
		super("schedule job not found for this owner");
		this.name = "TelclaudeLiveMcpScheduleNotFoundError";
	}
}

export type TelclaudeMcpCapabilityClients = Pick<
	TelclaudeMcpBridgeDependencies,
	| "webFetch"
	| "webSearch"
	| "browse"
	| "browseAct"
	| "browseActPrepare"
	| "browseActExecute"
	| "imageGenerate"
	| "tts"
	| "skillRequest"
	| "scheduleCreate"
	| "scheduleList"
	| "scheduleCancel"
	| "scheduleUpdate"
	| "githubListRepos"
	| "githubListRefs"
	| "githubGetTree"
	| "githubReadFile"
>;

/**
 * Fail-closed capability-tool clients for contexts that need a full bridge
 * dependency surface but never serve capability tools (probe runners,
 * approval continuation). Even a fully scoped call fails with a typed
 * not-configured error.
 */
export function createNotConfiguredTelclaudeMcpCapabilityClients(): TelclaudeMcpCapabilityClients {
	return {
		async webFetch() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_web_fetch");
		},
		async webSearch() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_web_search");
		},
		async browse() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse");
		},
		async browseAct() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse_act");
		},
		async browseActPrepare() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse_act_prepare");
		},
		async browseActExecute() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse_act_execute");
		},
		async imageGenerate() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_image_generate");
		},
		async tts() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_tts");
		},
		async skillRequest() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_skill_request");
		},
		async scheduleCreate() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_schedule_create");
		},
		async scheduleList() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_schedule_list");
		},
		async scheduleCancel() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_schedule_cancel");
		},
		async scheduleUpdate() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_schedule_update");
		},
		async githubListRepos() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_github_list_repos");
		},
		async githubListRefs() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_github_list_refs");
		},
		async githubGetTree() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_github_get_tree");
		},
		async githubReadFile() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_github_read_file");
		},
	};
}

export function createStoredAttachmentOutboundMediaResolver(options: {
	readonly edgeRuntime: TelclaudeEdgeRuntime;
	readonly quarantineStore: AttachmentQuarantineStore;
	readonly validateAttachment?: AttachmentValidator;
}): OutboundMediaResolver {
	const attachmentValidator = options.validateAttachment ?? validateAttachmentRef;
	return async (refs, { request, conversation }) => {
		if (refs.length === 0) return [];
		if (conversation.edgeDomain === null) {
			throw new Error("outbound media denied: conversation domain is not edge-projectable");
		}
		const mediaRefs: EdgeAttachmentRef[] = [];
		for (const ref of refs) {
			const validated = attachmentValidator(ref, { actorUserId: request.actorId });
			if (!validated.valid) {
				throw new Error(`outbound media denied: ${validated.reason}`);
			}
			const sourceDomain = generatedMediaAttachmentDomain(validated.attachment.providerId);
			if (sourceDomain && sourceDomain !== conversation.mcpDomain) {
				throw new Error(
					`outbound media denied: attachment source domain ${sourceDomain} cannot be reused for ${conversation.mcpDomain}`,
				);
			}
			const bytes = await readFile(validated.attachment.filepath).catch((error: unknown) => {
				throw new Error(
					`outbound media denied: attachment bytes unavailable: ${sanitizedErrorMessage(error)}`,
				);
			});
			const quarantined = options.quarantineStore.store({
				bytes,
				mediaType: validated.attachment.mimeType ?? "application/octet-stream",
				conversationToken: conversation.token,
				scanState: "clean",
				trustLabel: "trusted",
				ttlMs: OUTBOUND_MEDIA_QUARANTINE_TTL_MS,
			});
			const edgeRef = EdgeAttachmentRefSchema.parse({
				...quarantined,
				lifecycle: {
					...quarantined.lifecycle,
					authorizedFor: [
						...new Set([
							...quarantined.lifecycle.authorizedFor,
							conversation.profileId,
							`tc-${conversation.edgeDomain}`,
						]),
					],
				},
			});
			mediaRefs.push(
				options.edgeRuntime.registerAuthorizedAttachmentRef({
					ref: edgeRef,
					domain: conversation.edgeDomain,
				}),
			);
		}
		return mediaRefs;
	};
}

function generatedMediaAttachmentDomain(providerId: string): TelclaudeMcpDomain | null {
	const [toolName, domain, extra] = providerId.split(":");
	if (extra !== undefined) return null;
	if (toolName !== "tc_image_generate" && toolName !== "tc_tts") return null;
	if (
		domain === "private" ||
		domain === "social" ||
		domain === "household" ||
		domain === "public" ||
		domain === "specialist"
	) {
		return domain;
	}
	return null;
}

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
	const browserWriteApproverActorId = optionalTrimmed(options.browserWriteApproverActorId);
	const conversationStore = options.conversationStore ?? createRelayConversationStore();
	const edgeRuntime = options.edgeRuntime ?? new TelclaudeEdgeRuntime();
	const resolveOutboundMediaRefs =
		options.resolveOutboundMediaRefs ?? defaultResolveOutboundMediaRefs;
	const resolveScheduleOwner = options.resolveScheduleOwner ?? defaultResolveScheduleOwner;
	const webRateLimit = () => options.webRateLimit ?? loadConfig().web;

	// Audit a tool call, taking the authority-stamp fields off the request and
	// secret-redacting/truncating the payload. The kind labels the tool's effect.
	const auditFromRequest = (
		request: TelclaudeMcpAuthorityStamp,
		kind: string,
		payload: Record<string, unknown>,
	): void | Promise<void> =>
		auditNote({
			actorId: request.actorId,
			profileId: request.profileId,
			domain: request.domain,
			endpointId: request.endpointId,
			kind,
			payload: sanitizePayload(payload),
		});

	return {
		async providerRead(request) {
			assertAuthorityMemoryBoundary(request);
			const operation = resolveTelclaudeProviderOperation(request);
			assertProviderOperationPolicy(operation, request.domain, "read");
			const body = providerFetchBody({
				...operation,
				subjectUserId: request.subjectUserId,
			});
			const response = await provider({
				providerId: operation.providerId,
				path: PROVIDER_PATH,
				method: "POST",
				body: JSON.stringify(body),
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
			assertProviderOperationPolicy(operation, request.domain, "write");
			guardMediaDerivedAction(options.mediaActionConfirmationGate, request, {
				toolName: "tc_provider_prepare_write",
				params: {
					providerId: operation.providerId,
					service: operation.service,
					action: operation.action,
					params: operation.params,
					providerAccountRef: providerAccountRefFor(operation),
					...(request.subjectUserId ? { subjectUserId: request.subjectUserId } : {}),
				},
			});
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
				...(request.subjectUserId ? { subjectUserId: request.subjectUserId } : {}),
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
			const householdTurn =
				request.domain === "household"
					? resolveOutboundTurnAuthority(conversationStore, request, conversation)
					: null;
			const replyIntent = householdTurn
				? resolveOutboundReplyIntent(request, conversation, householdTurn)
				: (request.replyIntent ?? defaultReplyIntent(conversation));
			assertTargetableReplyIntent(conversation, replyIntent);
			const approverActorId = outboundApproverFor(outboundApproverActorId, request.actorId);
			const turn =
				householdTurn ?? resolveOutboundTurnAuthority(conversationStore, request, conversation);
			const householdReplyBinding = householdTurn
				? await resolveLiveHouseholdReplyBinding(
						options.resolveHouseholdReplyBinding,
						request,
						conversation,
						householdTurn,
						replyIntent,
					)
				: undefined;
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
				...(request.subjectUserId ? { subjectUserId: request.subjectUserId } : {}),
				...(householdReplyBinding ? { householdReplyBinding } : {}),
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
			await auditFromRequest(request, request.kind, request.payload);
			return { stored: true };
		},

		async webFetch(request: TelclaudeMcpWebFetchRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_fetch", request.actorId, webRateLimit());
			// Refuse to carry secret-shaped material outbound, then reserve the
			// rate-limit slot so a failed network attempt (SSRF/content-type/
			// timeout) still consumes quota rather than being freely repeatable.
			assertSafeWebEgress(request.url, "url");
			consumeRateLimit("web_fetch", request.actorId);
			const fetched = await fetchWebContent(request);
			await auditFromRequest(request, "web.fetch", {
				url: redactSecrets(request.url),
				finalUrl: redactSecrets(fetched.finalUrl),
				httpStatus: fetched.httpStatus,
				contentType: fetched.contentType,
				truncated: fetched.truncated,
			});
			return fetched;
		},

		async webSearch(request: TelclaudeMcpWebSearchRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_search", request.actorId, webRateLimit());
			assertSafeWebEgress(request.query, "query");
			consumeRateLimit("web_search", request.actorId);
			const found = await searchWeb(request.query, {
				count: request.count,
				...(options.webSearchFetch ? { fetchImpl: options.webSearchFetch } : {}),
			});
			const results = found.results.map((result) => ({
				title: redactSecrets(result.title),
				url: redactSecrets(result.url),
				snippet: redactSecrets(result.snippet),
			}));
			await auditFromRequest(request, "web.search", {
				query: redactSecrets(request.query),
				count: request.count,
				provider: found.provider,
				resultCount: results.length,
			});
			return {
				query: redactSecrets(request.query),
				provider: found.provider,
				results: wrapExternalContent(JSON.stringify(results, null, 2), {
					source: "web-search",
					serviceId: "tc_web_search",
					includeRiskAssessment: true,
				}),
			};
		},

		async githubListRepos(request: TelclaudeMcpGithubListReposRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("github_read", request.actorId, GITHUB_READ_RATE_LIMIT);
			consumeRateLimit("github_read", request.actorId);
			const result = await githubListRepos();
			await auditFromRequest(request, "github.list_repos", {
				totalCount: result.totalCount,
				returned: result.repositories.length,
				truncated: result.truncated,
			});
			return {
				totalCount: result.totalCount,
				truncated: result.truncated,
				repositories: wrapExternalContent(JSON.stringify(result.repositories, null, 2), {
					source: "github",
					serviceId: "tc_github_list_repos",
					includeRiskAssessment: true,
					maxLength: GITHUB_WRAP_MAX_CHARS,
				}),
			};
		},

		async githubListRefs(request: TelclaudeMcpGithubListRefsRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("github_read", request.actorId, GITHUB_READ_RATE_LIMIT);
			consumeRateLimit("github_read", request.actorId);
			const result = await githubListRefs({ repository: request.repository });
			await auditFromRequest(request, "github.list_refs", {
				repo: redactSecrets(result.repo),
				branches: result.branches.length,
				tags: result.tags.length,
				truncated: result.truncated,
			});
			return {
				repo: result.repo,
				truncated: result.truncated,
				refs: wrapExternalContent(
					JSON.stringify({ branches: result.branches, tags: result.tags }, null, 2),
					{
						source: "github",
						serviceId: "tc_github_list_refs",
						includeRiskAssessment: true,
						maxLength: GITHUB_WRAP_MAX_CHARS,
					},
				),
			};
		},

		async githubGetTree(request: TelclaudeMcpGithubGetTreeRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("github_read", request.actorId, GITHUB_READ_RATE_LIMIT);
			consumeRateLimit("github_read", request.actorId);
			const result = await githubGetTree({
				repository: request.repository,
				...(request.ref !== undefined ? { ref: request.ref } : {}),
				...(request.path !== undefined ? { path: request.path } : {}),
			});
			await auditFromRequest(request, "github.get_tree", {
				repo: redactSecrets(result.repo),
				ref: redactSecrets(result.ref),
				path: redactSecrets(result.path),
				entries: result.entries.length,
				truncated: result.truncated,
			});
			return {
				repo: result.repo,
				ref: result.ref,
				path: result.path,
				truncated: result.truncated,
				entries: wrapExternalContent(JSON.stringify(result.entries, null, 2), {
					source: "github",
					serviceId: "tc_github_get_tree",
					includeRiskAssessment: true,
					maxLength: GITHUB_WRAP_MAX_CHARS,
				}),
			};
		},

		async githubReadFile(request: TelclaudeMcpGithubReadFileRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("github_read", request.actorId, GITHUB_READ_RATE_LIMIT);
			consumeRateLimit("github_read", request.actorId);
			const result = await githubReadFile({
				repository: request.repository,
				path: request.path,
				...(request.ref !== undefined ? { ref: request.ref } : {}),
			});
			await auditFromRequest(request, "github.read_file", {
				repo: redactSecrets(result.repo),
				ref: redactSecrets(result.ref),
				path: redactSecrets(result.path),
				size: result.size,
				binary: result.binary,
				contentOmitted: result.contentOmitted,
			});
			return {
				repo: result.repo,
				ref: result.ref,
				path: result.path,
				size: result.size,
				sha: result.sha,
				binary: result.binary,
				contentOmitted: result.contentOmitted,
				...(result.omittedReason ? { omittedReason: result.omittedReason } : {}),
				content:
					result.content !== undefined
						? wrapExternalContent(redactSecrets(result.content), {
								source: "github",
								serviceId: "tc_github_read_file",
								includeRiskAssessment: true,
								maxLength: GITHUB_WRAP_MAX_CHARS,
							})
						: null,
			};
		},

		async browse(request: TelclaudeMcpBrowseRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_browse", request.actorId, webRateLimit());
			// Refuse secret-shaped URLs outbound (broker re-checks too), then fail
			// closed if no live browser is wired before reserving the rate slot.
			assertSafeWebEgress(request.url, "url");
			if (!options.browser) {
				throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse");
			}
			consumeRateLimit("web_browse", request.actorId);
			const result = await options.browser.browse({
				actor: request.actorId,
				profileId: request.profileId,
				// Server-resolved trust domain, mapped (not cast) to the browser authority
				// vocabulary — MCP 'social' → 'public-social', etc.
				authorityDomain: browserAuthorityDomainFromMcp(request.domain),
				sessionRef: request.turnConversationRef ?? request.endpointId,
				url: request.url,
				...(request.maxChars !== undefined ? { maxChars: request.maxChars } : {}),
				...(request.timeoutMs !== undefined ? { timeoutMs: request.timeoutMs } : {}),
			});
			await auditFromRequest(request, "web.browse", {
				url: redactSecrets(request.url),
				finalUrl: redactSecrets(result.finalUrl),
				httpStatus: result.httpStatus,
				truncated: result.truncated,
			});
			return result;
		},

		async browseAct(request: TelclaudeMcpBrowserActRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_browse", request.actorId, webRateLimit());
			// Same egress preflight as a browse: refuse a secret-shaped entry URL
			// before any browser work. For a `goto` the real navigation target is the
			// submittedValues string (NOT request.url), so preflight that destination
			// too — secret-shaped or non-http(s) destinations fail closed here. (goto is
			// committing, so the executor below also refuses it inline; this guards the
			// destination before any browser/executor work regardless.)
			assertSafeWebEgress(request.url, "url");
			assertSafeBrowserGotoDestination(request.verb, request.submittedValues);
			if (!options.browserAct) {
				throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse_act");
			}
			consumeRateLimit("web_browse", request.actorId);
			// Inline browser mutation is intentionally disabled at the relay surface;
			// the typed fail-closed error tells the runtime to prepare + approve.
			await options.browserAct.act(
				browserActSurfaceRequest(request, request.verb, request.target, request.submittedValues),
			);
			throw new BrowserActInlineDisabledError();
		},

		async browseActPrepare(request: TelclaudeMcpBrowserActPrepareRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_browse", request.actorId, webRateLimit());
			assertSafeWebEgress(request.url, "url");
			// For a staged `goto`, the navigation destination is submittedValues, not
			// request.url — preflight it before any browser/executor work too.
			assertSafeBrowserGotoDestination(request.verb, request.submittedValues);
			if (!options.browserAct) {
				throw new TelclaudeLiveMcpToolNotConfiguredError("tc_browse_act_prepare");
			}
			const approverActorId = browserWriteApproverFor(browserWriteApproverActorId, request.actorId);
			consumeRateLimit("web_browse", request.actorId);
			// Pre-allocate the ledger ref. The live-page pool inside the executor is
			// keyed by it (the committer resolves the held page by this exact ref
			// later), and the ledger record is filed under the SAME ref.
			const actionRef = `effect-${crypto.randomUUID()}`;
			const surfaceRequest = browserActSurfaceRequest(
				request,
				request.verb,
				request.target,
				request.submittedValues,
			);
			// No runtime-supplied forceConfirm is threaded here: it is RELAY-set +
			// escalate-only and stripped at the bridge input boundary. A relay-side
			// escalation would construct the surface request with forceConfirm directly.
			const staged = await options.browserAct.prepareIntent({
				...surfaceRequest,
				actionRef,
			});
			const prepared = staged.prepared;
			// File the ledger record under the SAME pre-allocated ref the executor's
			// live-page pool is keyed by. If prepare throws, the pool still holds the
			// page under actionRef; nothing else references it, so the pool's TTL sweep
			// reaps it — fail-closed, no dangling commit path.
			const record = options.ledger.prepare({
				kind: "browser-write",
				ref: actionRef,
				actorId: request.actorId,
				approverActorId,
				profileId: request.profileId,
				domain: request.domain,
				sessionRef: surfaceRequest.sessionRef,
				host: prepared.host,
				originScope: prepared.originScope,
				browserCredentialRef: prepared.browserCredentialRef,
				browserCredentialCreatedAt: prepared.browserCredentialCreatedAt,
				authorityDomain: prepared.authorityDomain,
				actionVerb: request.verb,
				actionTarget: request.target ?? null,
				evidenceRevision: prepared.evidenceRevision,
				evidenceNonce: prepared.evidenceNonce,
				evidenceScreenshotHash: prepared.evidenceScreenshotHash,
				evidenceScreenshotRef: prepared.evidenceScreenshotRef,
				display: prepared.display,
				commitSignal: prepared.commitSignal,
				bindingHash: prepared.bindingHash,
				approvalRequestId: makeApprovalRequestId(),
				approvalRevision: 1,
				...(request.turnConversationRef
					? { turnConversationRef: request.turnConversationRef }
					: {}),
			});
			await requestHumanApproval(options.ledger, record, options.requestSideEffectApproval);
			await auditFromRequest(request, "web.browse_act_prepare", {
				actionRef: record.ref,
				verb: request.verb,
				// Display-only summary: verb + redacted target + origin. Never the raw
				// target/values or any token.
				display: prepared.display,
			});
			return {
				actionRef: record.ref,
				approvalRequestId: record.approvalRequestId,
				display: prepared.display,
			};
		},

		async imageGenerate(request: TelclaudeMcpImageGenerateRequest) {
			assertAuthorityMemoryBoundary(request);
			// The image service enforces and consumes the existing image_generation
			// rate limit for this actor. Quality "auto" defers to the relay's
			// configured default (the service config only models explicit tiers).
			const generated = await runMediaGeneration("tc_image_generate", () =>
				generateImage(request.prompt, {
					userId: request.actorId,
					...(request.size ? { size: request.size } : {}),
					...(request.quality && request.quality !== "auto" ? { quality: request.quality } : {}),
				}),
			);
			const attachment = mintMediaAttachmentRef("tc_image_generate", request, {
				filepath: generated.path,
				mimeType: "image/png",
				sizeBytes: generated.sizeBytes,
			});
			await auditFromRequest(request, "media.image", {
				attachmentRef: attachment.ref,
				model: generated.model,
				sizeBytes: generated.sizeBytes,
				promptChars: request.prompt.length,
			});
			return {
				attachmentRef: attachment.ref,
				sizeBytes: generated.sizeBytes,
				model: generated.model,
				...(generated.revisedPrompt ? { revisedPrompt: generated.revisedPrompt } : {}),
				expiresAt: attachment.expiresAt,
			};
		},

		async tts(request: TelclaudeMcpTtsRequest) {
			assertAuthorityMemoryBoundary(request);
			const voice = resolveTtsVoice(request.voice);
			// voiceMessage: true converts to OGG/Opus so the attachment delivers as
			// a Telegram voice message. The TTS service enforces and consumes the
			// existing tts rate limit for this actor.
			const generated = await runMediaGeneration("tc_tts", () =>
				textToSpeech(request.text, {
					userId: request.actorId,
					voiceMessage: true,
					...(voice ? { voice } : {}),
					...(request.speed !== undefined ? { speed: request.speed } : {}),
				}),
			);
			const attachment = mintMediaAttachmentRef("tc_tts", request, {
				filepath: generated.path,
				mimeType: generated.format === "mp3" ? "audio/mpeg" : `audio/${generated.format}`,
				sizeBytes: generated.sizeBytes,
			});
			await auditFromRequest(request, "media.tts", {
				attachmentRef: attachment.ref,
				format: generated.format,
				voice: generated.voice,
				sizeBytes: generated.sizeBytes,
				textChars: request.text.length,
			});
			return {
				attachmentRef: attachment.ref,
				sizeBytes: generated.sizeBytes,
				format: generated.format,
				voice: generated.voice,
				estimatedDurationSeconds: generated.estimatedDurationSeconds,
				expiresAt: attachment.expiresAt,
			};
		},

		async skillRequest(request: TelclaudeMcpSkillRequestRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("skill_request", request.actorId, SKILL_REQUEST_RATE_LIMIT);
			// System-on-behalf-of-hermes producer: the standard non-signed upsert
			// path local scans use, with producerId recording the authority actor.
			// The fingerprint dedupes repeated requests for the same skill into one
			// open Curator item. Filing never installs anything — the operator
			// decides via /curator, and the proposed catalogInstall deliberately
			// carries no sourceDir/upstreamRel, so the model cannot name an install
			// source.
			const item = upsertCuratorItem({
				fingerprint: `skill_request:${request.skillName}:v1`,
				kind: "skill_review",
				severity: "info",
				source: "hermes-live-mcp",
				title: `Hermes skill request: ${request.skillName}`,
				summary: `The ${request.domain} Hermes runtime (profile ${request.profileId}) requested skill "${request.skillName}" for the relay catalog.`,
				rationale: request.rationale,
				entityRef: `skill-catalog:${request.skillName}`,
				proposedAction: {
					catalogInstall: {
						skillName: request.skillName,
						...(request.sourceHint ? { sourceHint: request.sourceHint } : {}),
						requestedBy: request.actorId,
					},
				},
				evidence: {
					rationale: request.rationale,
					...(request.sourceHint ? { sourceHint: request.sourceHint } : {}),
					domain: request.domain,
					profileId: request.profileId,
					endpointId: request.endpointId,
				},
				producerKind: "system",
				producerId: request.actorId,
			});
			consumeRateLimit("skill_request", request.actorId);
			await auditFromRequest(request, "skill.request", {
				curatorItemId: item.id,
				shortId: item.shortId,
				skillName: request.skillName,
				itemStatus: item.status,
			});
			return {
				curatorItemId: item.id,
				shortId: item.shortId,
				status: "filed",
				note: "Filed as a Curator review item. The operator reviews skill requests via /curator (or `telclaude curator list`); nothing is installed or changed automatically.",
			};
		},

		async scheduleCreate(request: TelclaudeMcpScheduleCreateRequest) {
			assertAuthorityMemoryBoundary(request);
			if (request.domain === "household") {
				const context = householdReminderContext(request, options.householdReminderConfig);
				const schedule = householdOneShotSchedule(request.schedule);
				guardMediaDerivedAction(options.mediaActionConfirmationGate, request, {
					toolName: "tc_schedule_create",
					params: {
						text: request.prompt,
						...(request.label ? { label: request.label } : {}),
						schedule,
					},
				});
				const prepared = prepareHouseholdReminderCreate({
					...context,
					text: request.prompt,
					...(request.label ? { label: request.label } : {}),
					source: { kind: "parent" },
					schedule,
				});
				await auditFromRequest(request, "schedule.create", {
					reminderId: prepared.reminder.id,
					revision: prepared.reminder.revision,
					proposalHash: prepared.proposal.proposalHash,
					status: prepared.reminder.status,
				});
				return householdProposalView(
					prepared.reminder,
					prepared.proposal.action,
					context.addresseeGender,
				);
			}
			// ownerId + delivery target are resolved SERVER-SIDE from the authority.
			// The agent's input never carries an ownerId/chatId/threadId/deliveryTarget.
			const ownerId = resolveScheduleOwnerOrThrow(resolveScheduleOwner, request);
			const schedule = normalizeScheduleInput(request.schedule);
			const job = addCronJob({
				name: scheduleJobName(request.prompt, request.label),
				ownerId,
				// Forced home delivery: a same-authority reminder to the operator's
				// own home target. The agent cannot redirect this to another chat.
				deliveryTarget: { kind: "home" },
				schedule,
				action: { kind: "agent-prompt", prompt: request.prompt },
			});
			await auditFromRequest(request, "schedule.create", {
				jobId: job.id,
				scheduleKind: schedule.kind,
				promptChars: request.prompt.length,
			});
			return scheduleJobView(job);
		},

		async scheduleList(request: TelclaudeMcpScheduleListRequest) {
			assertAuthorityMemoryBoundary(request);
			if (request.domain === "household") {
				const context = householdReminderContext(request, options.householdReminderConfig);
				const reminders = listHouseholdReminders(context.authority).slice(0, request.limit);
				await auditFromRequest(request, "schedule.list", { count: reminders.length });
				return { reminders: reminders.map(householdReminderView) };
			}
			// Scope strictly to the authority's own owner. No home target means no
			// owned jobs — return an empty list rather than failing.
			const ownerId = resolveScheduleOwner(request)?.ownerId;
			const jobs = ownerId
				? listCronJobs({ includeDisabled: true })
						.filter((job) => job.ownerId === ownerId && job.action.kind === "agent-prompt")
						.slice(0, request.limit)
				: [];
			await auditFromRequest(request, "schedule.list", { count: jobs.length });
			return { jobs: jobs.map(scheduleJobView) };
		},

		async scheduleCancel(request: TelclaudeMcpScheduleCancelRequest) {
			assertAuthorityMemoryBoundary(request);
			if (request.domain === "household") {
				const context = householdReminderContext(request, options.householdReminderConfig);
				guardMediaDerivedAction(options.mediaActionConfirmationGate, request, {
					toolName: "tc_schedule_cancel",
					params: { reminderId: request.jobId },
				});
				const prepared = prepareHouseholdReminderCancellation({
					...context,
					reminderId: request.jobId,
				});
				await auditFromRequest(request, "schedule.cancel", {
					reminderId: prepared.reminder.id,
					revision: prepared.reminder.revision,
					proposalHash: prepared.proposal.proposalHash,
					status: prepared.reminder.status,
				});
				return householdProposalView(
					prepared.reminder,
					prepared.proposal.action,
					context.addresseeGender,
				);
			}
			const ownerId = resolveScheduleOwnerOrThrow(resolveScheduleOwner, request);
			const job = getCronJob(request.jobId);
			// Ownership check: a job owned by a different owner (or absent) fails
			// closed with an identical not-found error — the agent learns nothing
			// about other owners' jobs.
			if (!job || job.ownerId !== ownerId) {
				throw new TelclaudeLiveMcpScheduleNotFoundError();
			}
			const removed = removeCronJob(request.jobId);
			await auditFromRequest(request, "schedule.cancel", {
				jobId: request.jobId,
				removed,
			});
			return { jobId: request.jobId, cancelled: removed };
		},

		async scheduleUpdate(request: TelclaudeMcpScheduleUpdateRequest) {
			assertAuthorityMemoryBoundary(request);
			if (request.domain !== "household") {
				throw new TelclaudeLiveMcpScheduleValidationError(
					"tc_schedule_update is available only for household reminders",
				);
			}
			const context = householdReminderContext(request, options.householdReminderConfig);
			const schedule = householdOneShotSchedule(request.schedule);
			guardMediaDerivedAction(options.mediaActionConfirmationGate, request, {
				toolName: "tc_schedule_update",
				params: {
					reminderId: request.jobId,
					text: request.prompt,
					...(request.label ? { label: request.label } : {}),
					schedule,
				},
			});
			const prepared = prepareHouseholdReminderUpdate({
				...context,
				reminderId: request.jobId,
				text: request.prompt,
				...(request.label ? { label: request.label } : {}),
				schedule,
			});
			await auditFromRequest(request, "schedule.update", {
				reminderId: prepared.reminder.id,
				revision: prepared.reminder.revision,
				proposalHash: prepared.proposal.proposalHash,
				status: prepared.reminder.status,
			});
			return householdProposalView(
				prepared.reminder,
				prepared.proposal.action,
				context.addresseeGender,
			);
		},
	};
}

function householdReminderContext(
	request: TelclaudeMcpAuthorityStamp,
	config: TelclaudeConfig | undefined,
): HouseholdReminderContext {
	const subjectUserId = optionalTrimmed(request.subjectUserId);
	if (!subjectUserId) throw new Error("household reminder subject binding required");
	const context = resolveHouseholdReminderContext(
		{
			actorId: request.actorId,
			subjectUserId,
			profileId: request.profileId,
		},
		config ?? loadConfig(),
	);
	if (!context) throw new Error("household reminder binding or consent is unavailable");
	return context;
}

function guardMediaDerivedAction(
	gate: MediaActionConfirmationGate | undefined,
	request: TelclaudeMcpAuthorityStamp,
	action: { readonly toolName: MediaActionToolName; readonly params: Record<string, unknown> },
): void {
	if (
		!gate ||
		request.domain !== "household" ||
		!request.turnConversationRef ||
		!request.subjectUserId
	) {
		return;
	}
	const result = gate.guardConsequentialAction({
		turnRef: request.turnConversationRef,
		authority: {
			actorId: request.actorId,
			subjectUserId: request.subjectUserId,
			profileId: request.profileId,
		},
		action,
	});
	if (result.required) throw new MediaActionConfirmationRequiredError();
}

function householdOneShotSchedule(schedule: TelclaudeMcpScheduleInput) {
	if (schedule.kind !== "at") {
		throw new TelclaudeLiveMcpScheduleValidationError(
			`household recurring reminders are not available. ${HOUSEHOLD_REMINDER_RECURRING_DECLINE_HE}`,
		);
	}
	try {
		return resolveJerusalemOneShot(schedule.at);
	} catch (error) {
		throw new TelclaudeLiveMcpScheduleValidationError(
			error instanceof Error ? error.message : String(error),
		);
	}
}

function householdProposalView(
	reminder: HouseholdReminder,
	action: "create" | "update" | "cancel",
	addresseeGender: "f" | "m",
) {
	return {
		reminderId: reminder.id,
		revision: reminder.revision,
		status: reminder.status,
		confirmationRequired: true,
		confirmationPrompt: householdReminderProposalPrompt(action, reminder, addresseeGender),
	};
}

function householdReminderView(reminder: HouseholdReminder) {
	return {
		reminderId: reminder.id,
		revision: reminder.revision,
		status: reminder.status,
		text: reminder.text,
		...(reminder.label ? { label: reminder.label } : {}),
		localDateTime: reminder.schedule.localDateTime,
		timeZone: reminder.schedule.timeZone,
	};
}

const TTS_VOICES = ["alloy", "echo", "fable", "onyx", "nova", "shimmer"] as const;
type TtsVoice = (typeof TTS_VOICES)[number];

function resolveTtsVoice(voice: string | undefined): TtsVoice | undefined {
	if (voice === undefined) return undefined;
	if (!(TTS_VOICES as readonly string[]).includes(voice)) {
		throw new Error(
			`tts voice not supported: ${voice}. Supported voices: ${TTS_VOICES.join(", ")}`,
		);
	}
	return voice as TtsVoice;
}

async function runMediaGeneration<T>(
	toolName: TelclaudeMcpToolName,
	run: () => Promise<T>,
): Promise<T> {
	try {
		return await run();
	} catch (error) {
		throw new TelclaudeLiveMcpMediaGenerationError(toolName, error);
	}
}

/**
 * Mint a relay-owned attachment ref for generated media. The providerId binds
 * the ref to the producing tool AND the authority's conversation domain; the
 * ref HMAC covers both alongside the actor, so a ref minted for one actor or
 * domain cannot be re-presented for another. The runtime only ever sees the
 * ref token — never the filepath or raw bytes.
 */
function mintMediaAttachmentRef(
	toolName: "tc_image_generate" | "tc_tts",
	request: Pick<TelclaudeMcpAuthorityStamp, "actorId" | "domain">,
	media: { filepath: string; mimeType: string; sizeBytes: number },
): StoredAttachmentRef {
	return createAttachmentRef({
		actorUserId: request.actorId,
		providerId: `${toolName}:${request.domain}`,
		filepath: media.filepath,
		filename: path.basename(media.filepath),
		mimeType: media.mimeType,
		size: media.sizeBytes,
	});
}

/**
 * SSRF-guarded web fetch for tc_web_fetch: DNS-pinned fetch with redirect
 * re-validation, a content-type allowlist, byte/char truncation, secret
 * redaction, and an untrusted-content risk wrap.
 */
async function fetchWebContent(request: TelclaudeMcpWebFetchRequest): Promise<{
	url: string;
	finalUrl: string;
	httpStatus: number;
	contentType: string;
	content: string;
	truncated: boolean;
}> {
	const result = await fetchWithGuard({
		url: request.url,
		timeoutMs: request.timeoutMs ?? DEFAULT_WEB_FETCH_TIMEOUT_MS,
		auditContext: "hermes-mcp-web-fetch",
	});
	try {
		const contentType = result.response.headers.get("content-type") ?? "";
		if (!isAllowedWebContentType(contentType)) {
			try {
				await result.response.body?.cancel();
			} catch {
				// The body is being discarded; cancellation failures are irrelevant.
			}
			throw new TelclaudeLiveMcpUnsupportedContentError(contentType);
		}
		const { text, bytesTruncated } = await readBodyUtf8(
			result.response,
			request.maxChars * WEB_FETCH_BYTES_PER_CHAR,
		);
		const truncated = bytesTruncated || text.length > request.maxChars;
		const content = wrapExternalContent(redactSecrets(text.slice(0, request.maxChars)), {
			source: "web-fetch",
			serviceId: "tc_web_fetch",
			includeRiskAssessment: true,
			maxLength: request.maxChars,
		});
		return {
			url: request.url,
			finalUrl: result.finalUrl,
			httpStatus: result.response.status,
			contentType,
			content,
			truncated,
		};
	} finally {
		await result.release();
	}
}

function isAllowedWebContentType(contentType: string): boolean {
	const mime = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
	if (!mime) return false;
	if (mime.startsWith("text/")) return true;
	return mime === "application/json" || mime === "application/xhtml+xml";
}

async function readBodyUtf8(
	response: Response,
	maxBytes: number,
): Promise<{ text: string; bytesTruncated: boolean }> {
	const body = response.body;
	if (!body) return { text: "", bytesTruncated: false };

	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let bytesTruncated = false;
	try {
		while (total < maxBytes) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value || value.byteLength === 0) continue;
			const remaining = maxBytes - total;
			if (value.byteLength >= remaining) {
				chunks.push(value.subarray(0, remaining));
				total += remaining;
				bytesTruncated = true;
				break;
			}
			chunks.push(value);
			total += value.byteLength;
		}
	} finally {
		if (bytesTruncated) {
			try {
				await reader.cancel();
			} catch {
				// Body already capped; cancellation failures are irrelevant.
			}
		}
	}

	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return { text: new TextDecoder("utf-8").decode(bytes), bytesTruncated };
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
		"service" | "action" | "params" | "subjectUserId"
	>,
): { service: string; action: string; params: Record<string, unknown>; subjectUserId?: string } {
	return {
		service: request.service,
		action: request.action,
		params: request.params,
		...(request.subjectUserId ? { subjectUserId: request.subjectUserId } : {}),
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

function resolveOutboundReplyIntent(
	request: TelclaudeMcpOutboundPrepareRequest,
	conversation: RelayConversation,
	turn: RelayConversationInboundTurn,
): RelayConversationReplyIntent {
	if (request.domain !== "household") {
		return request.replyIntent ?? defaultReplyIntent(conversation);
	}
	const expected: RelayConversationReplyIntent = {
		kind: "address",
		addressRef: turn.senderPrincipalId,
	};
	if (
		request.replyIntent &&
		(request.replyIntent.kind !== "address" ||
			request.replyIntent.addressRef !== expected.addressRef)
	) {
		throw new Error("household outbound reply intent must match the current sender address");
	}
	return expected;
}

async function resolveLiveHouseholdReplyBinding(
	resolver: WhatsAppHouseholdReplyBindingResolver | undefined,
	request: TelclaudeMcpOutboundPrepareRequest,
	conversation: RelayConversation,
	turn: RelayConversationInboundTurn,
	replyIntent: RelayConversationReplyIntent,
): Promise<TelclaudeMcpHouseholdReplyBinding> {
	const subjectUserId = optionalTrimmed(request.subjectUserId);
	if (!subjectUserId) {
		throw new Error("household outbound subject binding required");
	}
	if (!resolver) {
		throw new Error("household reply binding resolver is not configured");
	}
	let resolved: Awaited<ReturnType<WhatsAppHouseholdReplyBindingResolver>>;
	try {
		resolved = await resolver({
			actorId: request.actorId,
			subjectUserId,
			profileId: request.profileId,
		});
	} catch (error) {
		throw new Error(
			`household reply binding unavailable: ${redactSecrets(error instanceof Error ? error.message : String(error))}`,
		);
	}
	if (
		!resolved ||
		resolved.revoked ||
		!resolved.pairingAttested ||
		resolved.identityAssurance !== "strong_link" ||
		resolved.actorId !== request.actorId ||
		resolved.subjectUserId !== subjectUserId ||
		resolved.profileId !== request.profileId
	) {
		throw new Error("household reply binding unavailable or mismatched");
	}
	const actorSeat = targetableRelayConversationMembers(conversation).find(
		(member) => member.actorId === request.actorId,
	);
	if (
		conversation.humanPairingProvenance !== true ||
		!actorSeat ||
		actorSeat.revoked ||
		actorSeat.identityAssurance !== "strong_link" ||
		!actorSeat.scopes.includes("message:reply") ||
		actorSeat.principalId !== turn.senderPrincipalId ||
		actorSeat.principalId !== resolved.principalId ||
		resolved.replyPrincipalId !== resolved.principalId ||
		replyIntent.kind !== "address" ||
		replyIntent.addressRef !== resolved.replyPrincipalId
	) {
		throw new Error("household reply binding does not match the live conversation");
	}
	return {
		bindingId: resolved.bindingId,
		subjectUserId,
		senderPrincipalHash: householdPrincipalHash(actorSeat.principalHash),
		recipientPrincipalHash: householdPrincipalHash(actorSeat.principalHash),
		identityAssurance: "strong_link",
	};
}

function householdPrincipalHash(value: string): `sha256:${string}` {
	if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
		throw new Error("household reply binding principal hash is invalid");
	}
	return value as `sha256:${string}`;
}

async function defaultResolveOutboundMediaRefs(
	refs: readonly string[],
): Promise<readonly EdgeAttachmentRef[]> {
	if (refs.length > 0) {
		throw new Error("outbound mediaRefs require an edge attachment resolver");
	}
	return [];
}

/** Minimum recurring interval for an "every" schedule. */
const SCHEDULE_EVERY_FLOOR_MS = 60_000;

/**
 * Resolve the schedule owner from the authority's subjectUserId (the operator's
 * resolved local-user id / home-target key) and confirm a home target exists.
 * Returns null when no home target is registered for that owner.
 *
 * The authority's subjectUserId is server-stamped: for a linked chat it is the
 * localUserId (which is exactly the home-target key), so a one-to-one match
 * confirms the operator owns a home target. The agent cannot influence it.
 */
function defaultResolveScheduleOwner(
	request: TelclaudeMcpAuthorityStamp,
): { readonly ownerId: string } | null {
	const candidate = request.subjectUserId?.trim();
	if (!candidate) return null;
	if (!getHomeTarget(candidate)) return null;
	return { ownerId: candidate };
}

function resolveScheduleOwnerOrThrow(
	resolver: ScheduleOwnerResolver,
	request: TelclaudeMcpAuthorityStamp,
): string {
	const resolved = resolver(request);
	const ownerId = resolved?.ownerId.trim();
	if (!ownerId) {
		throw new TelclaudeLiveMcpScheduleOwnerError();
	}
	return ownerId;
}

/**
 * Validate and normalize an agent-supplied schedule. addCronJob performs the
 * authoritative checks (future "at", positive everyMs, parseable cron); this
 * adds a friendlier error surface plus a sane recurring-interval floor and an
 * up-front cron-shape check so a malformed expression fails before the store.
 */
function normalizeScheduleInput(schedule: CronSchedule): CronSchedule {
	switch (schedule.kind) {
		case "at": {
			// Make the documented "no offset = UTC" contract deterministic. JS
			// Date.parse treats a no-offset date-TIME as process-local, so a
			// date-time without a trailing Z/±HH:MM offset gets an explicit Z
			// appended before parsing (date-only forms are already UTC per spec).
			// Without this the result would silently depend on the container TZ.
			const trimmed = schedule.at.trim();
			const hasOffset = /([Zz]|[+-]\d{2}:?\d{2})$/.test(trimmed);
			const atInput = !hasOffset && trimmed.includes("T") ? `${trimmed}Z` : trimmed;
			const atMs = Date.parse(atInput);
			if (!Number.isFinite(atMs)) {
				throw new TelclaudeLiveMcpScheduleValidationError(
					"`at` must be an ISO-8601 timestamp (e.g. 2026-06-18T09:00:00Z; interpreted as UTC if no offset)",
				);
			}
			if (atMs <= Date.now()) {
				throw new TelclaudeLiveMcpScheduleValidationError("`at` timestamp must be in the future");
			}
			return { kind: "at", at: new Date(atMs).toISOString() };
		}
		case "every": {
			if (!Number.isFinite(schedule.everyMs) || schedule.everyMs < SCHEDULE_EVERY_FLOOR_MS) {
				throw new TelclaudeLiveMcpScheduleValidationError(
					`\`every\` interval must be at least ${SCHEDULE_EVERY_FLOOR_MS}ms`,
				);
			}
			return { kind: "every", everyMs: Math.trunc(schedule.everyMs) };
		}
		case "cron": {
			try {
				validateCronExpression(schedule.expr);
			} catch (error) {
				throw new TelclaudeLiveMcpScheduleValidationError(sanitizedErrorMessage(error));
			}
			return { kind: "cron", expr: schedule.expr.trim() };
		}
		default: {
			const exhaustiveCheck: never = schedule;
			throw new TelclaudeLiveMcpScheduleValidationError(String(exhaustiveCheck));
		}
	}
}

function scheduleJobName(prompt: string, label: string | undefined): string {
	const base = label?.trim() || prompt.replace(/\s+/g, " ").trim().slice(0, 40);
	return `reminder - ${base}`.slice(0, 120);
}

function scheduleJobView(job: CronJob): Record<string, unknown> {
	return {
		jobId: job.id,
		name: job.name,
		enabled: job.enabled,
		schedule: job.schedule,
		prompt: job.action.kind === "agent-prompt" ? job.action.prompt : null,
		nextRunAt: job.nextRunAtMs === null ? null : new Date(job.nextRunAtMs).toISOString(),
	};
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

function assertProviderOperationPolicy(
	request: {
		readonly providerId: string;
		readonly service: string;
		readonly action: string;
		readonly params: Record<string, unknown>;
	},
	domain: TelclaudeMcpDomain,
	mode: "read" | "write",
): void {
	assertHouseholdPhase0ProviderActionAllowed({
		domain,
		service: request.service,
		action: request.action,
		mode,
	});
	if (request.service === "clalit" && containsUrgentHealthSignal(request)) {
		throw new Error("provider policy denied: urgent_health_escalation_required");
	}
}

// M5's deterministic pre-model health routing is the primary emergency boundary;
// keep this relay-side check as defense in depth for direct or malformed MCP calls.
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
		"חירום",
		"דחוף",
		"כאבים בחזה",
		"כאב בחזה",
		"קוצר נשימה",
		"קשיי נשימה",
		"שבץ",
		"אירוע מוחי",
		"התקף לב",
		"אוטם שריר הלב",
		"אובדני",
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

function browserWriteApproverFor(
	browserWriteApproverActorId: string | undefined,
	actorId: string,
): string {
	if (!browserWriteApproverActorId) {
		throw new Error("browser write approval denied: browserWriteApproverActorId is not configured");
	}
	if (browserWriteApproverActorId === actorId.trim()) {
		throw new Error(
			"browser write approval denied: browserWriteApproverActorId must differ from actorId",
		);
	}
	return browserWriteApproverActorId;
}

/** A `goto` destination that is not a parseable http(s) URL. */
class BrowserGotoDestinationError extends Error {
	readonly code = "browser_act_goto_destination_invalid";
	constructor() {
		super("browser act goto destination must be an http(s) URL string");
		this.name = "BrowserGotoDestinationError";
	}
}

class BrowserActInlineDisabledError extends Error {
	readonly code = "browser_act_inline_disabled";
	constructor() {
		super("inline browser acts are disabled; use prepare + approval + execute");
		this.name = "BrowserActInlineDisabledError";
	}
}

/**
 * For a `goto` act the navigation destination is the submittedValues string (the
 * driver does `page.goto(submittedValues)`), NOT request.url. That destination is
 * an outbound web egress target in a cookie-bearing session, so preflight it the
 * same way we preflight request.url: it must be a parseable http(s) URL AND must
 * pass the secret/private-data egress check. Fails closed before any executor or
 * browser work. No-op for every non-goto verb.
 */
function assertSafeBrowserGotoDestination(verb: string, submittedValues: unknown): void {
	if (verb !== "goto") return;
	if (typeof submittedValues !== "string") {
		throw new BrowserGotoDestinationError();
	}
	let parsed: URL;
	try {
		parsed = new URL(submittedValues);
	} catch {
		throw new BrowserGotoDestinationError();
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new BrowserGotoDestinationError();
	}
	assertSafeWebEgress(submittedValues, "goto_destination");
}

/**
 * Build the server-resolved act-surface request. Authority (actor/profile/mcp
 * domain) is taken from the relay-stamped request; the sessionRef is derived
 * server-side (the turn ref, else the endpoint id) — the runtime never names it.
 * The runtime supplies only verb/target/values + the entry url. submittedValues
 * arrives as `unknown` from the bridge; the evidence layer normalizes/rejects it.
 */
function browserActSurfaceRequest(
	request: TelclaudeMcpAuthorityStamp & { url: string; timeoutMs?: number },
	verb: BrowserActSurfaceRequest["verb"],
	target: string | undefined,
	submittedValues: unknown,
): BrowserActSurfaceRequest {
	return {
		actor: request.actorId,
		profileId: request.profileId,
		mcpDomain: request.domain,
		sessionRef: request.turnConversationRef ?? request.endpointId,
		url: request.url,
		verb,
		...(target !== undefined ? { target } : {}),
		...(submittedValues !== undefined
			? { submittedValues: submittedValues as BrowserActSurfaceRequest["submittedValues"] }
			: {}),
		...(request.timeoutMs !== undefined ? { settleTimeoutMs: request.timeoutMs } : {}),
	};
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
	readonly subjectUserId?: string;
	readonly writableNamespace: string;
}): void {
	if (request.domain === "social" || request.domain === "public") {
		if (!isSocialMemorySource(request.memorySource)) {
			throw new Error("live MCP social authority must use social memory source");
		}
		return;
	}
	if (request.domain === "household") {
		if (!isHouseholdMemorySource(request.memorySource)) {
			throw new Error("live MCP household authority must use household memory source");
		}
		if (request.subjectUserId !== request.memorySource) {
			throw new Error("live MCP household subject must equal memory source");
		}
		if (request.writableNamespace !== request.memorySource) {
			throw new Error("live MCP household namespace must equal memory source");
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
