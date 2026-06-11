import crypto from "node:crypto";
import path from "node:path";
import { loadConfig } from "../../config/config.js";
import { upsertCuratorItem } from "../../curator/store.js";
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
import { fetchWithGuard } from "../../sandbox/fetch-guard.js";
import { wrapExternalContent } from "../../security/external-content.js";
import { redactSecrets } from "../../security/output-filter.js";
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
	TelclaudeMcpImageGenerateRequest,
	TelclaudeMcpMemorySearchRequest,
	TelclaudeMcpOutboundPrepareRequest,
	TelclaudeMcpProviderPrepareWriteRequest,
	TelclaudeMcpProviderReadRequest,
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
	/** Rate limit for tc_web_fetch / tc_web_search; defaults to config `web`. */
	readonly webRateLimit?: FeatureRateLimitConfig;
	/** Injectable HTTP boundary for the web-search provider (tests only). */
	readonly webSearchFetch?: typeof fetch;
};

const ALLOWED_MEMORY_FILTER_KEYS = new Set(["categories", "trust"]);
const PROVIDER_PATH = "/v1/fetch";
const DEFAULT_WEB_FETCH_TIMEOUT_MS = 30_000;
const WEB_FETCH_BYTES_PER_CHAR = 4;
/** Filing a Curator item is cheap but operator attention is not: keep it tight. */
const SKILL_REQUEST_RATE_LIMIT: FeatureRateLimitConfig = {
	maxPerHourPerUser: 5,
	maxPerDayPerUser: 20,
};

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

export type TelclaudeMcpCapabilityClients = Pick<
	TelclaudeMcpBridgeDependencies,
	"webFetch" | "webSearch" | "imageGenerate" | "tts" | "skillRequest"
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
		async imageGenerate() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_image_generate");
		},
		async tts() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_tts");
		},
		async skillRequest() {
			throw new TelclaudeLiveMcpToolNotConfiguredError("tc_skill_request");
		},
	};
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
	const conversationStore = options.conversationStore ?? createRelayConversationStore();
	const edgeRuntime = options.edgeRuntime ?? new TelclaudeEdgeRuntime();
	const resolveOutboundMediaRefs =
		options.resolveOutboundMediaRefs ?? defaultResolveOutboundMediaRefs;
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
			await auditFromRequest(request, request.kind, request.payload);
			return { stored: true };
		},

		async webFetch(request: TelclaudeMcpWebFetchRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_fetch", request.actorId, webRateLimit());
			const fetched = await fetchWebContent(request);
			consumeRateLimit("web_fetch", request.actorId);
			await auditFromRequest(request, "web.fetch", {
				url: request.url,
				finalUrl: fetched.finalUrl,
				httpStatus: fetched.httpStatus,
				contentType: fetched.contentType,
				truncated: fetched.truncated,
			});
			return fetched;
		},

		async webSearch(request: TelclaudeMcpWebSearchRequest) {
			assertAuthorityMemoryBoundary(request);
			enforceRateLimit("web_search", request.actorId, webRateLimit());
			const found = await searchWeb(request.query, {
				count: request.count,
				...(options.webSearchFetch ? { fetchImpl: options.webSearchFetch } : {}),
			});
			const results = found.results.map((result) => ({
				title: redactSecrets(result.title),
				url: result.url,
				snippet: redactSecrets(result.snippet),
			}));
			consumeRateLimit("web_search", request.actorId);
			await auditFromRequest(request, "web.search", {
				query: request.query,
				count: request.count,
				provider: found.provider,
				resultCount: results.length,
			});
			return {
				query: request.query,
				provider: found.provider,
				results: wrapExternalContent(JSON.stringify(results, null, 2), {
					source: "web-search",
					serviceId: "tc_web_search",
					includeRiskAssessment: true,
				}),
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
