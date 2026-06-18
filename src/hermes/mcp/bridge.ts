import { z } from "zod";
import { validateMemorySource } from "../../memory/source.js";
import type { MemoryCategory, MemorySource, TrustLevel } from "../../memory/types.js";
import { validateMemoryEntryInput } from "../../memory/validation.js";
import {
	isRelayConversationToken,
	isRelayConversationTurnRef,
	type RelayConversationReplyIntent,
} from "../relay-conversation-store.js";
import {
	TELCLAUDE_MCP_SERVER_POLICY,
	TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES,
	type TelclaudeMcpCapabilityScope,
} from "./policy.js";
import { resolveTelclaudeProviderOperation } from "./provider-routing.js";

export {
	TELCLAUDE_MCP_ALL_CAPABILITY_SCOPES,
	TELCLAUDE_MCP_SERVER_POLICY,
	TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES,
	TELCLAUDE_MCP_TOOL_NAMES,
	type TelclaudeMcpCapabilityScope,
	type TelclaudeMcpToolName,
} from "./policy.js";

export type TelclaudeMcpDomain = "private" | "social" | "household" | "public" | "specialist";

export type TelclaudeMcpAuthority = {
	actorId: string;
	subjectUserId?: string;
	profileId: string;
	domain: TelclaudeMcpDomain;
	memorySource: MemorySource;
	writableNamespace: string;
	providerScopes: readonly string[];
	outboundChannels: readonly string[];
	/**
	 * Capability scopes for the capability-gated tools (web/media/skill-request).
	 * Absent or empty denies all capability tools — fail-closed.
	 */
	capabilityScopes?: readonly string[];
	endpointId: string;
	networkNamespace: string;
	turnConversationRef?: string;
};

export type TelclaudeMcpAuthorityStamp = {
	actorId: string;
	subjectUserId?: string;
	profileId: string;
	domain: TelclaudeMcpDomain;
	memorySource: MemorySource;
	writableNamespace: string;
	endpointId: string;
	networkNamespace: string;
	turnConversationRef?: string;
};

export type TelclaudeMcpProviderReadRequest = TelclaudeMcpAuthorityStamp & {
	providerId: string;
	service: string;
	action: string;
	params: Record<string, unknown>;
};

export type TelclaudeMcpProviderPrepareWriteRequest = TelclaudeMcpAuthorityStamp & {
	providerId: string;
	service: string;
	action: string;
	params: Record<string, unknown>;
	idempotencyKey?: string;
};

export type TelclaudeMcpProviderExecuteWriteRequest = TelclaudeMcpAuthorityStamp & {
	actionRef: string;
	providerScopes: readonly string[];
};

export type TelclaudeMcpMemorySearchRequest = TelclaudeMcpAuthorityStamp & {
	query: string;
	filters?: Record<string, unknown>;
	limit: number;
};

export type TelclaudeMcpMemoryWriteRequest = TelclaudeMcpAuthorityStamp & {
	id: string;
	category: MemoryCategory;
	content: string;
	metadata?: Record<string, unknown>;
	trust: TrustLevel;
};

export type TelclaudeMcpAttachmentGetRequest = TelclaudeMcpAuthorityStamp & {
	ref: string;
};

export type TelclaudeMcpOutboundPrepareRequest = TelclaudeMcpAuthorityStamp & {
	conversationToken: string;
	replyIntent?: RelayConversationReplyIntent;
	body: string;
	mediaRefs: string[];
	outboundChannels: readonly string[];
};

export type TelclaudeMcpOutboundExecuteRequest = TelclaudeMcpAuthorityStamp & {
	outboundRef: string;
	outboundChannels: readonly string[];
};

export type TelclaudeMcpAuditNoteRequest = TelclaudeMcpAuthorityStamp & {
	kind: string;
	payload: Record<string, unknown>;
};

export type TelclaudeMcpWebFetchRequest = TelclaudeMcpAuthorityStamp & {
	url: string;
	maxChars: number;
	timeoutMs?: number;
};

export type TelclaudeMcpWebSearchRequest = TelclaudeMcpAuthorityStamp & {
	query: string;
	count: number;
};

export type TelclaudeMcpBrowseRequest = TelclaudeMcpAuthorityStamp & {
	url: string;
	maxChars?: number;
	timeoutMs?: number;
};

export type TelclaudeMcpImageGenerateRequest = TelclaudeMcpAuthorityStamp & {
	prompt: string;
	size?: "1024x1024" | "1536x1024" | "1024x1536" | "auto";
	quality?: "low" | "medium" | "high" | "auto";
};

export type TelclaudeMcpTtsRequest = TelclaudeMcpAuthorityStamp & {
	text: string;
	voice?: string;
	speed?: number;
};

export type TelclaudeMcpSkillRequestRequest = TelclaudeMcpAuthorityStamp & {
	skillName: string;
	rationale: string;
	sourceHint?: string;
};

export type TelclaudeMcpScheduleInput =
	| { kind: "at"; at: string }
	| { kind: "every"; everyMs: number }
	| { kind: "cron"; expr: string };

export type TelclaudeMcpScheduleCreateRequest = TelclaudeMcpAuthorityStamp & {
	schedule: TelclaudeMcpScheduleInput;
	prompt: string;
	label?: string;
};

export type TelclaudeMcpScheduleListRequest = TelclaudeMcpAuthorityStamp & {
	limit: number;
};

export type TelclaudeMcpScheduleCancelRequest = TelclaudeMcpAuthorityStamp & {
	jobId: string;
};

export type TelclaudeMcpBridgeDependencies = {
	providerRead(request: TelclaudeMcpProviderReadRequest): Promise<unknown>;
	providerPrepareWrite(request: TelclaudeMcpProviderPrepareWriteRequest): Promise<unknown>;
	providerExecuteWrite(request: TelclaudeMcpProviderExecuteWriteRequest): Promise<unknown>;
	memorySearch(request: TelclaudeMcpMemorySearchRequest): Promise<unknown>;
	memoryWrite(request: TelclaudeMcpMemoryWriteRequest): Promise<unknown>;
	attachmentGet(request: TelclaudeMcpAttachmentGetRequest): Promise<unknown>;
	outboundPrepare(request: TelclaudeMcpOutboundPrepareRequest): Promise<unknown>;
	outboundExecute(request: TelclaudeMcpOutboundExecuteRequest): Promise<unknown>;
	auditNote(request: TelclaudeMcpAuditNoteRequest): Promise<unknown>;
	webFetch(request: TelclaudeMcpWebFetchRequest): Promise<unknown>;
	webSearch(request: TelclaudeMcpWebSearchRequest): Promise<unknown>;
	browse(request: TelclaudeMcpBrowseRequest): Promise<unknown>;
	imageGenerate(request: TelclaudeMcpImageGenerateRequest): Promise<unknown>;
	tts(request: TelclaudeMcpTtsRequest): Promise<unknown>;
	skillRequest(request: TelclaudeMcpSkillRequestRequest): Promise<unknown>;
	scheduleCreate(request: TelclaudeMcpScheduleCreateRequest): Promise<unknown>;
	scheduleList(request: TelclaudeMcpScheduleListRequest): Promise<unknown>;
	scheduleCancel(request: TelclaudeMcpScheduleCancelRequest): Promise<unknown>;
};

export type TelclaudeMcpBridge = {
	readonly policy: typeof TELCLAUDE_MCP_SERVER_POLICY;
	tc_provider_read(input: unknown): Promise<unknown>;
	tc_provider_prepare_write(input: unknown): Promise<unknown>;
	tc_provider_execute_write(input: unknown): Promise<unknown>;
	tc_memory_search(input: unknown): Promise<unknown>;
	tc_memory_write(input: unknown): Promise<unknown>;
	tc_attachment_get(input: unknown): Promise<unknown>;
	tc_outbound_prepare(input: unknown): Promise<unknown>;
	tc_outbound_execute(input: unknown): Promise<unknown>;
	tc_audit_note(input: unknown): Promise<unknown>;
	tc_web_fetch(input: unknown): Promise<unknown>;
	tc_web_search(input: unknown): Promise<unknown>;
	tc_browse(input: unknown): Promise<unknown>;
	tc_image_generate(input: unknown): Promise<unknown>;
	tc_tts(input: unknown): Promise<unknown>;
	tc_skill_request(input: unknown): Promise<unknown>;
	tc_schedule_create(input: unknown): Promise<unknown>;
	tc_schedule_list(input: unknown): Promise<unknown>;
	tc_schedule_cancel(input: unknown): Promise<unknown>;
};

const NonEmptyString = z.string().trim().min(1);
const JsonObjectSchema = z.record(z.string(), z.unknown());
const RefSchema = NonEmptyString.max(256);
const MAX_MEMORY_SEARCH_LIMIT = 20;
const DEFAULT_MEMORY_SEARCH_LIMIT = 10;

const ProviderReadInputSchema = z
	.object({
		providerId: NonEmptyString.optional(),
		service: NonEmptyString,
		action: NonEmptyString,
		params: JsonObjectSchema.optional(),
	})
	.strip();

const ProviderPrepareWriteInputSchema = z
	.object({
		providerId: NonEmptyString.optional(),
		service: NonEmptyString,
		action: NonEmptyString,
		params: JsonObjectSchema.optional(),
		idempotencyKey: NonEmptyString.max(128).optional(),
	})
	.strip();

const ProviderExecuteWriteInputSchema = z
	.object({
		actionRef: RefSchema,
	})
	.strict();

const MemorySearchInputSchema = z
	.object({
		query: NonEmptyString,
		filters: JsonObjectSchema.optional(),
		limit: z.number().int().min(1).max(MAX_MEMORY_SEARCH_LIMIT).optional(),
	})
	.strip();

const MemoryWriteInputSchema = z
	.object({
		id: NonEmptyString.max(128),
		category: z.enum(["profile", "interests", "threads", "posts", "meta"]),
		content: NonEmptyString,
		metadata: JsonObjectSchema.optional(),
		provenance: JsonObjectSchema.optional(),
	})
	.strip();

const AttachmentGetInputSchema = z
	.object({
		ref: RefSchema,
	})
	.strip();

const ReplyIntentInputSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("thread"),
			threadId: RefSchema,
		})
		.strict(),
	z
		.object({
			kind: z.literal("actor"),
			actorId: RefSchema,
		})
		.strict(),
	z
		.object({
			kind: z.literal("address"),
			addressRef: RefSchema,
		})
		.strict(),
]);

const OutboundPrepareInputSchema = z
	.object({
		conversationToken: RefSchema.refine(isRelayConversationToken, "invalid conversation token"),
		replyIntent: ReplyIntentInputSchema.optional(),
		body: NonEmptyString,
		mediaRefs: z.array(RefSchema).max(10).optional(),
	})
	.strict();

const OutboundExecuteInputSchema = z
	.object({
		outboundRef: RefSchema,
	})
	.strict();

const AuditNoteInputSchema = z
	.object({
		kind: NonEmptyString.max(128),
		payload: JsonObjectSchema.optional(),
	})
	.strip();

const WebFetchInputSchema = z
	.object({
		url: z.url({ protocol: /^https?$/ }).max(2048),
		maxChars: z.number().int().min(1).max(200_000).default(50_000),
		timeoutMs: z.number().int().min(1_000).max(60_000).optional(),
	})
	.strip();

const WebSearchInputSchema = z
	.object({
		query: NonEmptyString.max(512),
		count: z.number().int().min(1).max(10).default(5),
	})
	.strip();

const BrowseInputSchema = z
	.object({
		url: z.url({ protocol: /^https?$/ }).max(2048),
		maxChars: z.number().int().min(1).max(200_000).optional(),
		timeoutMs: z.number().int().min(1_000).max(120_000).optional(),
	})
	.strip();

const ImageGenerateInputSchema = z
	.object({
		prompt: NonEmptyString.max(4_000),
		size: z.enum(["1024x1024", "1536x1024", "1024x1536", "auto"]).optional(),
		quality: z.enum(["low", "medium", "high", "auto"]).optional(),
	})
	.strip();

const TtsInputSchema = z
	.object({
		text: NonEmptyString.max(4_000),
		voice: NonEmptyString.max(64).optional(),
		speed: z.number().min(0.5).max(2).optional(),
	})
	.strip();

const SkillRequestInputSchema = z
	.object({
		skillName: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
		rationale: NonEmptyString.max(2_000),
		sourceHint: NonEmptyString.max(500).optional(),
	})
	.strip();

const ScheduleInputSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("at"),
			at: NonEmptyString.max(64),
		})
		.strict(),
	z
		.object({
			kind: z.literal("every"),
			everyMs: z.number().int().min(1),
		})
		.strict(),
	z
		.object({
			kind: z.literal("cron"),
			expr: NonEmptyString.max(128),
		})
		.strict(),
]);

const ScheduleCreateInputSchema = z
	.object({
		schedule: ScheduleInputSchema,
		prompt: NonEmptyString.max(2_000),
		label: NonEmptyString.max(80).optional(),
	})
	.strip();

const ScheduleListInputSchema = z
	.object({
		limit: z.number().int().min(1).max(50).default(20),
	})
	.strip();

const ScheduleCancelInputSchema = z
	.object({
		jobId: NonEmptyString.max(128),
	})
	.strip();

const AUTHORITY_PROVENANCE_KEYS = new Set([
	"actorId",
	"subjectUserId",
	"profileId",
	"domain",
	"memorySource",
	"source",
	"sources",
	"sourceFamilies",
	"trust",
	"namespace",
	"writableNamespace",
	"providerAuthority",
	"capabilityScopes",
	"endpointId",
	"networkNamespace",
	"peerAddress",
	"turnConversationRef",
	"turnId",
	"inboundTurnId",
	"inboundTurnRef",
]);

const CLIENT_MEMORY_AUTHORITY_KEYS = new Set([
	...AUTHORITY_PROVENANCE_KEYS,
	"authority",
	"authorityHandle",
	"connection",
	"sessionKey",
]);

const CLIENT_TURN_AUTHORITY_KEYS = new Set([
	"turnConversationRef",
	"turnId",
	"inboundTurnId",
	"inboundTurnRef",
]);

export function createTelclaudeMcpBridge(
	authority: TelclaudeMcpAuthority,
	dependencies: TelclaudeMcpBridgeDependencies,
): TelclaudeMcpBridge {
	const normalizedAuthority = normalizeAuthority(authority);
	const stamp = authorityStamp(normalizedAuthority);

	return {
		policy: TELCLAUDE_MCP_SERVER_POLICY,

		async tc_provider_read(input) {
			assertNoClientTurnAuthority(input);
			const parsed = ProviderReadInputSchema.parse(input);
			const operation = resolveTelclaudeProviderOperation({
				providerId: parsed.providerId,
				service: parsed.service,
				action: parsed.action,
				params: parsed.params ?? {},
			});
			assertProviderScope(normalizedAuthority, operation.providerId);
			return dependencies.providerRead({
				...stamp,
				...operation,
			});
		},

		async tc_provider_prepare_write(input) {
			assertNoClientTurnAuthority(input);
			const parsed = ProviderPrepareWriteInputSchema.parse(input);
			const operation = resolveTelclaudeProviderOperation({
				providerId: parsed.providerId,
				service: parsed.service,
				action: parsed.action,
				params: parsed.params ?? {},
			});
			assertProviderScope(normalizedAuthority, operation.providerId);
			return dependencies.providerPrepareWrite({
				...stamp,
				...operation,
				...(parsed.idempotencyKey ? { idempotencyKey: parsed.idempotencyKey } : {}),
			});
		},

		async tc_provider_execute_write(input) {
			assertNoClientTurnAuthority(input);
			const parsed = ProviderExecuteWriteInputSchema.parse(input);
			return dependencies.providerExecuteWrite({
				...stamp,
				actionRef: parsed.actionRef,
				providerScopes: normalizedAuthority.providerScopes,
			});
		},

		async tc_memory_search(input) {
			assertNoClientTurnAuthority(input);
			assertNoClientMemoryAuthority(input);
			const parsed = MemorySearchInputSchema.parse(input);
			return dependencies.memorySearch({
				...stamp,
				query: parsed.query,
				filters: parsed.filters,
				limit: parsed.limit ?? DEFAULT_MEMORY_SEARCH_LIMIT,
			});
		},

		async tc_memory_write(input) {
			assertNoClientTurnAuthority(input);
			assertNoClientMemoryAuthority(input);
			const parsed = MemoryWriteInputSchema.parse(input);
			assertMetadataOnlyProvenance(parsed.provenance);
			const request: TelclaudeMcpMemoryWriteRequest = {
				...stamp,
				id: parsed.id,
				category: parsed.category,
				content: parsed.content,
				metadata: parsed.metadata,
				trust: trustForDomain(stamp.domain),
			};
			const validationError = validateMemoryEntryInput({
				id: request.id,
				category: request.category,
				content: request.content,
				metadata: request.metadata,
			});
			if (validationError) {
				throw new Error(validationError);
			}
			return dependencies.memoryWrite(request);
		},

		async tc_attachment_get(input) {
			assertNoClientTurnAuthority(input);
			const parsed = AttachmentGetInputSchema.parse(input);
			return dependencies.attachmentGet({ ...stamp, ref: parsed.ref });
		},

		async tc_outbound_prepare(input) {
			assertNoClientTurnAuthority(input);
			const parsed = OutboundPrepareInputSchema.parse(input);
			return dependencies.outboundPrepare({
				...stamp,
				conversationToken: parsed.conversationToken,
				replyIntent: parsed.replyIntent,
				body: parsed.body,
				mediaRefs: parsed.mediaRefs ?? [],
				outboundChannels: normalizedAuthority.outboundChannels,
			});
		},

		async tc_outbound_execute(input) {
			assertNoClientTurnAuthority(input);
			const parsed = OutboundExecuteInputSchema.parse(input);
			return dependencies.outboundExecute({
				...stamp,
				outboundRef: parsed.outboundRef,
				outboundChannels: normalizedAuthority.outboundChannels,
			});
		},

		async tc_audit_note(input) {
			assertNoClientTurnAuthority(input);
			const parsed = AuditNoteInputSchema.parse(input);
			return dependencies.auditNote({
				...stamp,
				kind: parsed.kind,
				payload: parsed.payload ?? {},
			});
		},

		async tc_web_fetch(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(normalizedAuthority, TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_web_fetch);
			const parsed = WebFetchInputSchema.parse(input);
			return dependencies.webFetch({
				...stamp,
				url: parsed.url,
				maxChars: parsed.maxChars,
				...(parsed.timeoutMs !== undefined ? { timeoutMs: parsed.timeoutMs } : {}),
			});
		},

		async tc_web_search(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(
				normalizedAuthority,
				TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_web_search,
			);
			const parsed = WebSearchInputSchema.parse(input);
			return dependencies.webSearch({
				...stamp,
				query: parsed.query,
				count: parsed.count,
			});
		},

		async tc_browse(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(normalizedAuthority, TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_browse);
			const parsed = BrowseInputSchema.parse(input);
			return dependencies.browse({
				...stamp,
				url: parsed.url,
				...(parsed.maxChars !== undefined ? { maxChars: parsed.maxChars } : {}),
				...(parsed.timeoutMs !== undefined ? { timeoutMs: parsed.timeoutMs } : {}),
			});
		},

		async tc_image_generate(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(
				normalizedAuthority,
				TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_image_generate,
			);
			const parsed = ImageGenerateInputSchema.parse(input);
			return dependencies.imageGenerate({
				...stamp,
				prompt: parsed.prompt,
				...(parsed.size ? { size: parsed.size } : {}),
				...(parsed.quality ? { quality: parsed.quality } : {}),
			});
		},

		async tc_tts(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(normalizedAuthority, TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_tts);
			const parsed = TtsInputSchema.parse(input);
			return dependencies.tts({
				...stamp,
				text: parsed.text,
				...(parsed.voice ? { voice: parsed.voice } : {}),
				...(parsed.speed !== undefined ? { speed: parsed.speed } : {}),
			});
		},

		async tc_skill_request(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(
				normalizedAuthority,
				TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_skill_request,
			);
			const parsed = SkillRequestInputSchema.parse(input);
			return dependencies.skillRequest({
				...stamp,
				skillName: parsed.skillName,
				rationale: parsed.rationale,
				...(parsed.sourceHint ? { sourceHint: parsed.sourceHint } : {}),
			});
		},

		async tc_schedule_create(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(
				normalizedAuthority,
				TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_schedule_create,
			);
			const parsed = ScheduleCreateInputSchema.parse(input);
			return dependencies.scheduleCreate({
				...stamp,
				schedule: parsed.schedule,
				prompt: parsed.prompt,
				...(parsed.label ? { label: parsed.label } : {}),
			});
		},

		async tc_schedule_list(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(
				normalizedAuthority,
				TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_schedule_list,
			);
			const parsed = ScheduleListInputSchema.parse(input);
			return dependencies.scheduleList({ ...stamp, limit: parsed.limit });
		},

		async tc_schedule_cancel(input) {
			assertNoClientTurnAuthority(input);
			assertCapabilityScope(
				normalizedAuthority,
				TELCLAUDE_MCP_TOOL_CAPABILITY_SCOPES.tc_schedule_cancel,
			);
			const parsed = ScheduleCancelInputSchema.parse(input);
			return dependencies.scheduleCancel({ ...stamp, jobId: parsed.jobId });
		},
	};
}

function normalizeAuthority(authority: TelclaudeMcpAuthority): TelclaudeMcpAuthority {
	const memorySourceError = validateMemorySource(authority.memorySource);
	if (memorySourceError) {
		throw new Error(memorySourceError);
	}
	const subjectUserId = optionalTrimmed(authority.subjectUserId);
	return {
		actorId: requiredTrimmed(authority.actorId, "actorId"),
		...(subjectUserId ? { subjectUserId } : {}),
		profileId: requiredTrimmed(authority.profileId, "profileId"),
		domain: authority.domain,
		memorySource: authority.memorySource,
		writableNamespace: requiredTrimmed(authority.writableNamespace, "writableNamespace"),
		providerScopes: uniqueTrimmed(authority.providerScopes),
		outboundChannels: uniqueTrimmed(authority.outboundChannels),
		...(authority.capabilityScopes
			? { capabilityScopes: uniqueTrimmed(authority.capabilityScopes) }
			: {}),
		endpointId: requiredTrimmed(authority.endpointId, "endpointId"),
		networkNamespace: requiredTrimmed(authority.networkNamespace, "networkNamespace"),
		...(authority.turnConversationRef
			? { turnConversationRef: normalizeTurnConversationRef(authority.turnConversationRef) }
			: {}),
	};
}

function authorityStamp(authority: TelclaudeMcpAuthority): TelclaudeMcpAuthorityStamp {
	return {
		actorId: authority.actorId,
		...(authority.subjectUserId ? { subjectUserId: authority.subjectUserId } : {}),
		profileId: authority.profileId,
		domain: authority.domain,
		memorySource: authority.memorySource,
		writableNamespace: authority.writableNamespace,
		endpointId: authority.endpointId,
		networkNamespace: authority.networkNamespace,
		...(authority.turnConversationRef
			? { turnConversationRef: authority.turnConversationRef }
			: {}),
	};
}

function normalizeTurnConversationRef(value: string): string {
	const ref = value.trim();
	if (!isRelayConversationTurnRef(ref)) {
		throw new Error("MCP authority turnConversationRef must be a relay turn ref");
	}
	return ref;
}

function assertNoClientTurnAuthority(input: unknown): void {
	if (!isRecord(input)) return;
	for (const key of Object.keys(input)) {
		if (CLIENT_TURN_AUTHORITY_KEYS.has(key)) {
			throw new Error("MCP clients may not supply relay turn authority");
		}
		if (AUTHORITY_PROVENANCE_KEYS.has(key)) {
			throw new Error(`MCP clients may not supply MCP authority field: ${key}`);
		}
	}
}

function assertNoClientMemoryAuthority(input: unknown): void {
	if (!containsClientMemoryAuthority(input)) return;
	throw new Error("MCP client cannot supply memory authority fields");
}

function containsClientMemoryAuthority(value: unknown): boolean {
	if (Array.isArray(value)) {
		return value.some(containsClientMemoryAuthority);
	}
	if (!isRecord(value)) return false;
	return Object.entries(value).some(
		([key, child]) => CLIENT_MEMORY_AUTHORITY_KEYS.has(key) || containsClientMemoryAuthority(child),
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`Telclaude MCP authority ${field} is required`);
	}
	return trimmed;
}

function optionalTrimmed(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed || undefined;
}

function uniqueTrimmed(values: readonly string[]): string[] {
	return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function assertProviderScope(authority: TelclaudeMcpAuthority, service: string): void {
	if (!authority.providerScopes.includes(service)) {
		throw new Error(`provider scope denied: ${service}`);
	}
}

function assertCapabilityScope(
	authority: TelclaudeMcpAuthority,
	scope: TelclaudeMcpCapabilityScope,
): void {
	if (!authority.capabilityScopes?.includes(scope)) {
		throw new Error(`capability scope denied: ${scope}`);
	}
}

function assertMetadataOnlyProvenance(provenance: Record<string, unknown> | undefined): void {
	if (!provenance) return;
	for (const key of Object.keys(provenance)) {
		if (AUTHORITY_PROVENANCE_KEYS.has(key)) {
			throw new Error(`memory provenance cannot set authoritative field: ${key}`);
		}
	}
}

function trustForDomain(domain: TelclaudeMcpDomain): TrustLevel {
	return domain === "private" || domain === "household" ? "trusted" : "untrusted";
}
