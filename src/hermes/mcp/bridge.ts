import { z } from "zod";
import { validateMemorySource } from "../../memory/source.js";
import type { MemoryCategory, MemorySource, TrustLevel } from "../../memory/types.js";
import { validateMemoryEntryInput } from "../../memory/validation.js";

export const TELCLAUDE_MCP_TOOL_NAMES = [
	"tc_provider_read",
	"tc_provider_prepare_write",
	"tc_provider_execute_write",
	"tc_memory_search",
	"tc_memory_write",
	"tc_attachment_get",
	"tc_outbound_prepare",
	"tc_outbound_execute",
	"tc_audit_note",
] as const;

export type TelclaudeMcpToolName = (typeof TELCLAUDE_MCP_TOOL_NAMES)[number];

export const TELCLAUDE_MCP_SERVER_POLICY = {
	tools: TELCLAUDE_MCP_TOOL_NAMES,
	resources: [],
	prompts: [],
	roots: [],
	sampling: false,
	env: {},
	cwd: null,
	subprocess: false,
} as const;

export type TelclaudeMcpDomain = "private" | "social" | "household" | "public" | "specialist";

export type TelclaudeMcpAuthority = {
	actorId: string;
	profileId: string;
	domain: TelclaudeMcpDomain;
	memorySource: MemorySource;
	writableNamespace: string;
	providerScopes: readonly string[];
	outboundChannels: readonly string[];
	endpointId: string;
	networkNamespace: string;
};

export type TelclaudeMcpAuthorityStamp = {
	actorId: string;
	profileId: string;
	domain: TelclaudeMcpDomain;
	memorySource: MemorySource;
	writableNamespace: string;
	endpointId: string;
	networkNamespace: string;
};

export type TelclaudeMcpProviderReadRequest = TelclaudeMcpAuthorityStamp & {
	service: string;
	action: string;
	params: Record<string, unknown>;
};

export type TelclaudeMcpProviderPrepareWriteRequest = TelclaudeMcpAuthorityStamp & {
	service: string;
	action: string;
	params: Record<string, unknown>;
	idempotencyKey?: string;
};

export type TelclaudeMcpProviderExecuteWriteRequest = TelclaudeMcpAuthorityStamp & {
	actionRef: string;
	approvalToken: string;
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
	channel: string;
	recipient: string;
	content: string;
	mediaRefs: string[];
};

export type TelclaudeMcpOutboundExecuteRequest = TelclaudeMcpAuthorityStamp & {
	outboundRef: string;
	approvalToken: string;
};

export type TelclaudeMcpAuditNoteRequest = TelclaudeMcpAuthorityStamp & {
	kind: string;
	payload: Record<string, unknown>;
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
};

const NonEmptyString = z.string().trim().min(1);
const JsonObjectSchema = z.record(z.string(), z.unknown());
const RefSchema = NonEmptyString.max(256);
const MAX_MEMORY_SEARCH_LIMIT = 20;
const DEFAULT_MEMORY_SEARCH_LIMIT = 10;

const ProviderReadInputSchema = z
	.object({
		service: NonEmptyString,
		action: NonEmptyString,
		params: JsonObjectSchema.optional(),
	})
	.strip();

const ProviderPrepareWriteInputSchema = z
	.object({
		service: NonEmptyString,
		action: NonEmptyString,
		params: JsonObjectSchema.optional(),
		idempotencyKey: NonEmptyString.max(128).optional(),
	})
	.strip();

const ProviderExecuteWriteInputSchema = z
	.object({
		actionRef: RefSchema,
		approvalToken: NonEmptyString,
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

const OutboundPrepareInputSchema = z
	.object({
		channel: NonEmptyString,
		recipient: NonEmptyString.max(256),
		content: NonEmptyString,
		mediaRefs: z.array(RefSchema).max(10).optional(),
	})
	.strip();

const OutboundExecuteInputSchema = z
	.object({
		outboundRef: RefSchema,
		approvalToken: NonEmptyString,
	})
	.strict();

const AuditNoteInputSchema = z
	.object({
		kind: NonEmptyString.max(128),
		payload: JsonObjectSchema.optional(),
	})
	.strip();

const AUTHORITY_PROVENANCE_KEYS = new Set([
	"actorId",
	"profileId",
	"domain",
	"memorySource",
	"source",
	"trust",
	"writableNamespace",
	"providerAuthority",
	"endpointId",
	"networkNamespace",
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
			const parsed = ProviderReadInputSchema.parse(input);
			assertProviderScope(normalizedAuthority, parsed.service);
			return dependencies.providerRead({
				...stamp,
				service: parsed.service,
				action: parsed.action,
				params: parsed.params ?? {},
			});
		},

		async tc_provider_prepare_write(input) {
			const parsed = ProviderPrepareWriteInputSchema.parse(input);
			assertProviderScope(normalizedAuthority, parsed.service);
			return dependencies.providerPrepareWrite({
				...stamp,
				service: parsed.service,
				action: parsed.action,
				params: parsed.params ?? {},
				...(parsed.idempotencyKey ? { idempotencyKey: parsed.idempotencyKey } : {}),
			});
		},

		async tc_provider_execute_write(input) {
			const parsed = ProviderExecuteWriteInputSchema.parse(input);
			return dependencies.providerExecuteWrite({
				...stamp,
				actionRef: parsed.actionRef,
				approvalToken: parsed.approvalToken,
			});
		},

		async tc_memory_search(input) {
			const parsed = MemorySearchInputSchema.parse(input);
			return dependencies.memorySearch({
				...stamp,
				query: parsed.query,
				filters: parsed.filters,
				limit: parsed.limit ?? DEFAULT_MEMORY_SEARCH_LIMIT,
			});
		},

		async tc_memory_write(input) {
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
			const parsed = AttachmentGetInputSchema.parse(input);
			return dependencies.attachmentGet({ ...stamp, ref: parsed.ref });
		},

		async tc_outbound_prepare(input) {
			const parsed = OutboundPrepareInputSchema.parse(input);
			assertOutboundChannel(normalizedAuthority, parsed.channel);
			return dependencies.outboundPrepare({
				...stamp,
				channel: parsed.channel,
				recipient: parsed.recipient,
				content: parsed.content,
				mediaRefs: parsed.mediaRefs ?? [],
			});
		},

		async tc_outbound_execute(input) {
			const parsed = OutboundExecuteInputSchema.parse(input);
			return dependencies.outboundExecute({
				...stamp,
				outboundRef: parsed.outboundRef,
				approvalToken: parsed.approvalToken,
			});
		},

		async tc_audit_note(input) {
			const parsed = AuditNoteInputSchema.parse(input);
			return dependencies.auditNote({
				...stamp,
				kind: parsed.kind,
				payload: parsed.payload ?? {},
			});
		},
	};
}

function normalizeAuthority(authority: TelclaudeMcpAuthority): TelclaudeMcpAuthority {
	const memorySourceError = validateMemorySource(authority.memorySource);
	if (memorySourceError) {
		throw new Error(memorySourceError);
	}
	return {
		actorId: requiredTrimmed(authority.actorId, "actorId"),
		profileId: requiredTrimmed(authority.profileId, "profileId"),
		domain: authority.domain,
		memorySource: authority.memorySource,
		writableNamespace: requiredTrimmed(authority.writableNamespace, "writableNamespace"),
		providerScopes: uniqueTrimmed(authority.providerScopes),
		outboundChannels: uniqueTrimmed(authority.outboundChannels),
		endpointId: requiredTrimmed(authority.endpointId, "endpointId"),
		networkNamespace: requiredTrimmed(authority.networkNamespace, "networkNamespace"),
	};
}

function authorityStamp(authority: TelclaudeMcpAuthority): TelclaudeMcpAuthorityStamp {
	return {
		actorId: authority.actorId,
		profileId: authority.profileId,
		domain: authority.domain,
		memorySource: authority.memorySource,
		writableNamespace: authority.writableNamespace,
		endpointId: authority.endpointId,
		networkNamespace: authority.networkNamespace,
	};
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`Telclaude MCP authority ${field} is required`);
	}
	return trimmed;
}

function uniqueTrimmed(values: readonly string[]): string[] {
	return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function assertProviderScope(authority: TelclaudeMcpAuthority, service: string): void {
	if (!authority.providerScopes.includes(service)) {
		throw new Error(`provider scope denied: ${service}`);
	}
}

function assertOutboundChannel(authority: TelclaudeMcpAuthority, channel: string): void {
	if (!authority.outboundChannels.includes(channel)) {
		throw new Error(`outbound channel denied: ${channel}`);
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
