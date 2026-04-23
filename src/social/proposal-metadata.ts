import type { MemorySource, TrustLevel } from "../memory/types.js";
import { filterOutput } from "../security/output-filter.js";
import { getDb } from "../storage/db.js";
import { logSocialActivity } from "./activity-log.js";
import type { SocialDraftStatus } from "./types.js";

export type SocialQuoteProposalMetadata = {
	action: "quote";
	targetPostId: string;
	targetAuthor?: string;
	targetExcerpt?: string;
};

export type SocialDraftMetadata = {
	action?: "post" | "quote" | "thread";
	targetPostId?: string;
	targetAuthor?: string;
	targetExcerpt?: string;
	draftState?: SocialDraftStatus;
	draftWorkflow?: "workbench";
	serviceId?: string;
	targetUrl?: string;
	manualActionReason?: string;
	lastError?: string;
	postedPostId?: string;
	editedAt?: number;
	editedBy?: string;
	refinedAt?: number;
	refinedBy?: string;
	approvedAt?: number;
	approvedBy?: string;
	markedPostedAt?: number;
	markedPostedBy?: string;
	dismissedAt?: number;
	dismissedBy?: string;
};

export type SocialDraftRecord = {
	id: string;
	category: string;
	content: string;
	metadata?: SocialDraftMetadata;
	source: MemorySource;
	trust: TrustLevel;
	createdAt: number;
	promotedAt?: number;
	promotedBy?: string;
	postedAt?: number;
	chatId?: string;
	status: SocialDraftStatus;
};

type SocialDraftRow = {
	id: string;
	category: string;
	content: string;
	metadata: string | null;
	source: string;
	trust: string;
	created_at: number;
	promoted_at: number | null;
	promoted_by: string | null;
	posted_at: number | null;
	chat_id: string | null;
};

const SOCIAL_DRAFT_STATUSES: SocialDraftStatus[] = [
	"queued",
	"drafted",
	"needs_review",
	"manual_action_needed",
	"posted_via_api",
	"marked_posted",
	"dismissed",
	"failed",
];

const ACTIVE_DRAFT_STATUSES: SocialDraftStatus[] = [
	"queued",
	"drafted",
	"needs_review",
	"manual_action_needed",
	"failed",
];

const MAX_DRAFT_TEXT_LENGTH = 4000;

function isSocialDraftStatus(value: unknown): value is SocialDraftStatus {
	return typeof value === "string" && SOCIAL_DRAFT_STATUSES.includes(value as SocialDraftStatus);
}

function parseMetadataObject(raw: unknown): Record<string, unknown> | undefined {
	if (!raw) return undefined;
	if (typeof raw === "string") {
		try {
			const parsed = JSON.parse(raw) as unknown;
			return parseMetadataObject(parsed);
		} catch {
			return undefined;
		}
	}
	if (typeof raw === "object" && !Array.isArray(raw)) {
		return raw as Record<string, unknown>;
	}
	return undefined;
}

function normalizeMetadata(metadata: unknown): SocialDraftMetadata {
	const parsed = parseMetadataObject(metadata);
	if (!parsed) return {};
	const normalized: SocialDraftMetadata = {};

	if (parsed.action === "post" || parsed.action === "quote" || parsed.action === "thread") {
		normalized.action = parsed.action;
	}
	if (isSocialDraftStatus(parsed.draftState)) {
		normalized.draftState = parsed.draftState;
	}
	if (parsed.draftWorkflow === "workbench") {
		normalized.draftWorkflow = "workbench";
	}

	for (const key of [
		"targetPostId",
		"targetAuthor",
		"targetExcerpt",
		"serviceId",
		"targetUrl",
		"manualActionReason",
		"lastError",
		"postedPostId",
		"editedBy",
		"refinedBy",
		"approvedBy",
		"markedPostedBy",
		"dismissedBy",
	] as const) {
		const value = parsed[key];
		if (typeof value === "string" && value.trim()) {
			normalized[key] = value.trim();
		}
	}

	for (const key of [
		"editedAt",
		"refinedAt",
		"approvedAt",
		"markedPostedAt",
		"dismissedAt",
	] as const) {
		const value = parsed[key];
		if (typeof value === "number" && Number.isFinite(value)) {
			normalized[key] = value;
		}
	}

	return normalized;
}

function serializeMetadata(metadata: SocialDraftMetadata): string {
	return JSON.stringify(metadata);
}

function validateDraftText(text: string): string | null {
	const trimmed = text.trim();
	if (!trimmed) {
		return "Draft text cannot be empty";
	}
	if (trimmed.length > MAX_DRAFT_TEXT_LENGTH) {
		return `Draft text is too long (${MAX_DRAFT_TEXT_LENGTH} characters max)`;
	}
	const secretCheck = filterOutput(trimmed);
	if (secretCheck.blocked) {
		return "Draft text appears to contain a secret";
	}
	return null;
}

function rowToDraft(row: SocialDraftRow): SocialDraftRecord {
	const metadata = normalizeMetadata(row.metadata);
	const base = {
		metadata,
		_provenance: {
			source: row.source as MemorySource,
			trust: row.trust as TrustLevel,
			createdAt: row.created_at,
			...(row.promoted_at ? { promotedAt: row.promoted_at } : {}),
			...(row.promoted_by ? { promotedBy: row.promoted_by } : {}),
			...(row.posted_at ? { postedAt: row.posted_at } : {}),
			...(row.chat_id ? { chatId: row.chat_id } : {}),
		},
	};

	return {
		id: row.id,
		category: row.category,
		content: row.content,
		metadata,
		source: row.source as MemorySource,
		trust: row.trust as TrustLevel,
		createdAt: row.created_at,
		...(row.promoted_at ? { promotedAt: row.promoted_at } : {}),
		...(row.promoted_by ? { promotedBy: row.promoted_by } : {}),
		...(row.posted_at ? { postedAt: row.posted_at } : {}),
		...(row.chat_id ? { chatId: row.chat_id } : {}),
		status: resolveSocialDraftStatus(base),
	};
}

function ensureDraftCanMutate(record: SocialDraftRecord): string | null {
	if (record.category !== "posts") {
		return "Only post drafts can be changed";
	}
	if (record.source !== "telegram" && record.source !== "social") {
		return "Only telegram or social drafts can be changed";
	}
	if (record.status === "posted_via_api" || record.status === "marked_posted") {
		return "Posted drafts cannot be changed";
	}
	if (record.status === "dismissed") {
		return "Dismissed drafts cannot be changed";
	}
	return null;
}

function patchDraftMetadata(
	id: string,
	patch: SocialDraftMetadata,
	options: { content?: string; postedAt?: number | null } = {},
): SocialDraftRecord | null {
	const current = getSocialDraft(id);
	if (!current) return null;

	const nextMetadata = {
		...(current.metadata ?? {}),
		...patch,
	};
	const db = getDb();
	db.prepare(
		`UPDATE memory_entries
		 SET metadata = ?, content = COALESCE(?, content), posted_at = COALESCE(?, posted_at)
		 WHERE id = ?`,
	).run(serializeMetadata(nextMetadata), options.content ?? null, options.postedAt ?? null, id);
	return getSocialDraft(id);
}

export function parseSocialDraftMetadata(metadata: unknown): SocialDraftMetadata {
	return normalizeMetadata(metadata);
}

export function isActiveSocialDraftStatus(status: SocialDraftStatus): boolean {
	return ACTIVE_DRAFT_STATUSES.includes(status);
}

export function resolveSocialDraftStatus(entry: {
	metadata?: unknown;
	_provenance?: { trust?: string; promotedAt?: number; postedAt?: number };
}): SocialDraftStatus {
	const metadata = normalizeMetadata(entry.metadata);
	if (metadata.draftState) {
		return metadata.draftState;
	}
	if (entry._provenance?.postedAt) {
		return "posted_via_api";
	}
	if (entry._provenance?.trust === "trusted" && entry._provenance.promotedAt) {
		return "queued";
	}
	return "drafted";
}

export function socialDraftMetadataForNewProposal(params: {
	serviceId: string;
	action?: "post" | "quote" | "thread";
	targetPostId?: string;
	targetAuthor?: string;
	targetExcerpt?: string;
	targetUrl?: string;
}): SocialDraftMetadata {
	return {
		draftState: "drafted",
		draftWorkflow: "workbench",
		serviceId: params.serviceId,
		action: params.action ?? "post",
		...(params.targetPostId ? { targetPostId: params.targetPostId } : {}),
		...(params.targetAuthor ? { targetAuthor: params.targetAuthor } : {}),
		...(params.targetExcerpt ? { targetExcerpt: params.targetExcerpt } : {}),
		...(params.targetUrl ? { targetUrl: params.targetUrl } : {}),
	};
}

export function getSocialDraft(id: string): SocialDraftRecord | null {
	const row = getDb()
		.prepare(
			`SELECT id, category, content, metadata, source, trust, created_at, promoted_at, promoted_by, posted_at, chat_id
			 FROM memory_entries
			 WHERE id = ?`,
		)
		.get(id) as SocialDraftRow | undefined;
	return row ? rowToDraft(row) : null;
}

export type SocialDraftMutationResult =
	| { ok: true; draft: SocialDraftRecord }
	| { ok: false; reason: string };

export function updateSocialDraftText(params: {
	id: string;
	text: string;
	actor: string;
	refined?: boolean;
}): SocialDraftMutationResult {
	const record = getSocialDraft(params.id);
	if (!record) return { ok: false, reason: "Draft not found" };
	const mutationError = ensureDraftCanMutate(record);
	if (mutationError) return { ok: false, reason: mutationError };
	const validationError = validateDraftText(params.text);
	if (validationError) return { ok: false, reason: validationError };

	const now = Date.now();
	const draft = patchDraftMetadata(
		params.id,
		params.refined
			? {
					draftState: "needs_review",
					draftWorkflow: "workbench",
					refinedAt: now,
					refinedBy: params.actor,
					lastError: undefined,
					manualActionReason: undefined,
				}
			: {
					draftState: "needs_review",
					draftWorkflow: "workbench",
					editedAt: now,
					editedBy: params.actor,
					lastError: undefined,
					manualActionReason: undefined,
				},
		{ content: params.text.trim() },
	);
	return draft ? { ok: true, draft } : { ok: false, reason: "Failed to update draft" };
}

export function markSocialDraftApproved(params: {
	id: string;
	actor: string;
	serviceId?: string;
}): SocialDraftMutationResult {
	const record = getSocialDraft(params.id);
	if (!record) return { ok: false, reason: "Draft not found" };
	const mutationError = ensureDraftCanMutate(record);
	if (mutationError) return { ok: false, reason: mutationError };

	const now = Date.now();
	const draft = patchDraftMetadata(params.id, {
		draftState: "queued",
		draftWorkflow: "workbench",
		approvedAt: now,
		approvedBy: params.actor,
		...(params.serviceId ? { serviceId: params.serviceId } : {}),
		lastError: undefined,
		manualActionReason: undefined,
	});
	if (draft) {
		logSocialActivity({
			type: "approved",
			timestamp: now,
			serviceId: draft.metadata?.serviceId ?? params.serviceId ?? "social",
		});
		return { ok: true, draft };
	}
	return { ok: false, reason: "Failed to approve draft" };
}

export function markSocialDraftManualActionNeeded(params: {
	id: string;
	reason: string;
	serviceId?: string;
}): SocialDraftMutationResult {
	const now = Date.now();
	const draft = patchDraftMetadata(params.id, {
		draftState: "manual_action_needed",
		draftWorkflow: "workbench",
		manualActionReason: params.reason,
		lastError: params.reason,
		...(params.serviceId ? { serviceId: params.serviceId } : {}),
	});
	if (draft) {
		logSocialActivity({
			type: "manual_action_needed",
			timestamp: now,
			serviceId: draft.metadata?.serviceId ?? params.serviceId ?? "social",
		});
		return { ok: true, draft };
	}
	return { ok: false, reason: "Draft not found" };
}

export function markSocialDraftPostingFailed(params: {
	id: string;
	error: string;
	serviceId?: string;
}): SocialDraftMutationResult {
	const now = Date.now();
	const draft = patchDraftMetadata(params.id, {
		draftState: "failed",
		draftWorkflow: "workbench",
		lastError: params.error,
		manualActionReason: undefined,
		...(params.serviceId ? { serviceId: params.serviceId } : {}),
	});
	if (draft) {
		logSocialActivity({
			type: "posting_failed",
			timestamp: now,
			serviceId: draft.metadata?.serviceId ?? params.serviceId ?? "social",
		});
		return { ok: true, draft };
	}
	return { ok: false, reason: "Draft not found" };
}

export function markSocialDraftPostedViaApi(params: {
	id: string;
	serviceId?: string;
	postId?: string;
}): SocialDraftMutationResult {
	const now = Date.now();
	const draft = patchDraftMetadata(
		params.id,
		{
			draftState: "posted_via_api",
			draftWorkflow: "workbench",
			...(params.serviceId ? { serviceId: params.serviceId } : {}),
			...(params.postId ? { postedPostId: params.postId } : {}),
			lastError: undefined,
			manualActionReason: undefined,
		},
		{ postedAt: now },
	);
	if (draft) {
		logSocialActivity({
			type: "posted_via_api",
			timestamp: now,
			serviceId: draft.metadata?.serviceId ?? params.serviceId ?? "social",
		});
		return { ok: true, draft };
	}
	return { ok: false, reason: "Draft not found" };
}

export function markSocialDraftManuallyPosted(params: {
	id: string;
	actor: string;
	serviceId?: string;
}): SocialDraftMutationResult {
	const now = Date.now();
	const draft = patchDraftMetadata(
		params.id,
		{
			draftState: "marked_posted",
			draftWorkflow: "workbench",
			markedPostedAt: now,
			markedPostedBy: params.actor,
			...(params.serviceId ? { serviceId: params.serviceId } : {}),
			lastError: undefined,
			manualActionReason: undefined,
		},
		{ postedAt: now },
	);
	if (draft) {
		logSocialActivity({
			type: "marked_posted",
			timestamp: now,
			serviceId: draft.metadata?.serviceId ?? params.serviceId ?? "social",
		});
		return { ok: true, draft };
	}
	return { ok: false, reason: "Draft not found" };
}

export function dismissSocialDraft(params: {
	id: string;
	actor: string;
	serviceId?: string;
}): SocialDraftMutationResult {
	const now = Date.now();
	const draft = patchDraftMetadata(params.id, {
		draftState: "dismissed",
		draftWorkflow: "workbench",
		dismissedAt: now,
		dismissedBy: params.actor,
		...(params.serviceId ? { serviceId: params.serviceId } : {}),
	});
	if (draft) {
		logSocialActivity({
			type: "dismissed",
			timestamp: now,
			serviceId: draft.metadata?.serviceId ?? params.serviceId ?? "social",
		});
		return { ok: true, draft };
	}
	return { ok: false, reason: "Draft not found" };
}

export function parseSocialQuoteProposalMetadata(
	metadata: unknown,
): SocialQuoteProposalMetadata | null {
	const candidate = normalizeMetadata(metadata);
	if (candidate.action !== "quote" || typeof candidate.targetPostId !== "string") {
		return null;
	}

	const targetPostId = candidate.targetPostId.trim();
	if (!targetPostId) {
		return null;
	}

	return {
		action: "quote",
		targetPostId,
		targetAuthor:
			typeof candidate.targetAuthor === "string" && candidate.targetAuthor.trim()
				? candidate.targetAuthor.trim()
				: undefined,
		targetExcerpt:
			typeof candidate.targetExcerpt === "string" && candidate.targetExcerpt.trim()
				? candidate.targetExcerpt.trim()
				: undefined,
	};
}
