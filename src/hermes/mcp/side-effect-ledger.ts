import crypto from "node:crypto";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import {
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
} from "../../security/approval-domains.js";

export {
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
} from "../../security/approval-domains.js";

const DEFAULT_SIDE_EFFECT_TTL_MS = 5 * 60 * 1_000;
const PROVIDER_PARAMS_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.provider.params.v1";
const PROVIDER_BODY_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.provider.body.v1";
const OUTBOUND_PARAMS_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.outbound.params.v1";
const OUTBOUND_BODY_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.outbound.body.v1";

export type TelclaudeMcpSideEffectDomain =
	| "private"
	| "social"
	| "household"
	| "public"
	| "specialist";

export type TelclaudeMcpSideEffectStatus = "prepared" | "executed" | "revoked";

export type TelclaudeMcpProviderSideEffectRecord = {
	readonly ref: string;
	readonly kind: "provider";
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
	readonly providerAccountRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly wysiwysRender: string;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly status: TelclaudeMcpSideEffectStatus;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly executedAtMs?: number;
	readonly approvalId?: string;
	readonly revokedAtMs?: number;
	readonly revokeReason?: string;
};

export type TelclaudeMcpOutboundSideEffectRecord = {
	readonly ref: string;
	readonly kind: "outbound";
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly channel: string;
	readonly destination: string;
	readonly renderedBody: string;
	readonly mediaRefs: readonly string[];
	readonly conversationRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly approvalMetadata: Record<string, unknown>;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly status: TelclaudeMcpSideEffectStatus;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly executedAtMs?: number;
	readonly approvalId?: string;
	readonly revokedAtMs?: number;
	readonly revokeReason?: string;
};

export type TelclaudeMcpSideEffectRecord =
	| TelclaudeMcpProviderSideEffectRecord
	| TelclaudeMcpOutboundSideEffectRecord;

export type TelclaudeMcpProviderSideEffectPrepareInput = {
	readonly kind: "provider";
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly service: string;
	readonly action: string;
	readonly params?: Record<string, unknown>;
	readonly providerAccountRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly wysiwysRender: string;
	readonly idempotencyKey?: string;
	readonly ttlMs?: number;
};

export type TelclaudeMcpOutboundSideEffectPrepareInput = {
	readonly kind: "outbound";
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly channel: string;
	readonly destination: string;
	readonly renderedBody: string;
	readonly mediaRefs?: readonly string[];
	readonly conversationRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly approvalMetadata?: Record<string, unknown>;
	readonly idempotencyKey?: string;
	readonly ttlMs?: number;
};

export type TelclaudeMcpSideEffectPrepareInput =
	| TelclaudeMcpProviderSideEffectPrepareInput
	| TelclaudeMcpOutboundSideEffectPrepareInput;

export type TelclaudeMcpProviderApprovalBinding = {
	readonly domainSeparator: typeof TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN;
	readonly ref: string;
	readonly kind: "provider";
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly service: string;
	readonly action: string;
	readonly providerAccountRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly contentHash: string;
};

export type TelclaudeMcpOutboundApprovalBinding = {
	readonly domainSeparator: typeof TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN;
	readonly ref: string;
	readonly kind: "outbound";
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly channel: string;
	readonly destination: string;
	readonly conversationRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly contentHash: string;
};

export type TelclaudeMcpSideEffectApprovalBinding =
	| TelclaudeMcpProviderApprovalBinding
	| TelclaudeMcpOutboundApprovalBinding;

export type TelclaudeMcpSideEffectApprovalVerification = {
	readonly approvalToken: string;
	readonly binding: TelclaudeMcpSideEffectApprovalBinding;
	readonly record: TelclaudeMcpSideEffectRecord;
	readonly nowMs: number;
};

export type TelclaudeMcpSideEffectApprovalResult =
	| {
			readonly ok: true;
			readonly approvalId?: string;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
	  };

export type TelclaudeMcpSideEffectApprovalVerifier = (
	request: TelclaudeMcpSideEffectApprovalVerification,
) => TelclaudeMcpSideEffectApprovalResult | Promise<TelclaudeMcpSideEffectApprovalResult>;

export type TelclaudeMcpSideEffectLedgerOptions = {
	readonly verifyApproval: TelclaudeMcpSideEffectApprovalVerifier;
	readonly nowMs?: () => number;
	readonly makeRef?: () => string;
	readonly defaultTtlMs?: number;
};

export type TelclaudeMcpSideEffectTerminalFailure = {
	readonly ok: false;
	readonly code: string;
	readonly reason: string;
	readonly retryable: false;
	readonly record?: TelclaudeMcpSideEffectRecord;
};

export type TelclaudeMcpSideEffectRetryableFailure = {
	readonly ok: false;
	readonly code: string;
	readonly reason: string;
	readonly retryable: true;
	readonly record: TelclaudeMcpSideEffectRecord;
};

export type TelclaudeMcpSideEffectAuthorizeResult =
	| {
			readonly ok: true;
			readonly record: TelclaudeMcpSideEffectRecord;
	  }
	| TelclaudeMcpSideEffectRetryableFailure
	| TelclaudeMcpSideEffectTerminalFailure;

export type TelclaudeMcpSideEffectRevokeResult =
	| {
			readonly ok: true;
			readonly record: TelclaudeMcpSideEffectRecord;
	  }
	| TelclaudeMcpSideEffectTerminalFailure;

export type TelclaudeMcpSideEffectLedger = {
	prepare(input: TelclaudeMcpSideEffectPrepareInput): TelclaudeMcpSideEffectRecord;
	get(ref: string): TelclaudeMcpSideEffectRecord | null;
	list(): TelclaudeMcpSideEffectRecord[];
	revoke(ref: string, reason?: string): TelclaudeMcpSideEffectRevokeResult;
	authorize(ref: string, approvalToken: string): Promise<TelclaudeMcpSideEffectAuthorizeResult>;
};

export function createTelclaudeMcpSideEffectLedger(
	options: TelclaudeMcpSideEffectLedgerOptions,
): TelclaudeMcpSideEffectLedger {
	const records = new Map<string, TelclaudeMcpSideEffectRecord>();
	const nowMs = options.nowMs ?? Date.now;
	const makeRef = options.makeRef ?? (() => `effect-${crypto.randomUUID()}`);
	const defaultTtlMs = normalizeDuration(
		options.defaultTtlMs ?? DEFAULT_SIDE_EFFECT_TTL_MS,
		"defaultTtlMs",
	);

	return {
		prepare(input) {
			const record =
				input.kind === "provider"
					? prepareProviderRecord(input, makeRef, nowMs(), defaultTtlMs)
					: prepareOutboundRecord(input, makeRef, nowMs(), defaultTtlMs);
			if (records.has(record.ref)) {
				throw new Error(`duplicate side-effect ref: ${record.ref}`);
			}
			records.set(record.ref, record);
			return cloneRecord(record);
		},

		get(ref) {
			const record = records.get(requiredTrimmed(ref, "ref"));
			return record ? cloneRecord(record) : null;
		},

		list() {
			return [...records.values()].map(cloneRecord);
		},

		revoke(ref, reason) {
			const normalizedRef = requiredTrimmed(ref, "ref");
			const record = records.get(normalizedRef);
			if (!record) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			if (record.status !== "prepared") {
				return (
					terminalFailureForRecord(record) ??
					terminalFailure("effect_invalid_state", "side effect is not prepared", record)
				);
			}

			const revoked = deepFreeze({
				...record,
				status: "revoked" as const,
				revokedAtMs: nowMs(),
				...(reason ? { revokeReason: reason } : {}),
			});
			records.set(normalizedRef, revoked);
			return { ok: true, record: cloneRecord(revoked) };
		},

		async authorize(ref, approvalToken) {
			const normalizedRef = requiredTrimmed(ref, "ref");
			const authorizationNowMs = nowMs();
			const prepared = records.get(normalizedRef);
			if (!prepared) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			const preparedFailure = terminalFailureForRecord(prepared);
			if (preparedFailure) return preparedFailure;
			if (isExpired(prepared, authorizationNowMs)) {
				return terminalFailure("effect_expired", "side effect approval window expired", prepared);
			}

			const binding = approvalBinding(prepared);
			let approval: TelclaudeMcpSideEffectApprovalResult;
			try {
				approval = await options.verifyApproval({
					approvalToken: requiredTrimmed(approvalToken, "approvalToken"),
					binding: immutableClone(binding),
					record: cloneRecord(prepared),
					nowMs: authorizationNowMs,
				});
			} catch (error) {
				return retryableFailure("approval_verification_failed", errorMessage(error), prepared);
			}
			if (!approval.ok) {
				return retryableFailure(approval.code, approval.reason, prepared);
			}

			const current = records.get(normalizedRef);
			if (!current) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			const currentFailure = terminalFailureForRecord(current);
			if (currentFailure) return currentFailure;

			const executed = deepFreeze({
				...current,
				status: "executed" as const,
				executedAtMs: authorizationNowMs,
				...(approval.approvalId ? { approvalId: approval.approvalId } : {}),
			});
			records.set(normalizedRef, executed);
			return { ok: true, record: cloneRecord(executed) };
		},
	};
}

function prepareProviderRecord(
	input: TelclaudeMcpProviderSideEffectPrepareInput,
	makeRef: () => string,
	nowMs: number,
	defaultTtlMs: number,
): TelclaudeMcpProviderSideEffectRecord {
	const base = {
		ref: requiredTrimmed(makeRef(), "ref"),
		kind: "provider" as const,
		actorId: requiredTrimmed(input.actorId, "actorId"),
		profileId: requiredTrimmed(input.profileId, "profileId"),
		domain: input.domain,
		service: requiredTrimmed(input.service, "service"),
		action: requiredTrimmed(input.action, "action"),
		params: cloneJsonObject(input.params ?? {}, "params"),
		providerAccountRef: requiredTrimmed(input.providerAccountRef, "providerAccountRef"),
		approvalRequestId: requiredTrimmed(input.approvalRequestId, "approvalRequestId"),
		approvalRevision: normalizeRevision(input.approvalRevision),
		wysiwysRender: requiredTrimmed(input.wysiwysRender, "wysiwysRender"),
		...(input.idempotencyKey
			? { idempotencyKey: requiredTrimmed(input.idempotencyKey, "idempotencyKey") }
			: {}),
	};
	const ttlMs = normalizeDuration(input.ttlMs ?? defaultTtlMs, "ttlMs");
	return deepFreeze({
		...base,
		paramsHash: hashProviderParams(base),
		bodyHash: hashProviderBody(base),
		status: "prepared" as const,
		createdAtMs: nowMs,
		expiresAtMs: nowMs + ttlMs,
	});
}

function prepareOutboundRecord(
	input: TelclaudeMcpOutboundSideEffectPrepareInput,
	makeRef: () => string,
	nowMs: number,
	defaultTtlMs: number,
): TelclaudeMcpOutboundSideEffectRecord {
	const base = {
		ref: requiredTrimmed(makeRef(), "ref"),
		kind: "outbound" as const,
		actorId: requiredTrimmed(input.actorId, "actorId"),
		profileId: requiredTrimmed(input.profileId, "profileId"),
		domain: input.domain,
		channel: requiredTrimmed(input.channel, "channel"),
		destination: requiredTrimmed(input.destination, "destination"),
		renderedBody: requiredTrimmed(input.renderedBody, "renderedBody"),
		mediaRefs: normalizeStringList(input.mediaRefs ?? [], "mediaRefs"),
		conversationRef: requiredTrimmed(input.conversationRef, "conversationRef"),
		approvalRequestId: requiredTrimmed(input.approvalRequestId, "approvalRequestId"),
		approvalRevision: normalizeRevision(input.approvalRevision),
		approvalMetadata: cloneJsonObject(input.approvalMetadata ?? {}, "approvalMetadata"),
		...(input.idempotencyKey
			? { idempotencyKey: requiredTrimmed(input.idempotencyKey, "idempotencyKey") }
			: {}),
	};
	const ttlMs = normalizeDuration(input.ttlMs ?? defaultTtlMs, "ttlMs");
	return deepFreeze({
		...base,
		paramsHash: hashOutboundParams(base),
		bodyHash: hashOutboundBody(base),
		status: "prepared" as const,
		createdAtMs: nowMs,
		expiresAtMs: nowMs + ttlMs,
	});
}

function hashProviderParams(record: ProviderBindingFields): string {
	return canonicalDigest({
		domainSeparator: PROVIDER_PARAMS_HASH_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		service: record.service,
		action: record.action,
		params: record.params,
		providerAccountRef: record.providerAccountRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		wysiwysRender: record.wysiwysRender,
		idempotencyKey: record.idempotencyKey ?? null,
	});
}

function hashProviderBody(record: ProviderBindingFields): string {
	return canonicalDigest({
		domainSeparator: PROVIDER_BODY_HASH_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		service: record.service,
		action: record.action,
		providerAccountRef: record.providerAccountRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		wysiwysRender: record.wysiwysRender,
		idempotencyKey: record.idempotencyKey ?? null,
	});
}

function hashOutboundParams(record: OutboundBindingFields): string {
	return canonicalDigest({
		domainSeparator: OUTBOUND_PARAMS_HASH_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		channel: record.channel,
		destination: record.destination,
		mediaRefs: record.mediaRefs,
		conversationRef: record.conversationRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		approvalMetadata: record.approvalMetadata,
		idempotencyKey: record.idempotencyKey ?? null,
	});
}

function hashOutboundBody(record: OutboundBindingFields): string {
	return canonicalDigest({
		domainSeparator: OUTBOUND_BODY_HASH_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		channel: record.channel,
		destination: record.destination,
		renderedBody: record.renderedBody,
		mediaRefs: record.mediaRefs,
		conversationRef: record.conversationRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		approvalMetadata: record.approvalMetadata,
		idempotencyKey: record.idempotencyKey ?? null,
	});
}

function hashProviderApprovalContent(record: TelclaudeMcpProviderSideEffectRecord): string {
	return canonicalDigest({
		domainSeparator: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		service: record.service,
		action: record.action,
		providerAccountRef: record.providerAccountRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		idempotencyKey: record.idempotencyKey ?? null,
		paramsHash: record.paramsHash,
		bodyHash: record.bodyHash,
	});
}

function hashOutboundApprovalContent(record: TelclaudeMcpOutboundSideEffectRecord): string {
	return canonicalDigest({
		domainSeparator: TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		channel: record.channel,
		destination: record.destination,
		conversationRef: record.conversationRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		idempotencyKey: record.idempotencyKey ?? null,
		paramsHash: record.paramsHash,
		bodyHash: record.bodyHash,
	});
}

function approvalBinding(
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectApprovalBinding {
	if (record.kind === "provider") {
		return {
			domainSeparator: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
			ref: record.ref,
			kind: "provider",
			actorId: record.actorId,
			profileId: record.profileId,
			domain: record.domain,
			service: record.service,
			action: record.action,
			providerAccountRef: record.providerAccountRef,
			approvalRequestId: record.approvalRequestId,
			approvalRevision: record.approvalRevision,
			...(record.idempotencyKey ? { idempotencyKey: record.idempotencyKey } : {}),
			paramsHash: record.paramsHash,
			bodyHash: record.bodyHash,
			contentHash: hashProviderApprovalContent(record),
		};
	}
	return {
		domainSeparator: TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		ref: record.ref,
		kind: "outbound",
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		channel: record.channel,
		destination: record.destination,
		conversationRef: record.conversationRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		...(record.idempotencyKey ? { idempotencyKey: record.idempotencyKey } : {}),
		paramsHash: record.paramsHash,
		bodyHash: record.bodyHash,
		contentHash: hashOutboundApprovalContent(record),
	};
}

function terminalFailureForRecord(
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectTerminalFailure | null {
	if (record.status === "executed") {
		return terminalFailure("effect_already_executed", "side effect has already executed", record);
	}
	if (record.status === "revoked") {
		return terminalFailure("effect_revoked", "side effect was revoked", record);
	}
	return null;
}

function retryableFailure(
	code: string,
	reason: string,
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectRetryableFailure {
	return {
		ok: false,
		code,
		reason,
		retryable: true,
		record: cloneRecord(record),
	};
}

function terminalFailure(
	code: string,
	reason: string,
	record?: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectTerminalFailure {
	return {
		ok: false,
		code,
		reason,
		retryable: false,
		...(record ? { record: cloneRecord(record) } : {}),
	};
}

function isExpired(record: TelclaudeMcpSideEffectRecord, nowMs: number): boolean {
	return record.status === "prepared" && record.expiresAtMs < nowMs;
}

function canonicalDigest(value: unknown): string {
	const canonical = JSON.stringify(sortKeysDeep(value));
	const hash = crypto.createHash("sha256").update(canonical).digest("hex");
	return `sha256:${hash}`;
}

function cloneRecord(record: TelclaudeMcpSideEffectRecord): TelclaudeMcpSideEffectRecord {
	return immutableClone(record);
}

function cloneJsonObject(value: Record<string, unknown>, field: string): Record<string, unknown> {
	if (!isPlainObject(value)) {
		throw new Error(`${field} must be a JSON object`);
	}
	return cloneJsonValue(value, field) as Record<string, unknown>;
}

function cloneJsonValue<T>(value: T, field: string): T {
	assertJsonValue(value, field);
	return cloneJson(value);
}

function immutableClone<T>(value: T): T {
	return deepFreeze(cloneJson(value));
}

function cloneJson<T>(value: T): T {
	if (value === undefined) return value;
	return JSON.parse(JSON.stringify(value)) as T;
}

function assertJsonValue(value: unknown, field: string): void {
	if (value === null) return;
	if (typeof value === "string" || typeof value === "boolean") return;
	if (typeof value === "number") {
		if (!Number.isFinite(value)) {
			throw new Error(`${field} must be finite JSON`);
		}
		return;
	}
	if (Array.isArray(value)) {
		for (const [index, entry] of value.entries()) {
			assertJsonValue(entry, `${field}[${index}]`);
		}
		return;
	}
	if (isPlainObject(value)) {
		for (const [key, entry] of Object.entries(value)) {
			if (entry === undefined) {
				throw new Error(`${field}.${key} must not be undefined`);
			}
			assertJsonValue(entry, `${field}.${key}`);
		}
		return;
	}
	throw new Error(`${field} must be JSON-serializable`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

function deepFreeze<T>(value: T): T {
	if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
	for (const entry of Object.values(value as Record<string, unknown>)) {
		deepFreeze(entry);
	}
	return Object.freeze(value);
}

function normalizeStringList(values: readonly string[], field: string): readonly string[] {
	return cloneJsonValue(
		values.map((value, index) => requiredTrimmed(value, `${field}[${index}]`)),
		field,
	);
}

function normalizeRevision(value: number): number {
	if (!Number.isInteger(value) || value < 1) {
		throw new Error("approvalRevision must be a positive integer");
	}
	return value;
}

function normalizeDuration(value: number, field: string): number {
	if (!Number.isFinite(value) || value <= 0) {
		throw new Error(`${field} must be a positive finite duration`);
	}
	return value;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`side-effect ${field} is required`);
	}
	return trimmed;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

type ProviderBindingFields = Pick<
	TelclaudeMcpProviderSideEffectRecord,
	| "actorId"
	| "profileId"
	| "domain"
	| "service"
	| "action"
	| "params"
	| "providerAccountRef"
	| "approvalRequestId"
	| "approvalRevision"
	| "wysiwysRender"
	| "idempotencyKey"
>;

type OutboundBindingFields = Pick<
	TelclaudeMcpOutboundSideEffectRecord,
	| "actorId"
	| "profileId"
	| "domain"
	| "channel"
	| "destination"
	| "renderedBody"
	| "mediaRefs"
	| "conversationRef"
	| "approvalRequestId"
	| "approvalRevision"
	| "approvalMetadata"
	| "idempotencyKey"
>;
