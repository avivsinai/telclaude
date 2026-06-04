import crypto from "node:crypto";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import {
	type CreateApprovalResult,
	consumeApprovalMatching as consumeSecurityApprovalMatching,
	createApproval as createSecurityApproval,
	type PendingApproval,
	peekPendingApprovalByNonce,
} from "../../security/approvals.js";
import {
	getTelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectApprovalBinding,
	type TelclaudeMcpSideEffectRecord,
	telclaudeMcpSideEffectRecordIntegrityFailures,
} from "./side-effect-ledger.js";

const DEFAULT_HUMAN_APPROVAL_TTL_MS = 5 * 60 * 1_000;
const MAX_SIDE_EFFECT_APPROVAL_TOKEN_TTL_MS = 60_000;
export const TELCLAUDE_MCP_SIDE_EFFECT_HUMAN_APPROVAL_TOOL_KEY_PREFIX =
	"hermes.side-effect-human-approval.v1";

export type SideEffectHumanApprovalCreateInput = {
	readonly record: TelclaudeMcpSideEffectRecord;
	readonly chatId: number;
	readonly username?: string;
	readonly ttlMs?: number;
};

export type SideEffectHumanApprovalConsumeInput = {
	readonly record: TelclaudeMcpSideEffectRecord;
	readonly chatId: number;
	readonly approverActorId: string;
	readonly approvalNonce: string;
};

export type SideEffectHumanApprovalTokenRequest = {
	readonly record: TelclaudeMcpSideEffectRecord;
	readonly binding: TelclaudeMcpSideEffectApprovalBinding;
	readonly jti: string;
	readonly ttlMs: number;
	readonly nowMs: number;
};

export type SideEffectHumanApprovalTokenResult = {
	readonly approvalToken: string;
	readonly approvalId?: string;
};

export type SideEffectHumanApprovalResult =
	| {
			readonly ok: true;
			readonly nonce: string;
			readonly createdAt: number;
			readonly expiresAt: number;
			readonly bindingDigest: string;
			readonly autoGranted?: boolean;
	  }
	| SideEffectHumanApprovalFailure;

export type SideEffectHumanApprovalConsumeResult =
	| {
			readonly ok: true;
			readonly actionRef: string;
			readonly approvalId: string;
			readonly binding: TelclaudeMcpSideEffectApprovalBinding;
			readonly serverSideApprovalStored: true;
			readonly expiresAtMs: number;
	  }
	| SideEffectHumanApprovalFailure;

export type SideEffectHumanApprovalTokenResolution =
	| {
			readonly ok: true;
			readonly approvalToken: string;
			readonly approvalId: string;
			readonly binding: TelclaudeMcpSideEffectApprovalBinding;
			readonly finalize: () => void;
	  }
	| SideEffectHumanApprovalFailure;

export type SideEffectHumanApprovalFailure = {
	readonly ok: false;
	readonly code: string;
	readonly reason: string;
	readonly retryable: boolean;
};

export type SideEffectHumanApprovalController = {
	request(input: SideEffectHumanApprovalCreateInput): Promise<SideEffectHumanApprovalResult>;
	consume(
		input: SideEffectHumanApprovalConsumeInput,
	): Promise<SideEffectHumanApprovalConsumeResult>;
	takeServerSideApproval(input: {
		readonly actionRef: string;
		readonly record: TelclaudeMcpSideEffectRecord;
		readonly nowMs?: number;
	}): SideEffectHumanApprovalTokenResolution;
};

export type SideEffectHumanApprovalDependencies = {
	readonly createApproval?: (
		entry: Parameters<typeof createSecurityApproval>[0],
		ttlMs?: number,
	) => CreateApprovalResult;
	readonly consumeApprovalMatching?: typeof consumeSecurityApprovalMatching;
	readonly mintApprovalToken: (
		request: SideEffectHumanApprovalTokenRequest,
	) =>
		| SideEffectHumanApprovalTokenResult
		| string
		| Promise<SideEffectHumanApprovalTokenResult | string>;
	readonly nowMs?: () => number;
	readonly renderProviderApproval?: (
		record: Extract<TelclaudeMcpSideEffectRecord, { kind: "provider" }>,
	) => string;
	readonly renderOutboundApproval?: (
		record: Extract<TelclaudeMcpSideEffectRecord, { kind: "outbound" }>,
	) => string;
	readonly autoGrant?: SideEffectHumanApprovalAutoGrantOptions;
};

export type SideEffectHumanApprovalAutoGrantOptions = {
	readonly enabled: boolean;
	readonly ttlMs?: number;
};

type StoredServerSideApproval = {
	readonly actionRef: string;
	readonly approvalToken: string;
	readonly approvalId: string;
	readonly binding: TelclaudeMcpSideEffectApprovalBinding;
	readonly bindingDigest: string;
	readonly expiresAtMs: number;
};

export function createSideEffectHumanApprovalController(
	dependencies: SideEffectHumanApprovalDependencies,
): SideEffectHumanApprovalController {
	const createApproval = dependencies.createApproval ?? createSecurityApproval;
	const consumeApprovalMatching =
		dependencies.consumeApprovalMatching ?? consumeSecurityApprovalMatching;
	const nowMs = dependencies.nowMs ?? Date.now;
	const serverSideApprovals = new Map<string, StoredServerSideApproval>();

	return {
		async request(input) {
			const authorizationNowMs = nowMs();
			const prepared = prepareApprovalBinding(input.record, dependencies, authorizationNowMs);
			if (!prepared.ok) return prepared;
			const autoGrant = await maybeAutoGrantSideEffect(
				input.record,
				prepared,
				dependencies,
				authorizationNowMs,
				serverSideApprovals,
			);
			if (autoGrant) return autoGrant;
			const ttlMs = normalizeTtlMs(input.ttlMs ?? DEFAULT_HUMAN_APPROVAL_TTL_MS);
			const created = createApproval(
				{
					requestId: input.record.approvalRequestId,
					chatId: input.chatId,
					tier: "FULL_ACCESS",
					body: prepared.body,
					username: input.username,
					from: input.record.actorId,
					to: input.record.approverActorId,
					messageId: input.record.ref,
					observerClassification: "BLOCK",
					observerConfidence: 1,
					observerReason: "Hermes MCP side-effect approval",
					riskTier: "high",
					toolKey: toolKeyForDigest(prepared.bindingDigest),
					sessionKey: input.record.ref,
				},
				ttlMs,
			);
			return {
				ok: true,
				nonce: created.nonce,
				createdAt: created.createdAt,
				expiresAt: created.expiresAt,
				bindingDigest: prepared.bindingDigest,
			};
		},

		async consume(input) {
			const authorizationNowMs = nowMs();
			const precheck = prepareApprovalBinding(input.record, dependencies, authorizationNowMs);
			if (!precheck.ok) return precheck;
			const authorityFailure = approvalAuthorityFailure(input, input.record, authorizationNowMs);
			if (authorityFailure) return authorityFailure;
			const approvalNonce = normalizeApprovalNonce(input.approvalNonce);

			const pending = peekPendingApprovalByNonce(approvalNonce);
			if (!pending.success) {
				return approvalConsumeFailure(pending.error);
			}
			const pendingFailure = approvalRowBindingFailure(pending.data, input.record, precheck);
			if (pendingFailure) return pendingFailure;
			if (pending.data.chatId !== input.chatId) {
				return approvalConsumeFailure("This approval code belongs to a different chat.");
			}
			if (pending.data.expiresAt < authorizationNowMs) {
				const expired = consumeApprovalMatching(approvalNonce, input.chatId, () => null);
				if (!expired.success) return approvalConsumeFailure(expired.error);
				return failure("approval_expired", "side-effect approval has expired", false);
			}

			const remainingTtlMs = Math.min(
				MAX_SIDE_EFFECT_APPROVAL_TOKEN_TTL_MS,
				Math.max(1, pending.data.expiresAt - authorizationNowMs),
			);
			let minted: SideEffectHumanApprovalTokenResult | string;
			try {
				minted = await dependencies.mintApprovalToken({
					record: input.record,
					binding: precheck.binding,
					jti: pending.data.nonce,
					ttlMs: remainingTtlMs,
					nowMs: authorizationNowMs,
				});
			} catch (error) {
				return failure(
					"approval_token_mint_failed",
					error instanceof Error ? error.message : String(error),
					true,
				);
			}
			const consumed = consumeApprovalMatching(approvalNonce, input.chatId, (approval) => {
				return approvalRowBindingFailure(approval, input.record, precheck)?.reason ?? null;
			});
			if (!consumed.success) {
				return approvalConsumeFailure(consumed.error);
			}
			const consumedFailure = approvalRowBindingFailure(consumed.data, input.record, precheck);
			if (consumedFailure) return consumedFailure;
			const tokenResult =
				typeof minted === "string"
					? { approvalToken: minted, approvalId: consumed.data.nonce }
					: minted;
			const approvalId = tokenResult.approvalId ?? consumed.data.nonce;
			serverSideApprovals.set(input.record.ref, {
				actionRef: input.record.ref,
				approvalToken: tokenResult.approvalToken,
				approvalId,
				binding: precheck.binding,
				bindingDigest: precheck.bindingDigest,
				expiresAtMs: authorizationNowMs + remainingTtlMs,
			});
			return {
				ok: true,
				actionRef: input.record.ref,
				approvalId,
				binding: precheck.binding,
				serverSideApprovalStored: true,
				expiresAtMs: authorizationNowMs + remainingTtlMs,
			};
		},

		takeServerSideApproval(input) {
			const stored = serverSideApprovals.get(requiredTrimmed(input.actionRef, "actionRef"));
			if (!stored) {
				return failure(
					"approval_token_unavailable",
					"server-side approval token is unavailable",
					true,
				);
			}
			const authorizationNowMs = input.nowMs ?? nowMs();
			if (stored.expiresAtMs < authorizationNowMs) {
				serverSideApprovals.delete(stored.actionRef);
				return failure("approval_expired", "server-side approval token expired", false);
			}
			const prepared = prepareApprovalBinding(input.record, dependencies, authorizationNowMs);
			if (!prepared.ok) return prepared;
			if (prepared.bindingDigest !== stored.bindingDigest) {
				return failure("approval_binding_mismatch", "server-side approval binding mismatch", false);
			}
			return {
				ok: true,
				approvalToken: stored.approvalToken,
				approvalId: stored.approvalId,
				binding: stored.binding,
				finalize: () => {
					const current = serverSideApprovals.get(stored.actionRef);
					if (
						current?.approvalId === stored.approvalId &&
						current.bindingDigest === stored.bindingDigest
					) {
						serverSideApprovals.delete(stored.actionRef);
					}
				},
			};
		},
	};
}

async function maybeAutoGrantSideEffect(
	record: TelclaudeMcpSideEffectRecord,
	prepared: {
		readonly binding: TelclaudeMcpSideEffectApprovalBinding;
		readonly bindingDigest: string;
	},
	dependencies: SideEffectHumanApprovalDependencies,
	nowMs: number,
	serverSideApprovals: Map<string, StoredServerSideApproval>,
): Promise<SideEffectHumanApprovalResult | null> {
	if (dependencies.autoGrant?.enabled !== true) return null;
	if (!autoGrantEligible(record)) return null;
	const ttlMs = normalizeAutoGrantTtlMs(dependencies.autoGrant.ttlMs);
	const approvalId = autoGrantJtiFor(record);
	let minted: SideEffectHumanApprovalTokenResult | string;
	try {
		minted = (await dependencies.mintApprovalToken({
			record,
			binding: prepared.binding,
			jti: approvalId,
			ttlMs,
			nowMs,
		})) as SideEffectHumanApprovalTokenResult | string;
	} catch (error) {
		return failure(
			"approval_token_mint_failed",
			error instanceof Error ? error.message : String(error),
			true,
		);
	}
	const tokenResult = typeof minted === "string" ? { approvalToken: minted, approvalId } : minted;
	const storedApprovalId = tokenResult.approvalId ?? approvalId;
	serverSideApprovals.set(record.ref, {
		actionRef: record.ref,
		approvalToken: tokenResult.approvalToken,
		approvalId: storedApprovalId,
		binding: prepared.binding,
		bindingDigest: prepared.bindingDigest,
		expiresAtMs: nowMs + ttlMs,
	});
	return {
		ok: true,
		nonce: storedApprovalId,
		createdAt: nowMs,
		expiresAt: nowMs + ttlMs,
		bindingDigest: prepared.bindingDigest,
		autoGranted: true,
	};
}

function autoGrantEligible(record: TelclaudeMcpSideEffectRecord): boolean {
	if (record.kind !== "outbound") return false;
	if (record.domain !== "private") return false;
	if (record.authorizationState !== "authorized") return false;
	if (!record.turnConversationRef) return false;
	return (
		record.approvalMetadata.source === "hermes-live-mcp" &&
		record.approvalMetadata.pairedProvenance === true &&
		record.approvalMetadata.replyCapableActorSeat === true
	);
}

function autoGrantJtiFor(record: TelclaudeMcpSideEffectRecord): string {
	return `auto-${record.ref}`;
}

function prepareApprovalBinding(
	record: TelclaudeMcpSideEffectRecord,
	dependencies: Pick<
		SideEffectHumanApprovalDependencies,
		"renderProviderApproval" | "renderOutboundApproval"
	>,
	nowMs: number,
):
	| {
			readonly ok: true;
			readonly binding: TelclaudeMcpSideEffectApprovalBinding;
			readonly bindingDigest: string;
			readonly body: string;
	  }
	| SideEffectHumanApprovalFailure {
	if (record.status !== "prepared") {
		return failure("effect_not_prepared", "side effect is not prepared", false);
	}
	if (record.approverActorId === record.actorId) {
		return failure(
			"approval_self_approval_denied",
			"side effects require approval by a distinct human approver",
			false,
		);
	}
	if (record.expiresAtMs < nowMs) {
		return failure("effect_expired", "side effect approval window expired", false);
	}
	const integrityFailures = telclaudeMcpSideEffectRecordIntegrityFailures(record);
	if (integrityFailures.length > 0) {
		return failure("effect_integrity_mismatch", integrityFailures.join("; "), false);
	}
	const humanVisibleRender = renderHumanVisibleApproval(record, dependencies);
	const storedHumanVisibleRender =
		record.kind === "provider" ? record.wysiwysRender : record.renderedBody;
	if (humanVisibleRender !== storedHumanVisibleRender) {
		return failure(
			"approval_wysiwyg_mismatch",
			"approval render no longer matches executable side-effect parameters",
			false,
		);
	}
	const binding = getTelclaudeMcpSideEffectApprovalBinding(record);
	const bindingDigest = digestBinding(binding);
	const body = formatSideEffectHumanApprovalBody(
		record,
		binding,
		bindingDigest,
		humanVisibleRender,
	);
	return { ok: true, binding, bindingDigest, body };
}

function approvalAuthorityFailure(
	input: SideEffectHumanApprovalConsumeInput,
	record: TelclaudeMcpSideEffectRecord,
	nowMs: number,
): SideEffectHumanApprovalFailure | null {
	if (record.approverActorId !== input.approverActorId) {
		return failure(
			"approval_wrong_approver",
			"approval actor does not match side-effect approver",
			false,
		);
	}
	if (record.approverActorId === record.actorId) {
		return failure(
			"approval_self_approval_denied",
			"side effects require approval by a distinct human approver",
			false,
		);
	}
	if (record.expiresAtMs < nowMs) {
		return failure("effect_expired", "side effect approval window expired", false);
	}
	return null;
}

function approvalRowBindingFailure(
	approval: PendingApproval,
	record: TelclaudeMcpSideEffectRecord,
	prepared: {
		readonly bindingDigest: string;
		readonly body: string;
	},
): SideEffectHumanApprovalFailure | null {
	if (approval.requestId !== record.approvalRequestId) {
		return failure("approval_binding_mismatch", "approval requestId mismatch", false);
	}
	if (approval.body !== prepared.body) {
		return failure("approval_binding_mismatch", "approval body/render mismatch", false);
	}
	if (approval.from !== record.actorId || approval.to !== record.approverActorId) {
		return failure("approval_binding_mismatch", "approval actor binding mismatch", false);
	}
	if (approval.messageId !== record.ref) {
		return failure("approval_binding_mismatch", "approval actionRef binding mismatch", false);
	}
	if (approval.toolKey !== toolKeyForDigest(prepared.bindingDigest)) {
		return failure("approval_binding_mismatch", "approval binding digest mismatch", false);
	}
	if (approval.sessionKey !== record.ref) {
		return failure("approval_binding_mismatch", "approval session binding mismatch", false);
	}
	return null;
}

function renderHumanVisibleApproval(
	record: TelclaudeMcpSideEffectRecord,
	dependencies: Pick<
		SideEffectHumanApprovalDependencies,
		"renderProviderApproval" | "renderOutboundApproval"
	>,
): string {
	if (record.kind === "provider") {
		return requiredTrimmed(
			dependencies.renderProviderApproval?.(record) ?? record.wysiwysRender,
			"approvalBody",
		);
	}
	return requiredTrimmed(
		dependencies.renderOutboundApproval?.(record) ?? record.renderedBody,
		"approvalBody",
	);
}

function formatSideEffectHumanApprovalBody(
	record: TelclaudeMcpSideEffectRecord,
	binding: TelclaudeMcpSideEffectApprovalBinding,
	bindingDigest: string,
	humanVisibleRender: string,
): string {
	const common = [
		`Action ref: ${record.ref}`,
		`Actor: ${record.actorId}`,
		`Approver: ${record.approverActorId}`,
		`Profile: ${record.profileId}`,
		`Domain: ${record.domain}`,
		`Approval request: ${record.approvalRequestId}`,
		`Approval revision: ${record.approvalRevision}`,
		`Params hash: ${record.paramsHash}`,
		`Body hash: ${record.bodyHash}`,
		`Content hash: ${binding.contentHash}`,
		`Binding digest: ${bindingDigest}`,
		"",
		"Human-visible render:",
		humanVisibleRender,
		"",
		"Canonical approval binding:",
		canonicalJson(binding),
	];
	if (record.kind === "provider") {
		return [
			"Hermes MCP provider side-effect approval required",
			`Provider: ${record.providerId}`,
			`Service: ${record.service}`,
			`Action: ${record.action}`,
			`Provider account: ${record.providerAccountRef}`,
			"",
			...common,
		].join("\n");
	}
	return [
		"Hermes MCP outbound side-effect approval required",
		`Channel: ${record.channel}`,
		`Destination: ${record.destination}`,
		`Conversation: ${record.conversationRef}`,
		`Media refs: ${record.mediaRefs.join(", ") || "(none)"}`,
		"",
		...common,
	].join("\n");
}

function digestBinding(binding: TelclaudeMcpSideEffectApprovalBinding): string {
	const canonical = canonicalJson(binding);
	const hash = crypto.createHash("sha256").update(canonical).digest("hex");
	return `sha256:${hash}`;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(sortKeysDeep(value));
}

function toolKeyForDigest(digest: string): string {
	return `${TELCLAUDE_MCP_SIDE_EFFECT_HUMAN_APPROVAL_TOOL_KEY_PREFIX}:${digest}`;
}

function normalizeTtlMs(value: number): number {
	if (!Number.isFinite(value) || value <= 0 || value > DEFAULT_HUMAN_APPROVAL_TTL_MS) {
		throw new Error("side-effect human approval ttlMs must be between 1 and 300000");
	}
	return value;
}

function normalizeAutoGrantTtlMs(value: number | undefined): number {
	const ttlMs = value ?? MAX_SIDE_EFFECT_APPROVAL_TOKEN_TTL_MS;
	if (!Number.isFinite(ttlMs) || ttlMs <= 0 || ttlMs > MAX_SIDE_EFFECT_APPROVAL_TOKEN_TTL_MS) {
		throw new Error("side-effect auto-grant ttlMs must be between 1 and 60000");
	}
	return ttlMs;
}

function requiredTrimmed(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`${field} is required`);
	}
	return trimmed;
}

function normalizeApprovalNonce(value: string): string {
	return requiredTrimmed(value, "approvalNonce").toLowerCase();
}

function approvalConsumeFailure(error: string): SideEffectHumanApprovalFailure {
	if (error.startsWith("No pending approval")) {
		return failure(
			"approval_binding_lost",
			"pending side-effect approval binding is unavailable; re-request approval",
			true,
		);
	}
	if (error.includes("different chat")) {
		return failure("approval_wrong_chat", error, false);
	}
	if (error.includes("expired")) {
		return failure("approval_expired", error, false);
	}
	return failure("approval_unavailable", error, true);
}

function failure(code: string, reason: string, retryable: boolean): SideEffectHumanApprovalFailure {
	return { ok: false, code, reason, retryable };
}
