import crypto from "node:crypto";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import type { BrowserActCommitSignal } from "../../relay/browser-act-evidence.js";
import type { BrowserAuthorityDomain } from "../../relay/browser-cookie-store.js";
import type { BrowserWriteDisplay } from "../../relay/browser-write-confirm.js";
import {
	TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
} from "../../security/approval-domains.js";
import type {
	AttachmentRef as EdgeAttachmentRef,
	PreparedOutbound,
} from "../edge-adapter-contract.js";

export {
	TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
	TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
} from "../../security/approval-domains.js";

const DEFAULT_SIDE_EFFECT_TTL_MS = 5 * 60 * 1_000;
const PROVIDER_PARAMS_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.provider.params.v1";
const PROVIDER_BODY_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.provider.body.v1";
const OUTBOUND_PARAMS_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.outbound.params.v1";
const OUTBOUND_BODY_HASH_DOMAIN = "telclaude.hermes.mcp.side-effect.outbound.body.v1";
const EDGE_PREPARED_HASH_RE = /^[a-f0-9]{64}$/;
const EDGE_CONTENT_HASH_RE = /^sha256:[a-f0-9]{64}$/;
const RELAY_CONVERSATION_TURN_REF_RE = /^turn_[0-9a-f]{32}$/;

export type TelclaudeMcpSideEffectDomain =
	| "private"
	| "social"
	| "household"
	| "public"
	| "specialist";

export type TelclaudeMcpSideEffectStatus =
	| "prepared"
	| "executing"
	| "executed"
	| "revoked"
	| "failed";
export type TelclaudeMcpOutboundResolvedDestination = PreparedOutbound["resolvedDestination"];
export type TelclaudeMcpOutboundPreparedMediaRef = Pick<
	EdgeAttachmentRef,
	"quarantineId" | "contentHash"
>;
export type TelclaudeMcpOutboundAuthorizationState =
	| "authorized"
	| "approval_required"
	| "denied"
	| "revoked";

export type TelclaudeMcpProviderSideEffectRecord = {
	readonly ref: string;
	readonly kind: "provider";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
	readonly subjectUserId?: string;
	readonly providerAccountRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly wysiwysRender: string;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly status: TelclaudeMcpSideEffectStatus;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly executingAtMs?: number;
	readonly executionApprovalId?: string;
	readonly executedAtMs?: number;
	readonly approvalId?: string;
	readonly revokedAtMs?: number;
	readonly revokeReason?: string;
	readonly failedAtMs?: number;
	readonly failReason?: string;
};

export type TelclaudeMcpOutboundSideEffectRecord = {
	readonly ref: string;
	readonly kind: "outbound";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly channel: string;
	readonly destination: string;
	readonly resolvedDestination: TelclaudeMcpOutboundResolvedDestination;
	readonly requestedBody: string;
	readonly renderedBody: string;
	readonly mediaRefs: readonly string[];
	readonly preparedMediaRefs: readonly TelclaudeMcpOutboundPreparedMediaRef[];
	readonly conversationRef: string;
	readonly authorizationState: TelclaudeMcpOutboundAuthorizationState;
	readonly edgePreparedRef: string;
	readonly edgePreparedHash: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly approvalMetadata: Record<string, unknown>;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly status: TelclaudeMcpSideEffectStatus;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly executingAtMs?: number;
	readonly executionApprovalId?: string;
	readonly executedAtMs?: number;
	readonly approvalId?: string;
	readonly revokedAtMs?: number;
	readonly revokeReason?: string;
	readonly failedAtMs?: number;
	readonly failReason?: string;
};

export type TelclaudeMcpBrowserWriteSideEffectRecord = {
	readonly ref: string;
	readonly kind: "browser-write";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly sessionRef: string;
	readonly host: string;
	readonly originScope: readonly string[];
	readonly browserCredentialRef: string | null;
	readonly browserCredentialCreatedAt: number | null;
	readonly authorityDomain: BrowserAuthorityDomain;
	readonly actionVerb: string;
	readonly actionTarget: string | null;
	readonly evidenceRevision: string;
	readonly evidenceNonce: string;
	readonly evidenceScreenshotHash: string;
	readonly evidenceScreenshotRef: string;
	readonly display: BrowserWriteDisplay;
	readonly commitSignal: BrowserActCommitSignal;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	/**
	 * The single pre-derived WYSIWYS binding hash from `prepareBrowserWrite`. Unlike
	 * provider/outbound this kind does NOT split into params/body — `prepare` stores
	 * the binding immutably and never recomputes it. Re-derivation happens only at
	 * execute time, inside `verifyBrowserWriteExecution`, over freshly-captured
	 * evidence.
	 */
	readonly bindingHash: string;
	readonly status: TelclaudeMcpSideEffectStatus;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	readonly executingAtMs?: number;
	readonly executionApprovalId?: string;
	readonly executedAtMs?: number;
	readonly approvalId?: string;
	readonly revokedAtMs?: number;
	readonly revokeReason?: string;
	readonly failedAtMs?: number;
	readonly failReason?: string;
};

export type TelclaudeMcpSideEffectRecord =
	| TelclaudeMcpProviderSideEffectRecord
	| TelclaudeMcpOutboundSideEffectRecord
	| TelclaudeMcpBrowserWriteSideEffectRecord;

export type TelclaudeMcpProviderSideEffectPrepareInput = {
	readonly kind: "provider";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly params?: Record<string, unknown>;
	readonly subjectUserId?: string;
	readonly providerAccountRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly wysiwysRender: string;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly ttlMs?: number;
};

export type TelclaudeMcpOutboundSideEffectPrepareInput = {
	readonly kind: "outbound";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly channel: string;
	readonly destination: string;
	readonly resolvedDestination: TelclaudeMcpOutboundResolvedDestination;
	readonly requestedBody: string;
	readonly renderedBody: string;
	readonly mediaRefs?: readonly string[];
	readonly preparedMediaRefs: readonly TelclaudeMcpOutboundPreparedMediaRef[];
	readonly conversationRef: string;
	readonly authorizationState: TelclaudeMcpOutboundAuthorizationState;
	readonly edgePreparedRef: string;
	readonly edgePreparedHash: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly approvalMetadata?: Record<string, unknown>;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly ttlMs?: number;
};

export type TelclaudeMcpBrowserWriteSideEffectPrepareInput = {
	readonly kind: "browser-write";
	/**
	 * Caller-supplied ref. Browser-write is the only kind that pre-allocates its ref:
	 * the relay-owned live-page pool is keyed by it BEFORE prepare (the committer later
	 * resolves the held page by this exact ref), so prepare persists the same value
	 * rather than minting a fresh one. Provider/outbound omit it and use `makeRef()`.
	 */
	readonly ref?: string;
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly sessionRef: string;
	readonly host: string;
	readonly originScope: readonly string[];
	readonly browserCredentialRef: string | null;
	readonly browserCredentialCreatedAt: number | null;
	readonly authorityDomain: BrowserAuthorityDomain;
	readonly actionVerb: string;
	readonly actionTarget: string | null;
	readonly evidenceRevision: string;
	readonly evidenceNonce: string;
	readonly evidenceScreenshotHash: string;
	readonly evidenceScreenshotRef: string;
	readonly display: BrowserWriteDisplay;
	readonly commitSignal: BrowserActCommitSignal;
	readonly bindingHash: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly ttlMs?: number;
};

export type TelclaudeMcpSideEffectPrepareInput =
	| TelclaudeMcpProviderSideEffectPrepareInput
	| TelclaudeMcpOutboundSideEffectPrepareInput
	| TelclaudeMcpBrowserWriteSideEffectPrepareInput;

export type TelclaudeMcpProviderApprovalBinding = {
	readonly domainSeparator: typeof TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN;
	readonly ref: string;
	readonly kind: "provider";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly subjectUserId?: string;
	readonly providerAccountRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly turnConversationRef?: string;
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
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly channel: string;
	readonly destination: string;
	readonly resolvedDestination: TelclaudeMcpOutboundResolvedDestination;
	readonly requestedBody: string;
	readonly preparedMediaRefs: readonly TelclaudeMcpOutboundPreparedMediaRef[];
	readonly conversationRef: string;
	readonly authorizationState: TelclaudeMcpOutboundAuthorizationState;
	readonly edgePreparedRef: string;
	readonly edgePreparedHash: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly paramsHash: string;
	readonly bodyHash: string;
	readonly contentHash: string;
};

export type TelclaudeMcpBrowserWriteApprovalBinding = {
	readonly domainSeparator: typeof TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN;
	readonly ref: string;
	readonly kind: "browser-write";
	readonly actorId: string;
	readonly approverActorId: string;
	readonly profileId: string;
	readonly domain: TelclaudeMcpSideEffectDomain;
	readonly sessionRef: string;
	readonly host: string;
	readonly originScope: readonly string[];
	readonly browserCredentialRef: string | null;
	readonly browserCredentialCreatedAt: number | null;
	readonly authorityDomain: BrowserAuthorityDomain;
	readonly actionVerb: string;
	readonly actionTarget: string | null;
	readonly evidenceRevision: string;
	readonly evidenceScreenshotHash: string;
	readonly evidenceScreenshotRef: string;
	readonly approvalRequestId: string;
	readonly approvalRevision: number;
	readonly turnConversationRef?: string;
	readonly idempotencyKey?: string;
	readonly bindingHash: string;
	readonly contentHash: string;
};

export type TelclaudeMcpSideEffectApprovalBinding =
	| TelclaudeMcpProviderApprovalBinding
	| TelclaudeMcpOutboundApprovalBinding
	| TelclaudeMcpBrowserWriteApprovalBinding;

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

export type TelclaudeMcpSideEffectVerifyResult =
	| {
			readonly ok: true;
			readonly record: TelclaudeMcpSideEffectRecord;
			readonly approvalId?: string;
	  }
	| TelclaudeMcpSideEffectRetryableFailure
	| TelclaudeMcpSideEffectTerminalFailure;

export type TelclaudeMcpSideEffectRevokeResult =
	| {
			readonly ok: true;
			readonly record: TelclaudeMcpSideEffectRecord;
	  }
	| TelclaudeMcpSideEffectTerminalFailure;

export type TelclaudeMcpSideEffectClaimResult =
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
	verify(ref: string, approvalToken: string): Promise<TelclaudeMcpSideEffectVerifyResult>;
	/**
	 * Atomic single-flight CAS over the in-memory record map: transitions ONLY
	 * `prepared -> executing` (stamping `executingAtMs` + `executionApprovalId`). A
	 * record already `executing`/`executed`/`failed`/`revoked` (or expired/self-approved)
	 * loses with a terminal failure. The winner is the only caller allowed to reach the
	 * irreversible committer; subsequent concurrent or serial executes lose here, before
	 * any recapture or commit. This closes the double-commit window where two distinct
	 * valid approval tokens could both pass `verify` and both reach `commit()`.
	 */
	claimExecuting(ref: string, approvalId?: string): TelclaudeMcpSideEffectClaimResult;
	/**
	 * Terminally closes a claimed (`executing`) record as `failed` after a pre-side-effect
	 * failure (recapture threw, drift detected) or an ambiguous commit failure. The
	 * consumed approval is NOT reopened; the operator must re-prepare. Browser-write uses
	 * this so an irreversible commit is never re-attempted on the same ref.
	 */
	markFailed(ref: string, reason?: string): TelclaudeMcpSideEffectClaimResult;
	/**
	 * Reverts a claimed (`executing`) record back to `prepared` after a retryable
	 * post-claim failure. Used only by provider/outbound, whose sidecar/delivery failures
	 * are designed to leave the ref retryable. Browser-write never reverts — it fails
	 * terminally via `markFailed`.
	 */
	releaseExecuting(ref: string): TelclaudeMcpSideEffectClaimResult;
	markExecuted(ref: string, approvalId?: string): TelclaudeMcpSideEffectAuthorizeResult;
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
			const record = prepareRecord(input, makeRef, nowMs(), defaultTtlMs);
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

		async verify(ref, approvalToken) {
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
			const approverFailure = terminalFailureForSelfApproval(prepared);
			if (approverFailure) return approverFailure;

			const binding = getTelclaudeMcpSideEffectApprovalBinding(prepared);
			let approval: TelclaudeMcpSideEffectApprovalResult;
			try {
				approval = await options.verifyApproval({
					approvalToken: requiredTrimmed(approvalToken, "approvalToken"),
					binding,
					record: cloneRecord(prepared),
					nowMs: authorizationNowMs,
				});
			} catch (error) {
				return retryableFailure("approval_verification_failed", errorMessage(error), prepared);
			}
			if (!approval.ok) {
				return retryableFailure(approval.code, approval.reason, prepared);
			}

			return {
				ok: true,
				record: cloneRecord(prepared),
				...(approval.approvalId ? { approvalId: approval.approvalId } : {}),
			};
		},

		claimExecuting(ref, approvalId) {
			const normalizedRef = requiredTrimmed(ref, "ref");
			const authorizationNowMs = nowMs();
			const current = records.get(normalizedRef);
			if (!current) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			// Already claimed or executed: the in-flight/replay loser. Distinct from
			// revoked/failed (terminalFailureForRecord) so the caller can surface a precise
			// in-flight code before any committer call.
			if (current.status === "executing") {
				return terminalFailure(
					"effect_execution_in_flight",
					"side effect execution is already in flight for this ref",
					current,
				);
			}
			const currentFailure = terminalFailureForRecord(current);
			if (currentFailure) return currentFailure;
			if (isExpired(current, authorizationNowMs)) {
				return terminalFailure("effect_expired", "side effect approval window expired", current);
			}
			const approverFailure = terminalFailureForSelfApproval(current);
			if (approverFailure) return approverFailure;
			if (current.status !== "prepared") {
				return terminalFailure("effect_invalid_state", "side effect is not prepared", current);
			}

			const claimed = deepFreeze({
				...current,
				status: "executing" as const,
				executingAtMs: authorizationNowMs,
				...(approvalId ? { executionApprovalId: requiredTrimmed(approvalId, "approvalId") } : {}),
			});
			records.set(normalizedRef, claimed);
			return { ok: true, record: cloneRecord(claimed) };
		},

		markFailed(ref, reason) {
			const normalizedRef = requiredTrimmed(ref, "ref");
			const current = records.get(normalizedRef);
			if (!current) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			if (current.status !== "executing") {
				return (
					terminalFailureForRecord(current) ??
					terminalFailure("effect_invalid_state", "side effect is not executing", current)
				);
			}
			const failed = deepFreeze({
				...current,
				status: "failed" as const,
				failedAtMs: nowMs(),
				...(reason ? { failReason: reason } : {}),
			});
			records.set(normalizedRef, failed);
			return { ok: true, record: cloneRecord(failed) };
		},

		releaseExecuting(ref) {
			const normalizedRef = requiredTrimmed(ref, "ref");
			const current = records.get(normalizedRef);
			if (!current) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			if (current.status !== "executing") {
				return (
					terminalFailureForRecord(current) ??
					terminalFailure("effect_invalid_state", "side effect is not executing", current)
				);
			}
			const {
				executingAtMs: _executingAtMs,
				executionApprovalId: _executionApprovalId,
				...rest
			} = current;
			const released = deepFreeze({
				...rest,
				status: "prepared" as const,
			});
			records.set(normalizedRef, released);
			return { ok: true, record: cloneRecord(released) };
		},

		markExecuted(ref, approvalId) {
			const normalizedRef = requiredTrimmed(ref, "ref");
			const authorizationNowMs = nowMs();
			const current = records.get(normalizedRef);
			if (!current) {
				return terminalFailure("effect_not_found", "side effect was not prepared");
			}
			const currentFailure = terminalFailureForRecord(current);
			if (currentFailure) return currentFailure;
			const approverFailure = terminalFailureForSelfApproval(current);
			if (approverFailure) return approverFailure;
			// Execution may only finalize a record that the winner already claimed. A
			// record still `prepared` was never single-flighted; refuse to jump straight
			// to `executed` (this is the hard rule for irreversible browser-write).
			if (current.status !== "executing") {
				return terminalFailure(
					"effect_invalid_state",
					"side effect must be claimed (executing) before it can be marked executed",
					current,
				);
			}
			const normalizedApprovalId = approvalId
				? requiredTrimmed(approvalId, "approvalId")
				: undefined;
			if (current.executionApprovalId && normalizedApprovalId !== current.executionApprovalId) {
				return terminalFailure(
					"effect_invalid_state",
					"executed approvalId does not match the claimed execution approval",
					current,
				);
			}

			const executed = deepFreeze({
				...current,
				status: "executed" as const,
				executedAtMs: authorizationNowMs,
				...(normalizedApprovalId ? { approvalId: normalizedApprovalId } : {}),
			});
			records.set(normalizedRef, executed);
			return { ok: true, record: cloneRecord(executed) };
		},

		async authorize(ref, approvalToken) {
			const verified = await this.verify(ref, approvalToken);
			if (!verified.ok) return verified;
			const claimed = this.claimExecuting(ref, verified.approvalId);
			if (!claimed.ok) return claimed;
			return this.markExecuted(ref, verified.approvalId);
		},
	};
}

export function getTelclaudeMcpSideEffectApprovalBinding(
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectApprovalBinding {
	return immutableClone(approvalBinding(record));
}

export function telclaudeMcpSideEffectRecordIntegrityFailures(
	record: TelclaudeMcpSideEffectRecord,
): string[] {
	const failures: string[] = [];
	if (record.kind === "browser-write") {
		// browser-write carries a single pre-derived bindingHash that is only
		// re-derived at execute time against freshly-captured evidence (the page may
		// legitimately differ from prepare). There is nothing to recompute from the
		// stored record here, so the stored-record integrity check is a no-op.
		return failures;
	}
	if (record.kind === "provider") {
		const paramsHash = hashProviderParams(record);
		const bodyHash = hashProviderBody(record);
		if (record.paramsHash !== paramsHash) {
			failures.push("provider paramsHash does not match current provider params/render");
		}
		if (record.bodyHash !== bodyHash) {
			failures.push("provider bodyHash does not match current provider render");
		}
		return failures;
	}
	const paramsHash = hashOutboundParams(record);
	const bodyHash = hashOutboundBody(record);
	if (record.paramsHash !== paramsHash) {
		failures.push("outbound paramsHash does not match current outbound params/render");
	}
	if (record.bodyHash !== bodyHash) {
		failures.push("outbound bodyHash does not match current outbound render");
	}
	return failures;
}

function prepareRecord(
	input: TelclaudeMcpSideEffectPrepareInput,
	makeRef: () => string,
	nowMs: number,
	defaultTtlMs: number,
): TelclaudeMcpSideEffectRecord {
	switch (input.kind) {
		case "provider":
			return prepareProviderRecord(input, makeRef, nowMs, defaultTtlMs);
		case "outbound":
			return prepareOutboundRecord(input, makeRef, nowMs, defaultTtlMs);
		case "browser-write":
			return prepareBrowserWriteRecord(input, makeRef, nowMs, defaultTtlMs);
		default:
			throw new Error("unknown side-effect prepare kind");
	}
}

function prepareBrowserWriteRecord(
	input: TelclaudeMcpBrowserWriteSideEffectPrepareInput,
	makeRef: () => string,
	nowMs: number,
	defaultTtlMs: number,
): TelclaudeMcpBrowserWriteSideEffectRecord {
	const ttlMs = normalizeDuration(input.ttlMs ?? defaultTtlMs, "ttlMs");
	return deepFreeze({
		// Honor the caller-supplied (pool-bound) ref; fall back to makeRef() only when
		// the caller did not pre-allocate one (e.g. tests that don't pool a live page).
		ref: requiredTrimmed(input.ref ?? makeRef(), "ref"),
		kind: "browser-write" as const,
		actorId: requiredTrimmed(input.actorId, "actorId"),
		approverActorId: requiredTrimmed(input.approverActorId, "approverActorId"),
		profileId: requiredTrimmed(input.profileId, "profileId"),
		domain: input.domain,
		sessionRef: requiredTrimmed(input.sessionRef, "sessionRef"),
		host: requiredTrimmed(input.host, "host").toLowerCase(),
		originScope: normalizeStringList(input.originScope, "originScope"),
		browserCredentialRef:
			input.browserCredentialRef === null
				? null
				: requiredTrimmed(input.browserCredentialRef, "browserCredentialRef"),
		browserCredentialCreatedAt:
			input.browserCredentialRef === null
				? null
				: normalizeTimestamp(input.browserCredentialCreatedAt, "browserCredentialCreatedAt"),
		authorityDomain: normalizeBrowserAuthorityDomain(input.authorityDomain),
		actionVerb: requiredTrimmed(input.actionVerb, "actionVerb").toLowerCase(),
		actionTarget:
			input.actionTarget === null ? null : requiredTrimmed(input.actionTarget, "actionTarget"),
		evidenceRevision: requiredTrimmed(input.evidenceRevision, "evidenceRevision"),
		evidenceNonce: requiredTrimmed(input.evidenceNonce, "evidenceNonce"),
		evidenceScreenshotHash: normalizeSha256Hash(
			input.evidenceScreenshotHash,
			"evidenceScreenshotHash",
		),
		evidenceScreenshotRef: requiredTrimmed(input.evidenceScreenshotRef, "evidenceScreenshotRef"),
		display: normalizeBrowserWriteDisplay(input.display),
		commitSignal: normalizeBrowserCommitSignal(input.commitSignal),
		approvalRequestId: requiredTrimmed(input.approvalRequestId, "approvalRequestId"),
		approvalRevision: normalizeRevision(input.approvalRevision),
		...(input.turnConversationRef
			? { turnConversationRef: normalizeTurnConversationRef(input.turnConversationRef) }
			: {}),
		...(input.idempotencyKey
			? { idempotencyKey: requiredTrimmed(input.idempotencyKey, "idempotencyKey") }
			: {}),
		bindingHash: normalizeBindingHash(input.bindingHash),
		status: "prepared" as const,
		createdAtMs: nowMs,
		expiresAtMs: nowMs + ttlMs,
	});
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
		approverActorId: requiredTrimmed(input.approverActorId, "approverActorId"),
		profileId: requiredTrimmed(input.profileId, "profileId"),
		domain: input.domain,
		providerId: requiredTrimmed(input.providerId, "providerId"),
		service: requiredTrimmed(input.service, "service"),
		action: requiredTrimmed(input.action, "action"),
		params: cloneJsonObject(input.params ?? {}, "params"),
		...(input.subjectUserId
			? { subjectUserId: requiredTrimmed(input.subjectUserId, "subjectUserId") }
			: {}),
		providerAccountRef: requiredTrimmed(input.providerAccountRef, "providerAccountRef"),
		approvalRequestId: requiredTrimmed(input.approvalRequestId, "approvalRequestId"),
		approvalRevision: normalizeRevision(input.approvalRevision),
		wysiwysRender: requiredTrimmed(input.wysiwysRender, "wysiwysRender"),
		...(input.turnConversationRef
			? { turnConversationRef: normalizeTurnConversationRef(input.turnConversationRef) }
			: {}),
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
		approverActorId: requiredTrimmed(input.approverActorId, "approverActorId"),
		profileId: requiredTrimmed(input.profileId, "profileId"),
		domain: input.domain,
		channel: requiredTrimmed(input.channel, "channel"),
		destination: requiredTrimmed(input.destination, "destination"),
		resolvedDestination: normalizeResolvedDestination(input.resolvedDestination),
		requestedBody: requiredString(input.requestedBody, "requestedBody"),
		renderedBody: requiredTrimmed(input.renderedBody, "renderedBody"),
		mediaRefs: normalizeStringList(input.mediaRefs ?? [], "mediaRefs"),
		preparedMediaRefs: normalizePreparedMediaRefs(input.preparedMediaRefs),
		conversationRef: requiredTrimmed(input.conversationRef, "conversationRef"),
		authorizationState: normalizeAuthorizationState(input.authorizationState),
		edgePreparedRef: requiredTrimmed(input.edgePreparedRef, "edgePreparedRef"),
		edgePreparedHash: normalizeEdgePreparedHash(input.edgePreparedHash),
		approvalRequestId: requiredTrimmed(input.approvalRequestId, "approvalRequestId"),
		approvalRevision: normalizeRevision(input.approvalRevision),
		approvalMetadata: cloneJsonObject(input.approvalMetadata ?? {}, "approvalMetadata"),
		...(input.turnConversationRef
			? { turnConversationRef: normalizeTurnConversationRef(input.turnConversationRef) }
			: {}),
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
		providerId: record.providerId,
		service: record.service,
		action: record.action,
		params: record.params,
		subjectUserId: record.subjectUserId ?? null,
		providerAccountRef: record.providerAccountRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		wysiwysRender: record.wysiwysRender,
		turnConversationRef: record.turnConversationRef ?? null,
		idempotencyKey: record.idempotencyKey ?? null,
	});
}

function hashProviderBody(record: ProviderBindingFields): string {
	return canonicalDigest({
		domainSeparator: PROVIDER_BODY_HASH_DOMAIN,
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		providerId: record.providerId,
		service: record.service,
		action: record.action,
		subjectUserId: record.subjectUserId ?? null,
		providerAccountRef: record.providerAccountRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		wysiwysRender: record.wysiwysRender,
		turnConversationRef: record.turnConversationRef ?? null,
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
		resolvedDestination: record.resolvedDestination,
		requestedBody: record.requestedBody,
		mediaRefs: record.mediaRefs,
		preparedMediaRefs: record.preparedMediaRefs,
		conversationRef: record.conversationRef,
		authorizationState: record.authorizationState,
		edgePreparedRef: record.edgePreparedRef,
		edgePreparedHash: record.edgePreparedHash,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		approvalMetadata: record.approvalMetadata,
		turnConversationRef: record.turnConversationRef ?? null,
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
		resolvedDestination: record.resolvedDestination,
		requestedBody: record.requestedBody,
		renderedBody: record.renderedBody,
		mediaRefs: record.mediaRefs,
		preparedMediaRefs: record.preparedMediaRefs,
		conversationRef: record.conversationRef,
		authorizationState: record.authorizationState,
		edgePreparedRef: record.edgePreparedRef,
		edgePreparedHash: record.edgePreparedHash,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		approvalMetadata: record.approvalMetadata,
		turnConversationRef: record.turnConversationRef ?? null,
		idempotencyKey: record.idempotencyKey ?? null,
	});
}

function hashProviderApprovalContent(record: TelclaudeMcpProviderSideEffectRecord): string {
	return canonicalDigest({
		domainSeparator: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
		actorId: record.actorId,
		approverActorId: record.approverActorId,
		profileId: record.profileId,
		domain: record.domain,
		providerId: record.providerId,
		service: record.service,
		action: record.action,
		subjectUserId: record.subjectUserId ?? null,
		providerAccountRef: record.providerAccountRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		turnConversationRef: record.turnConversationRef ?? null,
		idempotencyKey: record.idempotencyKey ?? null,
		paramsHash: record.paramsHash,
		bodyHash: record.bodyHash,
	});
}

function hashOutboundApprovalContent(record: TelclaudeMcpOutboundSideEffectRecord): string {
	return canonicalDigest({
		domainSeparator: TELCLAUDE_MCP_OUTBOUND_APPROVAL_DOMAIN,
		actorId: record.actorId,
		approverActorId: record.approverActorId,
		profileId: record.profileId,
		domain: record.domain,
		channel: record.channel,
		destination: record.destination,
		resolvedDestination: record.resolvedDestination,
		requestedBody: record.requestedBody,
		preparedMediaRefs: record.preparedMediaRefs,
		conversationRef: record.conversationRef,
		authorizationState: record.authorizationState,
		edgePreparedRef: record.edgePreparedRef,
		edgePreparedHash: record.edgePreparedHash,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		turnConversationRef: record.turnConversationRef ?? null,
		idempotencyKey: record.idempotencyKey ?? null,
		paramsHash: record.paramsHash,
		bodyHash: record.bodyHash,
	});
}

function hashBrowserWriteApprovalContent(record: TelclaudeMcpBrowserWriteSideEffectRecord): string {
	return canonicalDigest({
		domainSeparator: TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
		actorId: record.actorId,
		approverActorId: record.approverActorId,
		profileId: record.profileId,
		domain: record.domain,
		sessionRef: record.sessionRef,
		host: record.host,
		originScope: record.originScope,
		browserCredentialRef: record.browserCredentialRef,
		browserCredentialCreatedAt: record.browserCredentialCreatedAt,
		authorityDomain: record.authorityDomain,
		actionVerb: record.actionVerb,
		actionTarget: record.actionTarget,
		evidenceRevision: record.evidenceRevision,
		evidenceScreenshotHash: record.evidenceScreenshotHash,
		evidenceScreenshotRef: record.evidenceScreenshotRef,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		turnConversationRef: record.turnConversationRef ?? null,
		idempotencyKey: record.idempotencyKey ?? null,
		bindingHash: record.bindingHash,
	});
}

function approvalBinding(
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectApprovalBinding {
	if (record.kind === "browser-write") {
		return {
			domainSeparator: TELCLAUDE_MCP_BROWSER_WRITE_APPROVAL_DOMAIN,
			ref: record.ref,
			kind: "browser-write",
			actorId: record.actorId,
			approverActorId: record.approverActorId,
			profileId: record.profileId,
			domain: record.domain,
			sessionRef: record.sessionRef,
			host: record.host,
			originScope: record.originScope,
			browserCredentialRef: record.browserCredentialRef,
			browserCredentialCreatedAt: record.browserCredentialCreatedAt,
			authorityDomain: record.authorityDomain,
			actionVerb: record.actionVerb,
			actionTarget: record.actionTarget,
			evidenceRevision: record.evidenceRevision,
			evidenceScreenshotHash: record.evidenceScreenshotHash,
			evidenceScreenshotRef: record.evidenceScreenshotRef,
			approvalRequestId: record.approvalRequestId,
			approvalRevision: record.approvalRevision,
			...(record.turnConversationRef ? { turnConversationRef: record.turnConversationRef } : {}),
			...(record.idempotencyKey ? { idempotencyKey: record.idempotencyKey } : {}),
			bindingHash: record.bindingHash,
			contentHash: hashBrowserWriteApprovalContent(record),
		};
	}
	if (record.kind === "provider") {
		return {
			domainSeparator: TELCLAUDE_MCP_PROVIDER_APPROVAL_DOMAIN,
			ref: record.ref,
			kind: "provider",
			actorId: record.actorId,
			approverActorId: record.approverActorId,
			profileId: record.profileId,
			domain: record.domain,
			providerId: record.providerId,
			service: record.service,
			action: record.action,
			...(record.subjectUserId ? { subjectUserId: record.subjectUserId } : {}),
			providerAccountRef: record.providerAccountRef,
			approvalRequestId: record.approvalRequestId,
			approvalRevision: record.approvalRevision,
			...(record.turnConversationRef ? { turnConversationRef: record.turnConversationRef } : {}),
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
		approverActorId: record.approverActorId,
		profileId: record.profileId,
		domain: record.domain,
		channel: record.channel,
		destination: record.destination,
		resolvedDestination: record.resolvedDestination,
		requestedBody: record.requestedBody,
		preparedMediaRefs: record.preparedMediaRefs,
		conversationRef: record.conversationRef,
		authorizationState: record.authorizationState,
		edgePreparedRef: record.edgePreparedRef,
		edgePreparedHash: record.edgePreparedHash,
		approvalRequestId: record.approvalRequestId,
		approvalRevision: record.approvalRevision,
		...(record.turnConversationRef ? { turnConversationRef: record.turnConversationRef } : {}),
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
	if (record.status === "failed") {
		return terminalFailure("effect_failed", "side effect terminally failed; re-prepare", record);
	}
	return null;
}

function terminalFailureForSelfApproval(
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectTerminalFailure | null {
	if (record.actorId !== record.approverActorId) return null;
	if (record.kind === "provider") {
		return terminalFailure(
			"provider_distinct_human_approver_required",
			"provider side effects require approval by a distinct human approver",
			record,
		);
	}
	return terminalFailure(
		"side_effect_distinct_human_approver_required",
		"side effects require approval by a distinct human approver",
		record,
	);
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

function normalizeResolvedDestination(
	value: TelclaudeMcpOutboundResolvedDestination,
): TelclaudeMcpOutboundResolvedDestination {
	const destination = cloneJsonValue(value, "resolvedDestination");
	const conversationId = destination.conversationId
		? requiredTrimmed(destination.conversationId, "resolvedDestination.conversationId")
		: undefined;
	switch (destination.kind) {
		case "thread":
			return {
				kind: "thread",
				threadId: requiredTrimmed(destination.threadId ?? "", "resolvedDestination.threadId"),
				...(conversationId ? { conversationId } : {}),
			};
		case "actor":
			return {
				kind: "actor",
				actorId: requiredTrimmed(destination.actorId ?? "", "resolvedDestination.actorId"),
				...(conversationId ? { conversationId } : {}),
			};
		case "address":
			return {
				kind: "address",
				addressRef: requiredTrimmed(destination.addressRef ?? "", "resolvedDestination.addressRef"),
				...(conversationId ? { conversationId } : {}),
			};
		default:
			throw new Error("side-effect resolvedDestination.kind is invalid");
	}
}

function normalizePreparedMediaRefs(
	values: readonly TelclaudeMcpOutboundPreparedMediaRef[],
): readonly TelclaudeMcpOutboundPreparedMediaRef[] {
	return cloneJsonValue(
		values.map((value, index) => {
			const quarantineId = requiredTrimmed(
				value.quarantineId,
				`preparedMediaRefs[${index}].quarantineId`,
			);
			const contentHash = requiredTrimmed(
				value.contentHash,
				`preparedMediaRefs[${index}].contentHash`,
			);
			if (!EDGE_CONTENT_HASH_RE.test(contentHash)) {
				throw new Error("side-effect preparedMediaRefs contentHash must be a sha256 digest");
			}
			return { quarantineId, contentHash };
		}),
		"preparedMediaRefs",
	);
}

function normalizeAuthorizationState(
	value: TelclaudeMcpOutboundAuthorizationState,
): TelclaudeMcpOutboundAuthorizationState {
	if (
		value === "authorized" ||
		value === "approval_required" ||
		value === "denied" ||
		value === "revoked"
	) {
		return value;
	}
	throw new Error("side-effect authorizationState is invalid");
}

function normalizeRevision(value: number): number {
	if (!Number.isInteger(value) || value < 1) {
		throw new Error("approvalRevision must be a positive integer");
	}
	return value;
}

const BROWSER_AUTHORITY_DOMAINS: readonly BrowserAuthorityDomain[] = [
	"private",
	"public-social",
	"household",
	"public",
];

function normalizeBrowserAuthorityDomain(value: BrowserAuthorityDomain): BrowserAuthorityDomain {
	if (BROWSER_AUTHORITY_DOMAINS.includes(value)) return value;
	throw new Error("side-effect authorityDomain is invalid");
}

function normalizeBindingHash(value: string): string {
	const trimmed = requiredTrimmed(value, "bindingHash");
	if (!/^sha256:[a-f0-9]{64}$/.test(trimmed)) {
		throw new Error("side-effect bindingHash must be a sha256 digest");
	}
	return trimmed;
}

function normalizeSha256Hash(value: string, field: string): string {
	const trimmed = requiredTrimmed(value, field);
	if (!/^sha256:[a-f0-9]{64}$/.test(trimmed)) {
		throw new Error(`side-effect ${field} must be a sha256 digest`);
	}
	return trimmed;
}

function normalizeTimestamp(value: number | null, field: string): number {
	if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
		throw new Error(`side-effect ${field} must be a non-negative integer timestamp`);
	}
	return value;
}

function normalizeBrowserWriteDisplay(value: BrowserWriteDisplay): BrowserWriteDisplay {
	return cloneJsonValue(
		{
			verb: requiredTrimmed(value.verb, "display.verb").toLowerCase(),
			target: value.target === null ? null : requiredTrimmed(value.target, "display.target"),
			urlOrigin:
				value.urlOrigin === null ? null : requiredTrimmed(value.urlOrigin, "display.urlOrigin"),
			// Already-redacted display strings from prepareBrowserWrite — kept as data only.
			submittedValues: normalizeBrowserWriteSubmittedValues(value.submittedValues),
		},
		"display",
	);
}

function normalizeBrowserWriteSubmittedValues(value: string[] | null): string[] | null {
	if (value === null) return null;
	if (!Array.isArray(value) || value.length === 0) return null;
	return value.map((entry, index) => requiredString(entry, `display.submittedValues[${index}]`));
}

function normalizeBrowserCommitSignal(value: BrowserActCommitSignal): BrowserActCommitSignal {
	if (value.forceConfirm !== true) {
		throw new Error("browser-write commitSignal.forceConfirm must be true");
	}
	return cloneJsonValue(
		{
			forceConfirm: true,
			reasons: value.reasons.map((reason, index) =>
				requiredTrimmed(reason, `commitSignal.reasons[${index}]`),
			),
			observed: {
				navigation: Boolean(value.observed.navigation),
				formSubmit: Boolean(value.observed.formSubmit),
				mutatingRequest: Boolean(value.observed.mutatingRequest),
			},
		},
		"commitSignal",
	);
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

function requiredString(value: string, field: string): string {
	if (typeof value !== "string") {
		throw new Error(`side-effect ${field} is required`);
	}
	return value;
}

function normalizeEdgePreparedHash(value: string): string {
	const trimmed = requiredTrimmed(value, "edgePreparedHash");
	if (!EDGE_PREPARED_HASH_RE.test(trimmed)) {
		throw new Error("side-effect edgePreparedHash must be a 64-character lowercase hex digest");
	}
	return trimmed;
}

function normalizeTurnConversationRef(value: string): string {
	const trimmed = requiredTrimmed(value, "turnConversationRef");
	if (!RELAY_CONVERSATION_TURN_REF_RE.test(trimmed)) {
		throw new Error("side-effect turnConversationRef must be a relay turn ref");
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
	| "providerId"
	| "service"
	| "action"
	| "params"
	| "subjectUserId"
	| "providerAccountRef"
	| "approvalRequestId"
	| "approvalRevision"
	| "wysiwysRender"
	| "turnConversationRef"
	| "idempotencyKey"
>;

type OutboundBindingFields = Pick<
	TelclaudeMcpOutboundSideEffectRecord,
	| "actorId"
	| "profileId"
	| "domain"
	| "channel"
	| "destination"
	| "resolvedDestination"
	| "requestedBody"
	| "renderedBody"
	| "mediaRefs"
	| "preparedMediaRefs"
	| "conversationRef"
	| "authorizationState"
	| "edgePreparedRef"
	| "edgePreparedHash"
	| "approvalRequestId"
	| "approvalRevision"
	| "approvalMetadata"
	| "turnConversationRef"
	| "idempotencyKey"
>;
