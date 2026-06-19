import type { BrowserActEvidence } from "../../relay/browser-act-evidence.js";
import {
	type BrowserWriteContext,
	type PreparedBrowserWrite,
	verifyBrowserWriteExecution,
} from "../../relay/browser-write-confirm.js";
import type { OutboundDeliveryDispatcher } from "../../relay/outbound-delivery-dispatcher.js";
import type { ProviderProxyRequest, ProviderProxyResponse } from "../../relay/provider-proxy.js";
import { redactSecrets } from "../../security/output-filter.js";
import {
	type AttachmentRef,
	DeliveryReceiptSchema,
	EdgeAdapterSchemaVersions,
	type PreparedOutbound,
	PreparedOutboundSchema,
} from "../edge-adapter-contract.js";
import { edgePreparedPayloadHash } from "../edge-adapter-runtime.js";
import type {
	RelayConversation,
	RelayConversationInboundTurn,
} from "../relay-conversation-store.js";
import { targetableRelayConversationMembers } from "../relay-conversation-store.js";
import type {
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpBridgeDependencies,
	TelclaudeMcpOutboundExecuteRequest,
	TelclaudeMcpProviderExecuteWriteRequest,
} from "./bridge.js";
import type {
	TelclaudeMcpBrowserWriteSideEffectRecord,
	TelclaudeMcpOutboundSideEffectRecord,
	TelclaudeMcpProviderSideEffectRecord,
	TelclaudeMcpSideEffectAuthorizeResult,
	TelclaudeMcpSideEffectLedger,
	TelclaudeMcpSideEffectRecord,
	TelclaudeMcpSideEffectTerminalFailure,
} from "./side-effect-ledger.js";

/**
 * Re-derives evidence and commits a confirmed browser write. Injected like the
 * provider proxy / outbound dispatcher so the ledger never imports the broker.
 *
 * `recaptureEvidence` MUST recapture the live page with the record's stored
 * `evidenceNonce` and `observedSignals: {}` — that is the only way an unchanged page
 * re-produces the same revision/url/submitted-value HMACs and re-matches the prepared
 * `bindingHash`. A fresh random nonce (or a mutated page) yields a different binding
 * hash and `verifyBrowserWriteExecution` fails closed with `write_confirm_binding_drift`.
 * `commit` runs the actual state-changing act and returns a small JSON receipt; it is
 * called only after verification passes.
 */
export interface BrowserWriteCommitter {
	recaptureEvidence(record: TelclaudeMcpBrowserWriteSideEffectRecord): Promise<BrowserActEvidence>;
	commit(
		record: TelclaudeMcpBrowserWriteSideEffectRecord,
	): Promise<{ readonly receipt: Record<string, unknown> }>;
}

export type TelclaudeMcpBrowserWriteExecuteRequest = {
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: string;
	readonly actionRef: string;
};

export type TelclaudeMcpBrowserWriteExecuteResult =
	| { readonly ok: true; readonly receipt: Record<string, unknown> }
	| (TelclaudeMcpSideEffectTerminalFailure & { readonly ok: false })
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
			readonly retryable: boolean;
			readonly record?: TelclaudeMcpSideEffectRecord;
	  };

export type TelclaudeMcpLedgerExecuteDependencies = Pick<
	TelclaudeMcpBridgeDependencies,
	"providerExecuteWrite" | "outboundExecute" | "browseActExecute"
> & {
	/**
	 * Execute a confirmed browser write (S3) by ledger ref. This is the concrete
	 * name the committed ledger/tests use; `browseActExecute` is the bridge-facing
	 * alias of the SAME function so the dependency surface composes by spread.
	 */
	browserWriteExecute(
		request: TelclaudeMcpBrowserWriteExecuteRequest,
	): Promise<TelclaudeMcpBrowserWriteExecuteResult>;
};

export type TelclaudeMcpProviderSidecarApprovalTokenRequest = {
	readonly record: TelclaudeMcpProviderSideEffectRecord;
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
	readonly subjectUserId?: string;
	readonly actorUserId: string;
	readonly approvalNonce: string;
};

export type TelclaudeMcpProviderSidecarApprovalTokenIssuer = (
	request: TelclaudeMcpProviderSidecarApprovalTokenRequest,
) => string | Promise<string>;

export type TelclaudeMcpSideEffectApprovalTokenResolution =
	| {
			readonly ok: true;
			readonly approvalToken: string;
			readonly approvalId?: string;
			readonly finalize?: () => void;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
			readonly retryable: boolean;
	  };

export type TelclaudeMcpSideEffectApprovalTokenResolver = (request: {
	readonly actionRef: string;
	readonly record: TelclaudeMcpSideEffectRecord;
}) =>
	| TelclaudeMcpSideEffectApprovalTokenResolution
	| Promise<TelclaudeMcpSideEffectApprovalTokenResolution>;

export type TelclaudeMcpOutboundConversationResolver = (
	conversationRef: string,
	nowMs: number,
) => RelayConversation | null | Promise<RelayConversation | null>;

export type TelclaudeMcpInboundTurnAuthorityResolver = (request: {
	readonly turnConversationRef: string;
	readonly expectedConversationRef?: string;
	readonly actorId: string;
	readonly profileId: string;
	readonly domain: string;
	readonly channel?: string;
	readonly conversationId?: string;
	readonly nowMs: number;
}) => RelayConversationInboundTurn | null | Promise<RelayConversationInboundTurn | null>;

export type CreateTelclaudeMcpLedgerExecuteDependenciesOptions = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly providerProxy?: ProviderProxy;
	readonly providerApprovalTokenIssuer?: TelclaudeMcpProviderSidecarApprovalTokenIssuer;
	readonly sideEffectApprovalTokenResolver?: TelclaudeMcpSideEffectApprovalTokenResolver;
	readonly resolveAuthorizedOutboundConversation?: TelclaudeMcpOutboundConversationResolver;
	readonly resolveAuthorizedInboundTurn?: TelclaudeMcpInboundTurnAuthorityResolver;
	readonly outboundDeliveryDispatcher?: OutboundDeliveryDispatcher;
	readonly browserWriteCommitter?: BrowserWriteCommitter;
	readonly nowMs?: () => number;
};

type ProviderProxy = (request: ProviderProxyRequest) => Promise<ProviderProxyResponse>;

const PROVIDER_PATH = "/v1/fetch";

export function createTelclaudeMcpLedgerExecuteDependencies(
	options: CreateTelclaudeMcpLedgerExecuteDependenciesOptions,
): TelclaudeMcpLedgerExecuteDependencies {
	const deps: Omit<TelclaudeMcpLedgerExecuteDependencies, "browseActExecute"> = {
		async providerExecuteWrite(request) {
			const prepared = await providerLedgerEffectRecord(
				options.ledger,
				request.actionRef,
				request,
				options.nowMs?.() ?? Date.now(),
				options.resolveAuthorizedInboundTurn,
			);
			if (!prepared.ok) return prepared;
			const resolved = await resolveSideEffectApprovalToken(
				options.sideEffectApprovalTokenResolver,
				request.actionRef,
				prepared.record,
			);
			if (!resolved.ok) return resolved;
			const authorized = await options.ledger.verify(request.actionRef, resolved.approvalToken);
			if (!authorized.ok) return authorized;
			const approvalId = authorized.approvalId ?? resolved.approvalId;
			// Single-flight CAS: claim the ref after verify so two distinct valid tokens
			// cannot both reach the provider sidecar. The loser fails terminally in-flight.
			const claim = options.ledger.claimExecuting(request.actionRef, approvalId);
			if (!claim.ok) return claim;
			if (!options.providerProxy) {
				const executed = await options.ledger.markExecuted(request.actionRef, approvalId);
				if (executed.ok) resolved.finalize?.();
				return executed;
			}
			resolved.finalize?.();
			const executed = await executeProviderSidecar(
				options.providerProxy,
				claim.record as TelclaudeMcpProviderSideEffectRecord,
				options.providerApprovalTokenIssuer,
			);
			if (!executed.ok) {
				// Provider sidecar failures are retryable by design: release the claim back
				// to `prepared` rather than failing terminally (browser-write differs), and
				// report the released (prepared) record on the failure.
				return releaseAndReport(options.ledger, request.actionRef, executed);
			}
			return options.ledger.markExecuted(request.actionRef, approvalId);
		},
		async outboundExecute(request) {
			const nowMs = options.nowMs?.() ?? Date.now();
			const checked = await outboundLedgerEffectRecord(
				options.ledger,
				request.outboundRef,
				request,
				nowMs,
				options.resolveAuthorizedOutboundConversation,
				options.resolveAuthorizedInboundTurn,
			);
			if (!checked.ok) return checked;
			if (checked.record.channel === "whatsapp" && !options.outboundDeliveryDispatcher) {
				return terminalFailure(
					"outbound_delivery_dispatcher_missing",
					"outbound delivery dispatcher is not configured for WhatsApp",
					checked.record,
				);
			}
			const resolved = await resolveSideEffectApprovalToken(
				options.sideEffectApprovalTokenResolver,
				request.outboundRef,
				checked.record,
			);
			if (!resolved.ok) return resolved;
			const authorized = await options.ledger.verify(request.outboundRef, resolved.approvalToken);
			if (!authorized.ok) return authorized;
			const approvalId = authorized.approvalId ?? resolved.approvalId;
			// Single-flight CAS: claim the ref after verify so two distinct valid tokens
			// cannot both reach the outbound delivery dispatcher.
			const claim = options.ledger.claimExecuting(request.outboundRef, approvalId);
			if (!claim.ok) return claim;
			if (
				options.outboundDeliveryDispatcher &&
				claim.record.kind === "outbound" &&
				claim.record.channel === "whatsapp"
			) {
				const delivered = await executeOutboundDelivery(
					options.outboundDeliveryDispatcher,
					claim.record as TelclaudeMcpOutboundSideEffectRecord,
				);
				if (!delivered.ok) {
					// Delivery failure is retryable: release the claim to `prepared`.
					return releaseAndReport(options.ledger, request.outboundRef, delivered);
				}
			}
			const executed = await options.ledger.markExecuted(request.outboundRef, approvalId);
			if (executed.ok) resolved.finalize?.();
			return executed;
		},
		async browserWriteExecute(request) {
			const nowMs = options.nowMs?.() ?? Date.now();
			const checked = browserWriteLedgerEffectRecord(
				options.ledger,
				request.actionRef,
				request,
				nowMs,
			);
			if (!checked.ok) return checked;
			if (!options.browserWriteCommitter) {
				return terminalFailure(
					"browser_write_committer_missing",
					"browser-write committer is not configured",
					checked.record,
				);
			}
			const resolved = await resolveSideEffectApprovalToken(
				options.sideEffectApprovalTokenResolver,
				request.actionRef,
				checked.record,
			);
			if (!resolved.ok) return resolved;
			// Verify the approval token FIRST (so an invalid token cannot DoS a prepared
			// ref by stealing its single-flight claim), THEN atomically claim the ref.
			const authorized = await options.ledger.verify(request.actionRef, resolved.approvalToken);
			if (!authorized.ok) return authorized;
			const approvalId = authorized.approvalId ?? resolved.approvalId;

			// Single-flight CAS: only the winner of `prepared -> executing` may proceed to
			// the irreversible committer. A concurrent execute bearing a second distinct
			// valid token (e.g. a second human approval) loses HERE — before recapture or
			// commit — with a terminal in-flight/invalid-state error. A serial second
			// execute is already rejected at `verify` (executed/failed are terminal).
			const claim = options.ledger.claimExecuting(request.actionRef, approvalId);
			if (!claim.ok) return claim;
			const record = claim.record as TelclaudeMcpBrowserWriteSideEffectRecord;

			// Recapture the live page immediately-before, with the STORED nonce, then
			// re-derive the binding over the CURRENT action + fresh evidence. Any drift
			// (page mutated, action redirected, values changed, wrong nonce) fails closed
			// here. Because the ref is already claimed and a browser commit is irreversible,
			// a post-claim failure closes the record TERMINALLY (`failed`) — it is NOT
			// reverted to `prepared` and the consumed approval is NOT reopened. The operator
			// must re-prepare.
			let currentEvidence: BrowserActEvidence;
			try {
				currentEvidence = await options.browserWriteCommitter.recaptureEvidence(record);
			} catch (error) {
				const reason = redactSecrets(error instanceof Error ? error.message : String(error));
				options.ledger.markFailed(request.actionRef, `browser_write_recapture_failed: ${reason}`);
				return terminalFailure(
					"browser_write_recapture_failed",
					reason,
					options.ledger.get(request.actionRef) ?? record,
				);
			}
			const verification = verifyBrowserWriteExecution({
				prepared: reconstructPreparedBrowserWrite(record),
				context: browserWriteContext(record),
				action: { verb: record.actionVerb, target: record.actionTarget ?? undefined },
				currentEvidence,
				now: nowMs,
			});
			if (!verification.ok) {
				options.ledger.markFailed(request.actionRef, `browser_write_${verification.reason}`);
				return terminalFailure(
					`browser_write_${verification.reason}`,
					"browser write failed confirmation re-verification",
					options.ledger.get(request.actionRef) ?? record,
				);
			}

			let committed: { readonly receipt: Record<string, unknown> };
			try {
				committed = await options.browserWriteCommitter.commit(record);
			} catch (error) {
				// Ambiguous commit failure: fail closed, terminal, NO second commit attempt
				// on this ref. The side effect may or may not have landed.
				const reason = redactSecrets(error instanceof Error ? error.message : String(error));
				options.ledger.markFailed(request.actionRef, `browser_write_commit_failed: ${reason}`);
				return terminalFailure(
					"browser_write_commit_failed",
					reason,
					options.ledger.get(request.actionRef) ?? record,
				);
			}
			const executed = await options.ledger.markExecuted(request.actionRef, approvalId);
			if (!executed.ok) return executed;
			resolved.finalize?.();
			return { ok: true, receipt: committed.receipt };
		},
	};
	return {
		...deps,
		// Bridge-facing alias: tc_browse_act_execute resolves to the SAME ledger-driven
		// browser-write executor (verify → single-flight claim → recapture → re-verify →
		// commit). The runtime supplies only the actionRef; the stamp's extra authority
		// fields are accepted structurally and ignored by browserWriteExecute.
		browseActExecute: (request) => deps.browserWriteExecute(request),
	};
}

function browserWriteLedgerEffectRecord(
	ledger: TelclaudeMcpSideEffectLedger,
	ref: string,
	request: TelclaudeMcpBrowserWriteExecuteRequest,
	nowMs: number,
):
	| { readonly ok: true; readonly record: TelclaudeMcpBrowserWriteSideEffectRecord }
	| TelclaudeMcpSideEffectTerminalFailure {
	const record = ledger.get(ref);
	if (!record) {
		return terminalFailure("effect_not_found", "side effect was not prepared");
	}
	if (record.kind !== "browser-write") {
		return terminalFailure(
			"effect_kind_mismatch",
			"side effect kind mismatch: expected browser-write",
		);
	}
	if (
		record.actorId !== request.actorId ||
		record.profileId !== request.profileId ||
		record.domain !== request.domain
	) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch", record);
	}
	const terminal = terminalFailureBeforeApproval(record, nowMs);
	if (terminal) return terminal;
	return { ok: true, record };
}

function reconstructPreparedBrowserWrite(
	record: TelclaudeMcpBrowserWriteSideEffectRecord,
): PreparedBrowserWrite {
	return {
		writeRef: record.ref,
		actor: record.actorId,
		approver: record.approverActorId,
		profile: record.profileId,
		authorityDomain: record.authorityDomain,
		host: record.host,
		originScope: record.originScope,
		evidenceRevision: record.evidenceRevision,
		evidenceNonce: record.evidenceNonce,
		bindingHash: record.bindingHash,
		display: record.display,
		commitSignal: record.commitSignal,
		createdAtMs: record.createdAtMs,
		expiresAtMs: record.expiresAtMs,
	};
}

function browserWriteContext(
	record: TelclaudeMcpBrowserWriteSideEffectRecord,
): BrowserWriteContext {
	return {
		sessionRef: record.sessionRef,
		actor: record.actorId,
		profile: record.profileId,
		authorityDomain: record.authorityDomain,
		host: record.host,
		originScope: record.originScope,
	};
}

async function providerLedgerEffectRecord(
	ledger: TelclaudeMcpSideEffectLedger,
	ref: string,
	request: TelclaudeMcpProviderExecuteWriteRequest,
	nowMs: number,
	resolveAuthorizedInboundTurn: TelclaudeMcpInboundTurnAuthorityResolver | undefined,
): Promise<
	| { readonly ok: true; readonly record: TelclaudeMcpProviderSideEffectRecord }
	| TelclaudeMcpSideEffectTerminalFailure
> {
	const record = ledger.get(ref);
	if (!record) {
		return terminalFailure("effect_not_found", "side effect was not prepared");
	}
	if (record.kind !== "provider") {
		return terminalFailure("effect_kind_mismatch", "side effect kind mismatch: expected provider");
	}
	if (!sameAuthority(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	const turnFailure = await liveTurnAuthorityFailure(
		record,
		request,
		nowMs,
		resolveAuthorizedInboundTurn,
	);
	if (turnFailure) return turnFailure;
	if (!sameProviderScope(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	const terminal = terminalFailureBeforeApproval(record, nowMs);
	if (terminal) return terminal;
	return { ok: true, record };
}

async function outboundLedgerEffectRecord(
	ledger: TelclaudeMcpSideEffectLedger,
	ref: string,
	request: TelclaudeMcpOutboundExecuteRequest,
	nowMs: number,
	resolveAuthorizedOutboundConversation: TelclaudeMcpOutboundConversationResolver | undefined,
	resolveAuthorizedInboundTurn: TelclaudeMcpInboundTurnAuthorityResolver | undefined,
): Promise<
	| { readonly ok: true; readonly record: TelclaudeMcpOutboundSideEffectRecord }
	| TelclaudeMcpSideEffectTerminalFailure
> {
	const record = ledger.get(ref);
	if (!record) {
		return terminalFailure("effect_not_found", "side effect was not prepared");
	}
	if (record.kind !== "outbound") {
		return terminalFailure("effect_kind_mismatch", "side effect kind mismatch: expected outbound");
	}
	if (!sameAuthority(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	const turnFailure = await liveTurnAuthorityFailure(
		record,
		request,
		nowMs,
		resolveAuthorizedInboundTurn,
	);
	if (turnFailure) return turnFailure;
	if (!sameOutboundScope(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	const terminal = terminalFailureBeforeApproval(record, nowMs);
	if (terminal) return terminal;
	const edgeFailure = edgePreparedHashFailure(record);
	if (edgeFailure) return edgeFailure;
	const conversationFailure = await liveOutboundConversationFailure(
		record,
		resolveAuthorizedOutboundConversation,
		nowMs,
	);
	if (conversationFailure) return conversationFailure;
	return { ok: true, record };
}

async function liveTurnAuthorityFailure(
	record: TelclaudeMcpSideEffectRecord,
	request: TelclaudeMcpAuthorityStamp,
	nowMs: number,
	resolveAuthorizedInboundTurn: TelclaudeMcpInboundTurnAuthorityResolver | undefined,
): Promise<TelclaudeMcpSideEffectTerminalFailure | null> {
	if (!record.turnConversationRef) return null;
	if (request.turnConversationRef !== record.turnConversationRef) {
		return terminalFailure(
			"effect_turn_authority_mismatch",
			"side effect turn authority mismatch",
			record,
		);
	}
	if (!resolveAuthorizedInboundTurn) {
		return terminalFailure(
			"effect_turn_authority_unavailable",
			"side effect turn authority resolver is not configured",
			record,
		);
	}
	let turn: RelayConversationInboundTurn | null;
	try {
		turn = await resolveAuthorizedInboundTurn(turnAuthorityRequest(record, nowMs));
	} catch (error) {
		return terminalFailure(
			"effect_turn_authority_unavailable",
			redactSecrets(error instanceof Error ? error.message : String(error)),
			record,
		);
	}
	if (!turn) {
		return terminalFailure(
			"effect_turn_authority_unavailable",
			"side effect turn authority is unavailable",
			record,
		);
	}
	if (!sameTurnAuthority(record, turn)) {
		return terminalFailure(
			"effect_turn_authority_mismatch",
			"side effect turn authority mismatch",
			record,
		);
	}
	return null;
}

function turnAuthorityRequest(
	record: TelclaudeMcpSideEffectRecord,
	nowMs: number,
): Parameters<TelclaudeMcpInboundTurnAuthorityResolver>[0] {
	return {
		turnConversationRef: record.turnConversationRef ?? "",
		...(record.kind === "outbound"
			? {
					expectedConversationRef: record.conversationRef,
					channel: record.channel,
					...(record.resolvedDestination.conversationId
						? { conversationId: record.resolvedDestination.conversationId }
						: {}),
				}
			: {}),
		actorId: record.actorId,
		profileId: record.profileId,
		domain: record.domain,
		nowMs,
	};
}

function sameTurnAuthority(
	record: TelclaudeMcpSideEffectRecord,
	turn: RelayConversationInboundTurn,
): boolean {
	if (
		turn.ref !== record.turnConversationRef ||
		turn.profileId !== record.profileId ||
		turn.mcpDomain !== record.domain ||
		turn.senderActorId !== record.actorId
	) {
		return false;
	}
	if (record.kind !== "outbound") return true;
	if (
		turn.conversationToken !== record.conversationRef ||
		turn.channel !== record.channel ||
		(record.resolvedDestination.conversationId &&
			turn.conversationId !== record.resolvedDestination.conversationId)
	) {
		return false;
	}
	return true;
}

async function resolveSideEffectApprovalToken(
	resolver: TelclaudeMcpSideEffectApprovalTokenResolver | undefined,
	actionRef: string,
	record: TelclaudeMcpSideEffectRecord,
): Promise<
	TelclaudeMcpSideEffectApprovalTokenResolution & {
		readonly record?: TelclaudeMcpSideEffectRecord;
	}
> {
	if (!resolver) {
		return {
			ok: false,
			code: "side_effect_approval_token_resolver_missing",
			reason: "side-effect approval token resolver is not configured",
			retryable: false,
			record,
		};
	}
	let resolved: TelclaudeMcpSideEffectApprovalTokenResolution;
	try {
		resolved = await resolver({ actionRef, record });
	} catch (error) {
		return {
			ok: false,
			code: "side_effect_approval_token_unavailable",
			reason: redactSecrets(error instanceof Error ? error.message : String(error)),
			retryable: true,
			record,
		};
	}
	if (!resolved.ok) {
		return { ...resolved, record };
	}
	const approvalToken = resolved.approvalToken.trim();
	if (!approvalToken) {
		return {
			ok: false,
			code: "side_effect_approval_token_unavailable",
			reason: "side-effect approval token resolver returned an empty token",
			retryable: true,
			record,
		};
	}
	return {
		ok: true,
		approvalToken,
		...(resolved.approvalId ? { approvalId: resolved.approvalId } : {}),
		...(resolved.finalize ? { finalize: resolved.finalize } : {}),
	};
}

function terminalFailureBeforeApproval(
	record: TelclaudeMcpSideEffectRecord,
	nowMs: number,
): TelclaudeMcpSideEffectTerminalFailure | null {
	if (record.status === "executed") {
		return terminalFailure("effect_already_executed", "side effect has already executed", record);
	}
	if (record.status === "revoked") {
		return terminalFailure("effect_revoked", "side effect was revoked", record);
	}
	if (record.expiresAtMs < nowMs) {
		return terminalFailure("effect_expired", "side effect approval window expired", record);
	}
	if (record.actorId === record.approverActorId) {
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
	return null;
}

function edgePreparedHashFailure(
	record: TelclaudeMcpOutboundSideEffectRecord,
): TelclaudeMcpSideEffectTerminalFailure | null {
	if (record.renderedBody !== record.requestedBody) {
		return terminalFailure(
			"outbound_body_provenance_mismatch",
			"outbound rendered body does not match the approved requested body",
			record,
		);
	}
	const preparedHash = edgePreparedPayloadHash({
		channel: record.channel as Parameters<typeof edgePreparedPayloadHash>[0]["channel"],
		resolvedDestination: record.resolvedDestination,
		body: record.requestedBody,
		mediaRefs: record.preparedMediaRefs,
	});
	if (preparedHash !== record.edgePreparedHash) {
		return terminalFailure(
			"edge_prepared_hash_mismatch",
			"edge prepared hash does not match persisted outbound evidence",
			record,
		);
	}
	return null;
}

async function liveOutboundConversationFailure(
	record: TelclaudeMcpOutboundSideEffectRecord,
	resolveAuthorizedOutboundConversation: TelclaudeMcpOutboundConversationResolver | undefined,
	nowMs: number,
): Promise<TelclaudeMcpSideEffectTerminalFailure | null> {
	if (!resolveAuthorizedOutboundConversation) {
		return terminalFailure(
			"outbound_conversation_resolver_missing",
			"outbound conversation authorization resolver is not configured",
			record,
		);
	}
	let conversation: RelayConversation | null;
	try {
		conversation = await resolveAuthorizedOutboundConversation(record.conversationRef, nowMs);
	} catch (error) {
		return terminalFailure(
			"outbound_conversation_not_authorized",
			redactSecrets(error instanceof Error ? error.message : String(error)),
			record,
		);
	}
	if (!conversation) {
		return terminalFailure(
			"outbound_conversation_not_authorized",
			"outbound conversation is not authorized for execution",
			record,
		);
	}
	if (
		conversation.token !== record.conversationRef ||
		conversation.profileId !== record.profileId ||
		conversation.channel !== record.channel ||
		conversation.mcpDomain !== record.domain ||
		conversation.conversationId !== record.resolvedDestination.conversationId
	) {
		return terminalFailure(
			"outbound_conversation_mismatch",
			"outbound conversation does not match persisted recipient binding",
			record,
		);
	}
	const targetableMembers = targetableRelayConversationMembers(conversation);
	const actorSeat = targetableMembers.find((member) => member.actorId === record.actorId);
	if (!actorSeat?.scopes.includes("message:reply")) {
		return terminalFailure(
			"outbound_recipient_not_targetable",
			"outbound conversation has no reply-capable seat for the actor",
			record,
		);
	}
	return null;
}

async function executeOutboundDelivery(
	dispatcher: OutboundDeliveryDispatcher,
	record: TelclaudeMcpOutboundSideEffectRecord,
): Promise<TelclaudeMcpSideEffectAuthorizeResult> {
	const prepared = preparedOutboundForDelivery(record);
	let receipt: ReturnType<typeof DeliveryReceiptSchema.parse>;
	try {
		receipt = DeliveryReceiptSchema.parse(await dispatcher(prepared));
	} catch (error) {
		return terminalFailureForRecord(
			"outbound_delivery_failed",
			redactSecrets(error instanceof Error ? error.message : String(error)),
			record,
		);
	}
	if (receipt.outboundRef !== record.edgePreparedRef) {
		return terminalFailureForRecord(
			"outbound_delivery_receipt_mismatch",
			"outbound delivery receipt does not match the prepared edge ref",
			record,
		);
	}
	if (!deliveryReceiptSucceeded(receipt.deliveryStatus)) {
		return terminalFailureForRecord(
			"outbound_delivery_failed",
			"outbound delivery dispatcher returned failed",
			record,
		);
	}
	return { ok: true, record };
}

function preparedOutboundForDelivery(
	record: TelclaudeMcpOutboundSideEffectRecord,
): PreparedOutbound {
	return PreparedOutboundSchema.parse({
		schemaVersion: EdgeAdapterSchemaVersions.preparedOutbound,
		outboundRef: record.edgePreparedRef,
		channel: record.channel,
		resolvedDestination: record.resolvedDestination,
		finalRenderedBody: record.renderedBody,
		mediaRefs: record.preparedMediaRefs.map((mediaRef) =>
			attachmentRefForDelivery(record, mediaRef),
		),
		authorizingActor: {
			schemaVersion: EdgeAdapterSchemaVersions.actorRef,
			actorId: record.actorId,
			channelIdentity: {
				channel: record.channel,
				principalId: record.actorId,
			},
			identityAssurance: "strong_link",
			scopes: [],
			revocation: { revoked: false },
		},
		edgePreparedHash: record.edgePreparedHash,
		policyResult: {
			decision: "allowed",
			reason: "MCP side-effect ledger authorized outbound delivery",
		},
		approvalRequirement: { required: false },
		idempotencyKey: record.idempotencyKey ?? record.ref,
		sideEffectLedgerRef: record.ref,
		createdAt: new Date(record.createdAtMs).toISOString(),
		retryPolicy: {
			maxAttempts: 3,
			backoff: "exponential",
			deadLetterAfterAttempts: 3,
		},
	});
}

function attachmentRefForDelivery(
	record: TelclaudeMcpOutboundSideEffectRecord,
	mediaRef: TelclaudeMcpOutboundSideEffectRecord["preparedMediaRefs"][number],
): AttachmentRef {
	return {
		schemaVersion: EdgeAdapterSchemaVersions.attachmentRef,
		quarantineId: mediaRef.quarantineId,
		mediaType: "application/octet-stream",
		scanState: "clean",
		sizeBytes: 0,
		contentHash: mediaRef.contentHash,
		trustLabel: "trusted",
		expiresAt: new Date(record.expiresAtMs).toISOString(),
		lifecycle: {
			state: "authorized",
			authorizedFor: [record.conversationRef],
		},
	};
}

function deliveryReceiptSucceeded(status: string): boolean {
	return status === "sent" || status === "delivered" || status === "read";
}

async function executeProviderSidecar(
	providerProxy: ProviderProxy,
	record: TelclaudeMcpProviderSideEffectRecord,
	approvalTokenIssuer: TelclaudeMcpProviderSidecarApprovalTokenIssuer | undefined,
): Promise<TelclaudeMcpSideEffectAuthorizeResult> {
	if (record.kind !== "provider") {
		return terminalFailureForRecord("effect_kind_mismatch", "side effect kind mismatch", record);
	}
	const body = providerFetchBody(record);
	if (!approvalTokenIssuer) {
		return terminalFailureForRecord(
			"provider_approval_token_issuer_missing",
			"provider sidecar approval token issuer is not configured",
			record,
		);
	}
	let sidecarApprovalToken: string;
	try {
		sidecarApprovalToken = await approvalTokenIssuer({
			record,
			providerId: record.providerId,
			service: body.service,
			action: body.action,
			params: body.params,
			subjectUserId: body.subjectUserId,
			actorUserId: record.actorId,
			approvalNonce: record.approvalRequestId,
		});
	} catch (error) {
		return terminalFailureForRecord(
			"provider_approval_token_mint_failed",
			redactSecrets(error instanceof Error ? error.message : String(error)),
			record,
		);
	}
	let response: ProviderProxyResponse;
	try {
		response = await providerProxy({
			providerId: record.providerId,
			path: PROVIDER_PATH,
			method: "POST",
			body: JSON.stringify(body),
			userId: record.actorId,
			approvalToken: sidecarApprovalToken,
			approvalMode: "preapproved-ledger",
		});
	} catch (error) {
		return terminalFailureForRecord(
			"provider_execute_failed",
			redactSecrets(error instanceof Error ? error.message : String(error)),
			record,
		);
	}
	if (response.status === "error") {
		return terminalFailureForRecord(
			response.errorCode ? `provider_${response.errorCode}` : "provider_execute_failed",
			redactSecrets(response.error || "provider execute failed"),
			record,
		);
	}
	return { ok: true, record };
}

function providerFetchBody(record: TelclaudeMcpProviderSideEffectRecord): {
	service: string;
	action: string;
	params: Record<string, unknown>;
	subjectUserId?: string;
} {
	return {
		service: record.service,
		action: record.action,
		params: record.params,
		...(record.subjectUserId ? { subjectUserId: record.subjectUserId } : {}),
	};
}

function sameAuthority(
	record: TelclaudeMcpSideEffectRecord,
	request: TelclaudeMcpAuthorityStamp,
): boolean {
	return (
		record.actorId === request.actorId &&
		record.profileId === request.profileId &&
		record.domain === request.domain
	);
}

function sameProviderScope(
	record: TelclaudeMcpSideEffectRecord,
	request: TelclaudeMcpProviderExecuteWriteRequest | TelclaudeMcpOutboundExecuteRequest,
): boolean {
	if (record.kind !== "provider") return true;
	return (
		"providerScopes" in request &&
		request.providerScopes.some((providerId) => providerId === record.providerId)
	);
}

function sameOutboundScope(
	record: TelclaudeMcpOutboundSideEffectRecord,
	request: TelclaudeMcpOutboundExecuteRequest,
): boolean {
	return request.outboundChannels.some((channel) => channel === record.channel);
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
		...(record ? { record } : {}),
	};
}

function terminalFailureForRecord(
	code: string,
	reason: string,
	record: TelclaudeMcpSideEffectRecord,
): TelclaudeMcpSideEffectTerminalFailure {
	return {
		ok: false,
		code,
		reason,
		retryable: false,
		record,
	};
}

/**
 * Provider/outbound only: a sidecar/delivery failure after the single-flight claim is
 * retryable by design, so revert `executing -> prepared` and report the released
 * (prepared) record on the failure. Browser-write never uses this — its post-claim
 * failures are terminal (`markFailed`) because the commit is irreversible.
 */
function releaseAndReport<T extends Extract<TelclaudeMcpSideEffectAuthorizeResult, { ok: false }>>(
	ledger: TelclaudeMcpSideEffectLedger,
	ref: string,
	failure: T,
): T {
	ledger.releaseExecuting(ref);
	const released = ledger.get(ref);
	return released ? { ...failure, record: released } : failure;
}
