import type { ProviderProxyRequest, ProviderProxyResponse } from "../../relay/provider-proxy.js";
import { redactSecrets } from "../../security/output-filter.js";
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
	TelclaudeMcpOutboundSideEffectRecord,
	TelclaudeMcpProviderSideEffectRecord,
	TelclaudeMcpSideEffectAuthorizeResult,
	TelclaudeMcpSideEffectLedger,
	TelclaudeMcpSideEffectRecord,
	TelclaudeMcpSideEffectTerminalFailure,
} from "./side-effect-ledger.js";

export type TelclaudeMcpLedgerExecuteDependencies = Pick<
	TelclaudeMcpBridgeDependencies,
	"providerExecuteWrite" | "outboundExecute"
>;

export type TelclaudeMcpProviderSidecarApprovalTokenRequest = {
	readonly record: TelclaudeMcpProviderSideEffectRecord;
	readonly providerId: string;
	readonly service: string;
	readonly action: string;
	readonly params: Record<string, unknown>;
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
	readonly nowMs?: () => number;
};

type ProviderProxy = (request: ProviderProxyRequest) => Promise<ProviderProxyResponse>;

const PROVIDER_PATH = "/v1/fetch";

export function createTelclaudeMcpLedgerExecuteDependencies(
	options: CreateTelclaudeMcpLedgerExecuteDependenciesOptions,
): TelclaudeMcpLedgerExecuteDependencies {
	return {
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
			if (!options.providerProxy) {
				const executed = await options.ledger.markExecuted(
					request.actionRef,
					authorized.approvalId ?? resolved.approvalId,
				);
				if (executed.ok) resolved.finalize?.();
				return executed;
			}
			resolved.finalize?.();
			const executed = await executeProviderSidecar(
				options.providerProxy,
				authorized.record as TelclaudeMcpProviderSideEffectRecord,
				options.providerApprovalTokenIssuer,
			);
			if (!executed.ok) return executed;
			return options.ledger.markExecuted(
				request.actionRef,
				authorized.approvalId ?? resolved.approvalId,
			);
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
			const resolved = await resolveSideEffectApprovalToken(
				options.sideEffectApprovalTokenResolver,
				request.outboundRef,
				checked.record,
			);
			if (!resolved.ok) return resolved;
			const authorized = await options.ledger.verify(request.outboundRef, resolved.approvalToken);
			if (!authorized.ok) return authorized;
			const executed = await options.ledger.markExecuted(
				request.outboundRef,
				authorized.approvalId ?? resolved.approvalId,
			);
			if (executed.ok) resolved.finalize?.();
			return executed;
		},
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
	if (
		targetableMembers.length === 0 ||
		!targetableMembers.some((member) => member.actorId === record.actorId)
	) {
		return terminalFailure(
			"outbound_recipient_not_targetable",
			"outbound conversation has no reply-capable seat for the actor",
			record,
		);
	}
	return null;
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
} {
	return {
		service: record.service,
		action: record.action,
		params: record.params,
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
