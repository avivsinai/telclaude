import type { ProviderProxyRequest, ProviderProxyResponse } from "../../relay/provider-proxy.js";
import { redactSecrets } from "../../security/output-filter.js";
import type {
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpBridgeDependencies,
	TelclaudeMcpOutboundExecuteRequest,
	TelclaudeMcpProviderExecuteWriteRequest,
} from "./bridge.js";
import type {
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

export type TelclaudeMcpProviderApprovalTokenResolution =
	| {
			readonly ok: true;
			readonly approvalToken: string;
			readonly approvalId?: string;
	  }
	| {
			readonly ok: false;
			readonly code: string;
			readonly reason: string;
			readonly retryable: boolean;
	  };

export type TelclaudeMcpProviderApprovalTokenResolver = (request: {
	readonly actionRef: string;
	readonly record: TelclaudeMcpProviderSideEffectRecord;
}) =>
	| TelclaudeMcpProviderApprovalTokenResolution
	| Promise<TelclaudeMcpProviderApprovalTokenResolution>;

export type CreateTelclaudeMcpLedgerExecuteDependenciesOptions = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly providerProxy?: ProviderProxy;
	readonly providerApprovalTokenIssuer?: TelclaudeMcpProviderSidecarApprovalTokenIssuer;
	readonly providerApprovalTokenResolver?: TelclaudeMcpProviderApprovalTokenResolver;
	readonly nowMs?: () => number;
};

type ProviderProxy = (request: ProviderProxyRequest) => Promise<ProviderProxyResponse>;

const PROVIDER_PATH = "/v1/fetch";

export function createTelclaudeMcpLedgerExecuteDependencies(
	options: CreateTelclaudeMcpLedgerExecuteDependenciesOptions,
): TelclaudeMcpLedgerExecuteDependencies {
	return {
		async providerExecuteWrite(request) {
			const prepared = providerLedgerEffectRecord(
				options.ledger,
				request.actionRef,
				request,
				options.nowMs?.() ?? Date.now(),
			);
			if (!prepared.ok) return prepared;
			const resolved = await resolveProviderApprovalToken(
				options.providerApprovalTokenResolver,
				request.actionRef,
				prepared.record,
			);
			if (!resolved.ok) return resolved;
			const authorized = await options.ledger.verify(request.actionRef, resolved.approvalToken);
			if (!authorized.ok) return authorized;
			if (!options.providerProxy) {
				return options.ledger.markExecuted(
					request.actionRef,
					authorized.approvalId ?? resolved.approvalId,
				);
			}
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
		outboundExecute(request) {
			return authorizeLedgerEffect(options.ledger, "outbound", request.outboundRef, request);
		},
	};
}

async function authorizeLedgerEffect(
	ledger: TelclaudeMcpSideEffectLedger,
	expectedKind: TelclaudeMcpSideEffectRecord["kind"],
	ref: string,
	request: TelclaudeMcpOutboundExecuteRequest,
): Promise<TelclaudeMcpSideEffectAuthorizeResult> {
	const record = ledger.get(ref);
	if (!record) {
		return terminalFailure("effect_not_found", "side effect was not prepared");
	}
	if (record.kind !== expectedKind) {
		return terminalFailure(
			"effect_kind_mismatch",
			`side effect kind mismatch: expected ${expectedKind}`,
		);
	}
	if (!sameAuthority(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	if (!sameProviderScope(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	return ledger.authorize(ref, request.approvalToken);
}

function providerLedgerEffectRecord(
	ledger: TelclaudeMcpSideEffectLedger,
	ref: string,
	request: TelclaudeMcpProviderExecuteWriteRequest,
	nowMs: number,
):
	| { readonly ok: true; readonly record: TelclaudeMcpProviderSideEffectRecord }
	| TelclaudeMcpSideEffectTerminalFailure {
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
	if (!sameProviderScope(record, request)) {
		return terminalFailure("effect_authority_mismatch", "side effect authority mismatch");
	}
	const terminal = providerTerminalFailureBeforeApproval(record, nowMs);
	if (terminal) return terminal;
	return { ok: true, record };
}

async function resolveProviderApprovalToken(
	resolver: TelclaudeMcpProviderApprovalTokenResolver | undefined,
	actionRef: string,
	record: TelclaudeMcpProviderSideEffectRecord,
): Promise<
	TelclaudeMcpProviderApprovalTokenResolution & {
		readonly record?: TelclaudeMcpProviderSideEffectRecord;
	}
> {
	if (!resolver) {
		return {
			ok: false,
			code: "provider_approval_token_resolver_missing",
			reason: "provider approval token resolver is not configured",
			retryable: false,
			record,
		};
	}
	let resolved: TelclaudeMcpProviderApprovalTokenResolution;
	try {
		resolved = await resolver({ actionRef, record });
	} catch (error) {
		return {
			ok: false,
			code: "provider_approval_token_unavailable",
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
			code: "provider_approval_token_unavailable",
			reason: "provider approval token resolver returned an empty token",
			retryable: true,
			record,
		};
	}
	return {
		ok: true,
		approvalToken,
		...(resolved.approvalId ? { approvalId: resolved.approvalId } : {}),
	};
}

function providerTerminalFailureBeforeApproval(
	record: TelclaudeMcpProviderSideEffectRecord,
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
		return terminalFailure(
			"provider_distinct_human_approver_required",
			"provider side effects require approval by a distinct human approver",
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
