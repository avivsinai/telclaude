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
	TelclaudeMcpSideEffectVerifyResult,
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

export type CreateTelclaudeMcpLedgerExecuteDependenciesOptions = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
	readonly providerProxy?: ProviderProxy;
	readonly providerApprovalTokenIssuer?: TelclaudeMcpProviderSidecarApprovalTokenIssuer;
};

type ProviderProxy = (request: ProviderProxyRequest) => Promise<ProviderProxyResponse>;

const PROVIDER_PATH = "/v1/fetch";

export function createTelclaudeMcpLedgerExecuteDependencies(
	options: CreateTelclaudeMcpLedgerExecuteDependenciesOptions,
): TelclaudeMcpLedgerExecuteDependencies {
	return {
		async providerExecuteWrite(request) {
			const authorized = await verifyLedgerEffect(
				options.ledger,
				"provider",
				request.actionRef,
				request,
			);
			if (!authorized.ok) return authorized;
			if (!options.providerProxy) {
				return options.ledger.markExecuted(request.actionRef, authorized.approvalId);
			}
			const executed = await executeProviderSidecar(
				options.providerProxy,
				authorized.record as TelclaudeMcpProviderSideEffectRecord,
				options.providerApprovalTokenIssuer,
			);
			if (!executed.ok) return executed;
			return options.ledger.markExecuted(request.actionRef, authorized.approvalId);
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
	request: TelclaudeMcpProviderExecuteWriteRequest | TelclaudeMcpOutboundExecuteRequest,
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
	return ledger.authorize(ref, request.approvalToken);
}

async function verifyLedgerEffect(
	ledger: TelclaudeMcpSideEffectLedger,
	expectedKind: TelclaudeMcpSideEffectRecord["kind"],
	ref: string,
	request: TelclaudeMcpProviderExecuteWriteRequest | TelclaudeMcpOutboundExecuteRequest,
): Promise<TelclaudeMcpSideEffectVerifyResult> {
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
	return ledger.verify(ref, request.approvalToken);
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

function terminalFailure(code: string, reason: string): TelclaudeMcpSideEffectTerminalFailure {
	return {
		ok: false,
		code,
		reason,
		retryable: false,
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
