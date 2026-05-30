import type {
	TelclaudeMcpAuthorityStamp,
	TelclaudeMcpBridgeDependencies,
	TelclaudeMcpOutboundExecuteRequest,
	TelclaudeMcpProviderExecuteWriteRequest,
} from "./bridge.js";
import type {
	TelclaudeMcpSideEffectAuthorizeResult,
	TelclaudeMcpSideEffectLedger,
	TelclaudeMcpSideEffectRecord,
	TelclaudeMcpSideEffectTerminalFailure,
} from "./side-effect-ledger.js";

export type TelclaudeMcpLedgerExecuteDependencies = Pick<
	TelclaudeMcpBridgeDependencies,
	"providerExecuteWrite" | "outboundExecute"
>;

export type CreateTelclaudeMcpLedgerExecuteDependenciesOptions = {
	readonly ledger: TelclaudeMcpSideEffectLedger;
};

export function createTelclaudeMcpLedgerExecuteDependencies(
	options: CreateTelclaudeMcpLedgerExecuteDependenciesOptions,
): TelclaudeMcpLedgerExecuteDependencies {
	return {
		providerExecuteWrite(request) {
			return authorizeLedgerEffect(options.ledger, "provider", request.actionRef, request);
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
