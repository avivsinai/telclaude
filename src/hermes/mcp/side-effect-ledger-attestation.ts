import crypto from "node:crypto";
import { sortKeysDeep } from "../../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../../internal-auth.js";
import { HERMES_EVIDENCE_PROOF_MAX_SKEW_MS } from "../attestation-validation.js";

export const SIDE_EFFECT_LEDGER_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.sideeffect-ledger-attestation.v1";
export const SIDE_EFFECT_LEDGER_ATTESTATION_SOURCE = "telclaude-mcp-sideeffect-ledger-probe-runner";
export const SIDE_EFFECT_LEDGER_ATTESTATION_RUNNER = "telclaude-mcp-sideeffect-ledger-probe";
export const SIDE_EFFECT_LEDGER_ATTESTATION_PATH = "/v1/hermes.sideeffect-ledger.attestation";

const SIDE_EFFECT_LEDGER_ATTESTATION_SCOPE = "operator";

type SideEffectLedgerEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: string;
	readonly checks: readonly unknown[];
	readonly observations: unknown;
};

export type SideEffectLedgerAttestationSignedFields = {
	readonly schemaVersion: typeof SIDE_EFFECT_LEDGER_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof SIDE_EFFECT_LEDGER_ATTESTATION_SOURCE;
	readonly runner: typeof SIDE_EFFECT_LEDGER_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly checksSha256: `sha256:${string}`;
	readonly observationsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type SideEffectLedgerAttestation = SideEffectLedgerAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function sideEffectLedgerAttestationFieldsForEvidence(
	evidence: SideEffectLedgerEvidenceLike,
): SideEffectLedgerAttestationSignedFields {
	return {
		schemaVersion: SIDE_EFFECT_LEDGER_ATTESTATION_SCHEMA_VERSION,
		source: SIDE_EFFECT_LEDGER_ATTESTATION_SOURCE,
		runner: SIDE_EFFECT_LEDGER_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		checksSha256: sha256Json(evidence.checks),
		observationsSha256: sha256Json(evidence.observations),
		evidenceSha256: sideEffectLedgerEvidenceSha256(evidence),
	};
}

export function signSideEffectLedgerAttestation(
	evidence: SideEffectLedgerEvidenceLike,
): SideEffectLedgerAttestation {
	const attestation = sideEffectLedgerAttestationFieldsForEvidence(evidence);
	const payload = sideEffectLedgerAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			SIDE_EFFECT_LEDGER_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: SIDE_EFFECT_LEDGER_ATTESTATION_SCOPE },
		),
	};
}

export function sideEffectLedgerAttestationSignatureFailure(
	attestation: SideEffectLedgerAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = sideEffectLedgerAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		SIDE_EFFECT_LEDGER_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: SIDE_EFFECT_LEDGER_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			maxSkewMs: HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function sideEffectLedgerEvidenceSha256(
	evidence: SideEffectLedgerEvidenceLike,
): `sha256:${string}` {
	return sha256Json({
		schemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		source: evidence.source,
		checks: evidence.checks,
		observations: evidence.observations,
	});
}

function sideEffectLedgerAttestationSignedPayload(
	attestation: SideEffectLedgerAttestationSignedFields,
): string {
	return JSON.stringify({
		schemaVersion: attestation.schemaVersion,
		source: attestation.source,
		runner: attestation.runner,
		probeEvidenceSchemaVersion: attestation.probeEvidenceSchemaVersion,
		probeId: attestation.probeId,
		status: attestation.status,
		ran: attestation.ran,
		observedAt: attestation.observedAt,
		checksSha256: attestation.checksSha256,
		observationsSha256: attestation.observationsSha256,
		evidenceSha256: attestation.evidenceSha256,
	});
}

function sha256Json(value: unknown): `sha256:${string}` {
	return `sha256:${crypto
		.createHash("sha256")
		.update(JSON.stringify(sortKeysDeep(value)))
		.digest("hex")}`;
}
