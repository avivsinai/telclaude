import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

export const HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.workflow-run-ledger-attestation.v1";
export const HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SOURCE =
	"telclaude-workflow-run-ledger-probe-runner";
export const HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_RUNNER = "telclaude-workflow-run-ledger-probe";
export const HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_PATH =
	"/v1/hermes.workflow-run-ledger.attestation";

const HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCOPE = "operator";

type HermesWorkflowProbeEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: string;
	readonly checks: readonly unknown[];
	readonly observations: unknown;
};

export type HermesWorkflowRunLedgerAttestationSignedFields = {
	readonly schemaVersion: typeof HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SOURCE;
	readonly runner: typeof HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly evidenceSource: string;
	readonly checksSha256: `sha256:${string}`;
	readonly observationsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type HermesWorkflowRunLedgerAttestation = HermesWorkflowRunLedgerAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function hermesWorkflowRunLedgerAttestationFieldsForEvidence(
	evidence: HermesWorkflowProbeEvidenceLike,
): HermesWorkflowRunLedgerAttestationSignedFields {
	return {
		schemaVersion: HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCHEMA_VERSION,
		source: HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SOURCE,
		runner: HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		evidenceSource: evidence.source,
		checksSha256: sha256Json(evidence.checks),
		observationsSha256: sha256Json(evidence.observations),
		evidenceSha256: hermesWorkflowProbeEvidenceSha256(evidence),
	};
}

export function signHermesWorkflowRunLedgerAttestation(
	evidence: HermesWorkflowProbeEvidenceLike,
): HermesWorkflowRunLedgerAttestation {
	const attestation = hermesWorkflowRunLedgerAttestationFieldsForEvidence(evidence);
	const payload = hermesWorkflowRunLedgerAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCOPE },
		),
	};
}

export function hermesWorkflowRunLedgerAttestationSignatureFailure(
	attestation: HermesWorkflowRunLedgerAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = hermesWorkflowRunLedgerAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function hermesWorkflowProbeEvidenceSha256(
	evidence: HermesWorkflowProbeEvidenceLike,
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

function hermesWorkflowRunLedgerAttestationSignedPayload(
	attestation: HermesWorkflowRunLedgerAttestationSignedFields,
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
		evidenceSource: attestation.evidenceSource,
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
