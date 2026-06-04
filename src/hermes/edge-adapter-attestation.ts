import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

export const EDGE_ADAPTER_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.edge-adapter-attestation.v1";
export const EDGE_ADAPTER_ATTESTATION_SOURCE = "telclaude-edge-runtime-probe-runner";
export const EDGE_ADAPTER_ATTESTATION_RUNNER = "telclaude-edge-runtime-probe";
export const EDGE_ADAPTER_ATTESTATION_PATH = "/v1/hermes.edge-adapter.attestation";

const EDGE_ADAPTER_ATTESTATION_SCOPE = "operator";

type EdgeAdapterEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: string;
	readonly surface: unknown;
	readonly contract: unknown;
	readonly custody: unknown;
	readonly controls: readonly unknown[];
	readonly runtime?: unknown;
};

export type EdgeAdapterAttestationSignedFields = {
	readonly schemaVersion: typeof EDGE_ADAPTER_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof EDGE_ADAPTER_ATTESTATION_SOURCE;
	readonly runner: typeof EDGE_ADAPTER_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly evidenceSource: string;
	readonly surfaceSha256: `sha256:${string}`;
	readonly contractSha256: `sha256:${string}`;
	readonly custodySha256: `sha256:${string}`;
	readonly controlsSha256: `sha256:${string}`;
	readonly runtimeSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type EdgeAdapterAttestation = EdgeAdapterAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function edgeAdapterAttestationFieldsForEvidence(
	evidence: EdgeAdapterEvidenceLike,
): EdgeAdapterAttestationSignedFields {
	return {
		schemaVersion: EDGE_ADAPTER_ATTESTATION_SCHEMA_VERSION,
		source: EDGE_ADAPTER_ATTESTATION_SOURCE,
		runner: EDGE_ADAPTER_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		evidenceSource: evidence.source,
		surfaceSha256: sha256Json(evidence.surface),
		contractSha256: sha256Json(evidence.contract),
		custodySha256: sha256Json(evidence.custody),
		controlsSha256: sha256Json(evidence.controls),
		runtimeSha256: sha256Json(evidence.runtime ?? null),
		evidenceSha256: edgeAdapterEvidenceSha256(evidence),
	};
}

export function signEdgeAdapterAttestation(
	evidence: EdgeAdapterEvidenceLike,
): EdgeAdapterAttestation {
	const attestation = edgeAdapterAttestationFieldsForEvidence(evidence);
	const payload = edgeAdapterAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof("POST", EDGE_ADAPTER_ATTESTATION_PATH, payload, payload, {
			scope: EDGE_ADAPTER_ATTESTATION_SCOPE,
		}),
	};
}

export function edgeAdapterAttestationSignatureFailure(
	attestation: EdgeAdapterAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = edgeAdapterAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		EDGE_ADAPTER_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: EDGE_ADAPTER_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function edgeAdapterEvidenceSha256(evidence: EdgeAdapterEvidenceLike): `sha256:${string}` {
	return sha256Json({
		schemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		source: evidence.source,
		surface: evidence.surface,
		contract: evidence.contract,
		custody: evidence.custody,
		controls: evidence.controls,
		runtime: evidence.runtime ?? null,
	});
}

function edgeAdapterAttestationSignedPayload(
	attestation: EdgeAdapterAttestationSignedFields,
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
		surfaceSha256: attestation.surfaceSha256,
		contractSha256: attestation.contractSha256,
		custodySha256: attestation.custodySha256,
		controlsSha256: attestation.controlsSha256,
		runtimeSha256: attestation.runtimeSha256,
		evidenceSha256: attestation.evidenceSha256,
	});
}

function sha256Json(value: unknown): `sha256:${string}` {
	return `sha256:${crypto
		.createHash("sha256")
		.update(JSON.stringify(sortKeysDeep(value)))
		.digest("hex")}`;
}
