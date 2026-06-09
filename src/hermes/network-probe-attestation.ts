import crypto from "node:crypto";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import { HERMES_EVIDENCE_PROOF_MAX_SKEW_MS } from "./attestation-validation.js";

export const NETWORK_PROBE_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.network-probe-attestation.v1";
export const NETWORK_PROBE_ATTESTATION_SOURCE = "telclaude-hermes-network-probe-runner";
export const NETWORK_PROBE_ATTESTATION_RUNNER = "telclaude-hermes-network-probes";
export const NETWORK_PROBE_ATTESTATION_PATH = "/v1/hermes.network-probe.attestation";
const NETWORK_PROBE_ATTESTATION_SCOPE = "operator";

type NetworkProbeEvidenceLike = {
	readonly schemaVersion: string;
	readonly id: string;
	readonly posture?: string;
	readonly status: string;
	readonly ran: boolean;
	readonly summary: string;
	readonly generatedAt: string;
	readonly attempts: readonly unknown[];
};

export type NetworkProbeAttestationSignedFields = {
	readonly schemaVersion: typeof NETWORK_PROBE_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof NETWORK_PROBE_ATTESTATION_SOURCE;
	readonly runner: typeof NETWORK_PROBE_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly posture: string;
	readonly status: string;
	readonly ran: boolean;
	readonly generatedAt: string;
	readonly attemptsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type NetworkProbeAttestation = NetworkProbeAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function networkProbeAttestationFieldsForEvidence(
	evidence: NetworkProbeEvidenceLike,
): NetworkProbeAttestationSignedFields {
	return {
		schemaVersion: NETWORK_PROBE_ATTESTATION_SCHEMA_VERSION,
		source: NETWORK_PROBE_ATTESTATION_SOURCE,
		runner: NETWORK_PROBE_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.id,
		posture: evidence.posture ?? "agent-iptables",
		status: evidence.status,
		ran: evidence.ran,
		generatedAt: evidence.generatedAt,
		attemptsSha256: sha256Digest(JSON.stringify(evidence.attempts)),
		evidenceSha256: networkProbeEvidenceSha256(evidence),
	};
}

export function signNetworkProbeEvidenceAttestation(
	evidence: NetworkProbeEvidenceLike,
): NetworkProbeAttestation {
	return signNetworkProbeAttestation(networkProbeAttestationFieldsForEvidence(evidence));
}

export function signNetworkProbeAttestation(
	attestation: NetworkProbeAttestationSignedFields,
): NetworkProbeAttestation {
	const payload = networkProbeAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			NETWORK_PROBE_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: NETWORK_PROBE_ATTESTATION_SCOPE },
		),
	};
}

export function networkProbeEvidenceSha256(evidence: NetworkProbeEvidenceLike): `sha256:${string}` {
	return sha256Digest(networkProbeEvidenceSignedPayload(evidence));
}

export function networkProbeAttestationSignatureFailure(
	attestation: NetworkProbeAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = networkProbeAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		NETWORK_PROBE_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: NETWORK_PROBE_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			maxSkewMs: HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

function networkProbeEvidenceSignedPayload(evidence: NetworkProbeEvidenceLike): string {
	return JSON.stringify({
		schemaVersion: evidence.schemaVersion,
		id: evidence.id,
		posture: evidence.posture ?? null,
		status: evidence.status,
		ran: evidence.ran,
		summary: evidence.summary,
		generatedAt: evidence.generatedAt,
		attempts: evidence.attempts,
	});
}

function networkProbeAttestationSignedPayload(
	attestation: NetworkProbeAttestationSignedFields,
): string {
	return JSON.stringify({
		schemaVersion: attestation.schemaVersion,
		source: attestation.source,
		runner: attestation.runner,
		probeEvidenceSchemaVersion: attestation.probeEvidenceSchemaVersion,
		probeId: attestation.probeId,
		posture: attestation.posture,
		status: attestation.status,
		ran: attestation.ran,
		generatedAt: attestation.generatedAt,
		attemptsSha256: attestation.attemptsSha256,
		evidenceSha256: attestation.evidenceSha256,
	});
}

function sha256Digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
