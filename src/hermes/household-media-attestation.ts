import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import { HERMES_EVIDENCE_PROOF_MAX_SKEW_MS } from "./attestation-validation.js";

export const HOUSEHOLD_MEDIA_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.household-media-attestation.v1";
export const HOUSEHOLD_MEDIA_ATTESTATION_SOURCE = "telclaude-household-media-probe-runner";
export const HOUSEHOLD_MEDIA_ATTESTATION_RUNNER = "telclaude-household-media-probe";
export const HOUSEHOLD_MEDIA_ATTESTATION_PATH = "/v1/hermes.household-media.attestation";

const HOUSEHOLD_MEDIA_ATTESTATION_SCOPE = "operator";

type HouseholdMediaEvidenceLike = {
	readonly schemaVersion: "telclaude.hermes.household-media-probe.v1";
	readonly probeId: "household.media";
	readonly status: "pass" | "fail";
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: string;
	readonly checks: readonly unknown[];
	readonly observations: unknown;
};

export type HouseholdMediaAttestationSignedFields = {
	readonly schemaVersion: typeof HOUSEHOLD_MEDIA_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof HOUSEHOLD_MEDIA_ATTESTATION_SOURCE;
	readonly runner: typeof HOUSEHOLD_MEDIA_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: "telclaude.hermes.household-media-probe.v1";
	readonly probeId: "household.media";
	readonly status: "pass" | "fail";
	readonly ran: boolean;
	readonly observedAt: string;
	readonly checksSha256: `sha256:${string}`;
	readonly observationsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type HouseholdMediaAttestation = HouseholdMediaAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function householdMediaAttestationFieldsForEvidence(
	evidence: HouseholdMediaEvidenceLike,
): HouseholdMediaAttestationSignedFields {
	return {
		schemaVersion: HOUSEHOLD_MEDIA_ATTESTATION_SCHEMA_VERSION,
		source: HOUSEHOLD_MEDIA_ATTESTATION_SOURCE,
		runner: HOUSEHOLD_MEDIA_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		checksSha256: sha256Json(evidence.checks),
		observationsSha256: sha256Json(evidence.observations),
		evidenceSha256: householdMediaEvidenceSha256(evidence),
	};
}

export function signHouseholdMediaAttestation(
	evidence: HouseholdMediaEvidenceLike,
): HouseholdMediaAttestation {
	const attestation = householdMediaAttestationFieldsForEvidence(evidence);
	const payload = signedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			HOUSEHOLD_MEDIA_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: HOUSEHOLD_MEDIA_ATTESTATION_SCOPE },
		),
	};
}

export function householdMediaAttestationSignatureFailure(
	attestation: HouseholdMediaAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = signedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		HOUSEHOLD_MEDIA_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: HOUSEHOLD_MEDIA_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			maxSkewMs: HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function householdMediaEvidenceSha256(
	evidence: HouseholdMediaEvidenceLike,
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

function signedPayload(attestation: HouseholdMediaAttestationSignedFields): string {
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
