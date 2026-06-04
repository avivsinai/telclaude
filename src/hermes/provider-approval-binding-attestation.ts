import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

export const PROVIDER_APPROVAL_BINDING_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.provider-approval-binding-attestation.v1";
export const PROVIDER_APPROVAL_BINDING_ATTESTATION_SOURCE =
	"telclaude-provider-approval-binding-probe-runner";
export const PROVIDER_APPROVAL_BINDING_ATTESTATION_RUNNER =
	"telclaude-provider-approval-binding-probe";
export const PROVIDER_APPROVAL_BINDING_ATTESTATION_PATH =
	"/v1/hermes.providers.approval-binding.attestation";

const PROVIDER_APPROVAL_BINDING_ATTESTATION_SCOPE = "operator";

type ProviderApprovalBindingEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: string;
	readonly checks: readonly unknown[];
	readonly observations: unknown;
};

export type ProviderApprovalBindingAttestationSignedFields = {
	readonly schemaVersion: typeof PROVIDER_APPROVAL_BINDING_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof PROVIDER_APPROVAL_BINDING_ATTESTATION_SOURCE;
	readonly runner: typeof PROVIDER_APPROVAL_BINDING_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly observedAt: string;
	readonly checksSha256: `sha256:${string}`;
	readonly observationsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type ProviderApprovalBindingAttestation = ProviderApprovalBindingAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function providerApprovalBindingAttestationFieldsForEvidence(
	evidence: ProviderApprovalBindingEvidenceLike,
): ProviderApprovalBindingAttestationSignedFields {
	return {
		schemaVersion: PROVIDER_APPROVAL_BINDING_ATTESTATION_SCHEMA_VERSION,
		source: PROVIDER_APPROVAL_BINDING_ATTESTATION_SOURCE,
		runner: PROVIDER_APPROVAL_BINDING_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		checksSha256: sha256Json(evidence.checks),
		observationsSha256: sha256Json(evidence.observations),
		evidenceSha256: providerApprovalBindingEvidenceSha256(evidence),
	};
}

export function signProviderApprovalBindingAttestation(
	evidence: ProviderApprovalBindingEvidenceLike,
): ProviderApprovalBindingAttestation {
	const attestation = providerApprovalBindingAttestationFieldsForEvidence(evidence);
	const payload = providerApprovalBindingAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			PROVIDER_APPROVAL_BINDING_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: PROVIDER_APPROVAL_BINDING_ATTESTATION_SCOPE },
		),
	};
}

export function providerApprovalBindingAttestationSignatureFailure(
	attestation: ProviderApprovalBindingAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = providerApprovalBindingAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		PROVIDER_APPROVAL_BINDING_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: PROVIDER_APPROVAL_BINDING_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function providerApprovalBindingEvidenceSha256(
	evidence: ProviderApprovalBindingEvidenceLike,
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

function providerApprovalBindingAttestationSignedPayload(
	attestation: ProviderApprovalBindingAttestationSignedFields,
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
