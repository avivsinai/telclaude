import crypto from "node:crypto";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

// Signed runner attestation for the skills-allowlist parity probe. Without it,
// `evaluateSkillsAllowlistEvidence` accepts any self-consistent JSON as production
// proof: a hand-edited artifact with observationLayer "docker_exec" /
// enforcementLayer "pretooluse" markers and matching checks passes even though those
// are self-reported fields. The attestation binds the evidence body to an Ed25519
// signature from the operator relay key (which contained agents never hold), so a
// forged or post-hoc-edited artifact fails the body-digest match or the signature.
// Mirrors edge-adapter-attestation.ts (scope "operator",
// /v1/hermes.<surface>.attestation path).

export const SKILLS_ALLOWLIST_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.skills-allowlist-attestation.v1";
export const SKILLS_ALLOWLIST_ATTESTATION_SOURCE = "telclaude-skills-allowlist-probe-runner";
export const SKILLS_ALLOWLIST_ATTESTATION_RUNNER = "telclaude-skills-allowlist-probe";
export const SKILLS_ALLOWLIST_ATTESTATION_PATH = "/v1/hermes.skills-allowlist.attestation";

const SKILLS_ALLOWLIST_ATTESTATION_SCOPE = "operator";

type SkillsAllowlistEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly generatedAt: string;
	readonly summary: string;
	readonly origin: unknown;
	readonly properties: unknown;
	readonly checks: readonly unknown[];
};

export type SkillsAllowlistAttestationSignedFields = {
	readonly schemaVersion: typeof SKILLS_ALLOWLIST_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof SKILLS_ALLOWLIST_ATTESTATION_SOURCE;
	readonly runner: typeof SKILLS_ALLOWLIST_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly generatedAt: string;
	readonly originSha256: string;
	readonly propertiesSha256: string;
	readonly checksSha256: string;
	readonly evidenceSha256: string;
};

export type SkillsAllowlistAttestation = SkillsAllowlistAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

const Sha256DigestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const HexSha256Schema = z.string().regex(/^[a-f0-9]{64}$/i);

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: z.string().min(1),
		timestamp: z.string().min(1),
		nonce: z.string().min(1),
		method: z.string().min(1),
		path: z.string().min(1),
		requestBodySha256: HexSha256Schema,
		responseBodySha256: HexSha256Schema,
		signature: z.string().min(1),
	})
	.strict();

export const SkillsAllowlistAttestationSchema = z
	.object({
		schemaVersion: z.literal(SKILLS_ALLOWLIST_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(SKILLS_ALLOWLIST_ATTESTATION_SOURCE),
		runner: z.literal(SKILLS_ALLOWLIST_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.string().min(1),
		probeId: z.string().min(1),
		status: z.string().min(1),
		ran: z.boolean(),
		generatedAt: z.string().min(1),
		originSha256: Sha256DigestSchema,
		propertiesSha256: Sha256DigestSchema,
		checksSha256: Sha256DigestSchema,
		evidenceSha256: Sha256DigestSchema,
		signature: InternalResponseProofSchema,
	})
	.strict();

export function skillsAllowlistAttestationFieldsForEvidence(
	evidence: SkillsAllowlistEvidenceLike,
): SkillsAllowlistAttestationSignedFields {
	return {
		schemaVersion: SKILLS_ALLOWLIST_ATTESTATION_SCHEMA_VERSION,
		source: SKILLS_ALLOWLIST_ATTESTATION_SOURCE,
		runner: SKILLS_ALLOWLIST_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		generatedAt: evidence.generatedAt,
		originSha256: sha256Json(evidence.origin),
		propertiesSha256: sha256Json(evidence.properties),
		checksSha256: sha256Json(evidence.checks),
		evidenceSha256: skillsAllowlistEvidenceSha256(evidence),
	};
}

export function signSkillsAllowlistAttestation(
	evidence: SkillsAllowlistEvidenceLike,
): SkillsAllowlistAttestation {
	const attestation = skillsAllowlistAttestationFieldsForEvidence(evidence);
	const payload = skillsAllowlistAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			SKILLS_ALLOWLIST_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: SKILLS_ALLOWLIST_ATTESTATION_SCOPE },
		),
	};
}

export function skillsAllowlistAttestationSignatureFailure(
	attestation: SkillsAllowlistAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = skillsAllowlistAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		SKILLS_ALLOWLIST_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: SKILLS_ALLOWLIST_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function skillsAllowlistEvidenceSha256(evidence: SkillsAllowlistEvidenceLike): string {
	return sha256Json({
		schemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		generatedAt: evidence.generatedAt,
		summary: evidence.summary,
		origin: evidence.origin,
		properties: evidence.properties,
		checks: evidence.checks,
	});
}

function skillsAllowlistAttestationSignedPayload(
	attestation: SkillsAllowlistAttestationSignedFields,
): string {
	return JSON.stringify({
		schemaVersion: attestation.schemaVersion,
		source: attestation.source,
		runner: attestation.runner,
		probeEvidenceSchemaVersion: attestation.probeEvidenceSchemaVersion,
		probeId: attestation.probeId,
		status: attestation.status,
		ran: attestation.ran,
		generatedAt: attestation.generatedAt,
		originSha256: attestation.originSha256,
		propertiesSha256: attestation.propertiesSha256,
		checksSha256: attestation.checksSha256,
		evidenceSha256: attestation.evidenceSha256,
	});
}

function sha256Json(value: unknown): string {
	return `sha256:${crypto
		.createHash("sha256")
		.update(JSON.stringify(sortKeysDeep(value)))
		.digest("hex")}`;
}
