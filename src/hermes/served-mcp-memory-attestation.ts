import crypto from "node:crypto";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

// Signed runner attestation for the served-MCP memory parity probe. Without it,
// `evaluateServedMcpMemoryEvidence` accepts any self-consistent JSON as production
// proof: a hand-edited artifact with the right bits + matching checks + a plausible
// origin passes. The attestation binds the evidence body to an Ed25519 signature
// produced by the operator relay key (which contained agents never hold), so a
// forged or post-hoc-edited artifact fails the body-digest match or the signature.
// Mirrors edge-adapter-attestation.ts / no-fork-attestation.ts (scope "operator",
// /v1/hermes.<surface>.attestation path).

export const SERVED_MCP_MEMORY_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.served-mcp-memory-attestation.v1";
export const SERVED_MCP_MEMORY_ATTESTATION_SOURCE = "telclaude-served-mcp-memory-probe-runner";
export const SERVED_MCP_MEMORY_ATTESTATION_RUNNER = "telclaude-served-mcp-memory-probe";
export const SERVED_MCP_MEMORY_ATTESTATION_PATH = "/v1/hermes.served-mcp-memory.attestation";

const SERVED_MCP_MEMORY_ATTESTATION_SCOPE = "operator";

type ServedMcpMemoryEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly generatedAt: string;
	readonly summary: string;
	readonly memorySource: string;
	readonly origin: unknown;
	readonly properties: unknown;
	readonly checks: readonly unknown[];
};

export type ServedMcpMemoryAttestationSignedFields = {
	readonly schemaVersion: typeof SERVED_MCP_MEMORY_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof SERVED_MCP_MEMORY_ATTESTATION_SOURCE;
	readonly runner: typeof SERVED_MCP_MEMORY_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: string;
	readonly status: string;
	readonly ran: boolean;
	readonly generatedAt: string;
	readonly memorySource: string;
	readonly originSha256: string;
	readonly propertiesSha256: string;
	readonly checksSha256: string;
	readonly evidenceSha256: string;
};

export type ServedMcpMemoryAttestation = ServedMcpMemoryAttestationSignedFields & {
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

export const ServedMcpMemoryAttestationSchema = z
	.object({
		schemaVersion: z.literal(SERVED_MCP_MEMORY_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(SERVED_MCP_MEMORY_ATTESTATION_SOURCE),
		runner: z.literal(SERVED_MCP_MEMORY_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.string().min(1),
		probeId: z.string().min(1),
		status: z.string().min(1),
		ran: z.boolean(),
		generatedAt: z.string().min(1),
		memorySource: z.string().min(1),
		originSha256: Sha256DigestSchema,
		propertiesSha256: Sha256DigestSchema,
		checksSha256: Sha256DigestSchema,
		evidenceSha256: Sha256DigestSchema,
		signature: InternalResponseProofSchema,
	})
	.strict();

export function servedMcpMemoryAttestationFieldsForEvidence(
	evidence: ServedMcpMemoryEvidenceLike,
): ServedMcpMemoryAttestationSignedFields {
	return {
		schemaVersion: SERVED_MCP_MEMORY_ATTESTATION_SCHEMA_VERSION,
		source: SERVED_MCP_MEMORY_ATTESTATION_SOURCE,
		runner: SERVED_MCP_MEMORY_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		generatedAt: evidence.generatedAt,
		memorySource: evidence.memorySource,
		originSha256: sha256Json(evidence.origin),
		propertiesSha256: sha256Json(evidence.properties),
		checksSha256: sha256Json(evidence.checks),
		evidenceSha256: servedMcpMemoryEvidenceSha256(evidence),
	};
}

export function signServedMcpMemoryAttestation(
	evidence: ServedMcpMemoryEvidenceLike,
): ServedMcpMemoryAttestation {
	const attestation = servedMcpMemoryAttestationFieldsForEvidence(evidence);
	const payload = servedMcpMemoryAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			SERVED_MCP_MEMORY_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: SERVED_MCP_MEMORY_ATTESTATION_SCOPE },
		),
	};
}

export function servedMcpMemoryAttestationSignatureFailure(
	attestation: ServedMcpMemoryAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = servedMcpMemoryAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		SERVED_MCP_MEMORY_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: SERVED_MCP_MEMORY_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function servedMcpMemoryEvidenceSha256(evidence: ServedMcpMemoryEvidenceLike): string {
	return sha256Json({
		schemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		generatedAt: evidence.generatedAt,
		summary: evidence.summary,
		memorySource: evidence.memorySource,
		origin: evidence.origin,
		properties: evidence.properties,
		checks: evidence.checks,
	});
}

function servedMcpMemoryAttestationSignedPayload(
	attestation: ServedMcpMemoryAttestationSignedFields,
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
		memorySource: attestation.memorySource,
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
