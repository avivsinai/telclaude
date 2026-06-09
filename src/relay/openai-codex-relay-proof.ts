import crypto from "node:crypto";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

export const OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION =
	"telclaude.hermes.cli-headless-relay-proof.v1";
export const OPENAI_CODEX_RELAY_PROOF_SOURCE = "telclaude-openai-codex-proxy";
export const OPENAI_CODEX_RESPONSES_PATH = "/backend-api/codex/responses";
const OPENAI_CODEX_RELAY_PROOF_SCOPE = "operator";
const OPENAI_CODEX_RELAY_PROOF_TOKEN_PATTERN = /TELCLAUDE_HERMES_CLI_OK|HERMES_OK_[A-Za-z0-9_-]+/;

export type OpenAiCodexRelayProofSignedFields = {
	readonly schemaVersion: typeof OPENAI_CODEX_RELAY_PROOF_SCHEMA_VERSION;
	readonly source: typeof OPENAI_CODEX_RELAY_PROOF_SOURCE;
	readonly requestId: string;
	readonly method: "POST";
	readonly path: typeof OPENAI_CODEX_RESPONSES_PATH;
	readonly observedPeerAddress: string;
	readonly upstreamStatus: number;
	readonly model: string;
	readonly requestBodySha256: `sha256:${string}`;
	readonly proofTokenSha256?: `sha256:${string}`;
	readonly observedAt: string;
};

export type OpenAiCodexRelayProof = OpenAiCodexRelayProofSignedFields & {
	readonly signature: InternalResponseProof;
};

export function signOpenAiCodexRelayProof(
	proof: OpenAiCodexRelayProofSignedFields,
): OpenAiCodexRelayProof {
	const payload = openAiCodexRelayProofSignedPayload(proof);
	return {
		...proof,
		signature: buildInternalResponseProof("POST", OPENAI_CODEX_RESPONSES_PATH, payload, payload, {
			scope: OPENAI_CODEX_RELAY_PROOF_SCOPE,
		}),
	};
}

export function openAiCodexRelayProofSignatureFailure(
	proof: OpenAiCodexRelayProofSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
		readonly maxSkewMs?: number;
	},
): string | null {
	if (!proof.signature) return "signature is missing";
	const payload = openAiCodexRelayProofSignedPayload(proof);
	return internalResponseProofVerificationFailure(
		proof.signature,
		"POST",
		OPENAI_CODEX_RESPONSES_PATH,
		payload,
		payload,
		{
			scope: OPENAI_CODEX_RELAY_PROOF_SCOPE,
			allowStale: options?.allowStale,
			maxSkewMs: options?.maxSkewMs,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function extractOpenAiCodexRelayProofToken(value: string): string | null {
	return value.match(OPENAI_CODEX_RELAY_PROOF_TOKEN_PATTERN)?.[0] ?? null;
}

export function openAiCodexRelayProofTokenSha256(token: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(token).digest("hex")}`;
}

function openAiCodexRelayProofSignedPayload(proof: OpenAiCodexRelayProofSignedFields): string {
	return JSON.stringify({
		schemaVersion: proof.schemaVersion,
		source: proof.source,
		requestId: proof.requestId,
		method: proof.method,
		path: proof.path,
		observedPeerAddress: proof.observedPeerAddress,
		upstreamStatus: proof.upstreamStatus,
		model: proof.model,
		requestBodySha256: proof.requestBodySha256,
		proofTokenSha256: proof.proofTokenSha256 ?? null,
		observedAt: proof.observedAt,
	});
}
