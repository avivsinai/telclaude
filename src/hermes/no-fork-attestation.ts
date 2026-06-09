import crypto from "node:crypto";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import { HERMES_EVIDENCE_PROOF_MAX_SKEW_MS } from "./attestation-validation.js";

export const NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.no-fork-runner-attestation.v1";
export const NO_FORK_RUNNER_ATTESTATION_SOURCE = "telclaude-no-fork-proof-runner";
export const NO_FORK_RUNNER_ATTESTATION_RUNNER = "telclaude-hermes-no-fork-runner";
export const NO_FORK_RUNNER_ATTESTATION_PATH = "/v1/hermes.no-fork.runner-attestation";
const NO_FORK_RUNNER_ATTESTATION_SCOPE = "operator";

type NoForkProofCheckLike = {
	readonly name: string;
	readonly status: string;
	readonly detail: string;
};

type NoForkProofEvidenceLike = {
	readonly schemaVersion: number;
	readonly hermesCheckoutClean: boolean;
	readonly evidence_path: string;
	readonly checkoutPath?: string;
	readonly expectedRef?: string;
	readonly expectedVersion?: string;
	readonly head?: string;
	readonly expectedRefCommit?: string;
	readonly currentBranch?: string;
	readonly exactTags?: readonly string[];
	readonly statusPorcelain?: string;
	readonly diffExitCode?: number;
	readonly cachedDiffExitCode?: number;
	readonly checks?: readonly NoForkProofCheckLike[];
};

export type NoForkRunnerAttestationSignedFields = {
	readonly schemaVersion: typeof NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof NO_FORK_RUNNER_ATTESTATION_SOURCE;
	readonly runner: typeof NO_FORK_RUNNER_ATTESTATION_RUNNER;
	readonly startedAt: string;
	readonly endedAt: string;
	readonly checkoutPath: string;
	readonly expectedRef: string;
	readonly expectedVersion: string;
	readonly head: string;
	readonly expectedRefCommit: string;
	readonly wrapperPackageSha256: `sha256:${string}`;
	readonly profileGenerationSha256: `sha256:${string}`;
	readonly fixtureResultsSha256: `sha256:${string}`;
	readonly transcriptSha256: `sha256:${string}`;
	readonly checksSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
	readonly p0Command: readonly string[];
	readonly p0ExitCode: number;
	readonly p0Status: "pass" | "fail";
	readonly runtimeSourceReplacementDenied: boolean;
	readonly monkeypatchDenied: boolean;
	readonly postRunStatusPorcelain: string;
	readonly postRunDiffExitCode: number;
	readonly postRunCachedDiffExitCode: number;
};

export type NoForkRunnerAttestation = NoForkRunnerAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function signNoForkRunnerAttestation(
	attestation: NoForkRunnerAttestationSignedFields,
): NoForkRunnerAttestation {
	const payload = noForkRunnerAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			NO_FORK_RUNNER_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: NO_FORK_RUNNER_ATTESTATION_SCOPE },
		),
	};
}

export function noForkRunnerAttestationSignatureFailure(
	attestation: NoForkRunnerAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = noForkRunnerAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		NO_FORK_RUNNER_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: NO_FORK_RUNNER_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			maxSkewMs: HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

export function noForkProofChecksSha256(
	checks: readonly NoForkProofCheckLike[],
): `sha256:${string}` {
	return sha256Digest(JSON.stringify(checks));
}

export function noForkProofEvidenceSha256(evidence: NoForkProofEvidenceLike): `sha256:${string}` {
	return sha256Digest(noForkProofEvidenceSignedPayload(evidence));
}

function noForkProofEvidenceSignedPayload(evidence: NoForkProofEvidenceLike): string {
	return JSON.stringify({
		schemaVersion: evidence.schemaVersion,
		hermesCheckoutClean: evidence.hermesCheckoutClean,
		evidence_path: evidence.evidence_path,
		checkoutPath: evidence.checkoutPath ?? null,
		expectedRef: evidence.expectedRef ?? null,
		expectedVersion: evidence.expectedVersion ?? null,
		head: evidence.head ?? null,
		expectedRefCommit: evidence.expectedRefCommit ?? null,
		currentBranch: evidence.currentBranch ?? null,
		exactTags: evidence.exactTags ?? [],
		statusPorcelain: evidence.statusPorcelain ?? null,
		diffExitCode: evidence.diffExitCode ?? null,
		cachedDiffExitCode: evidence.cachedDiffExitCode ?? null,
		checks: evidence.checks ?? [],
	});
}

function noForkRunnerAttestationSignedPayload(
	attestation: NoForkRunnerAttestationSignedFields,
): string {
	return JSON.stringify({
		schemaVersion: attestation.schemaVersion,
		source: attestation.source,
		runner: attestation.runner,
		startedAt: attestation.startedAt,
		endedAt: attestation.endedAt,
		checkoutPath: attestation.checkoutPath,
		expectedRef: attestation.expectedRef,
		expectedVersion: attestation.expectedVersion,
		head: attestation.head,
		expectedRefCommit: attestation.expectedRefCommit,
		wrapperPackageSha256: attestation.wrapperPackageSha256,
		profileGenerationSha256: attestation.profileGenerationSha256,
		fixtureResultsSha256: attestation.fixtureResultsSha256,
		transcriptSha256: attestation.transcriptSha256,
		checksSha256: attestation.checksSha256,
		evidenceSha256: attestation.evidenceSha256,
		p0Command: [...attestation.p0Command],
		p0ExitCode: attestation.p0ExitCode,
		p0Status: attestation.p0Status,
		runtimeSourceReplacementDenied: attestation.runtimeSourceReplacementDenied,
		monkeypatchDenied: attestation.monkeypatchDenied,
		postRunStatusPorcelain: attestation.postRunStatusPorcelain,
		postRunDiffExitCode: attestation.postRunDiffExitCode,
		postRunCachedDiffExitCode: attestation.postRunCachedDiffExitCode,
	});
}

function sha256Digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
