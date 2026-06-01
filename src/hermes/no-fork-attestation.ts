import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

export const NO_FORK_RUNNER_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.no-fork-runner-attestation.v1";
export const NO_FORK_RUNNER_ATTESTATION_SOURCE = "telclaude-no-fork-proof-runner";
export const NO_FORK_RUNNER_ATTESTATION_RUNNER = "telclaude-hermes-no-fork-runner";
export const NO_FORK_RUNNER_ATTESTATION_PATH = "/v1/hermes.no-fork.runner-attestation";
const NO_FORK_RUNNER_ATTESTATION_SCOPE = "operator";

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
		},
	);
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
