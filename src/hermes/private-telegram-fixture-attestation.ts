import crypto from "node:crypto";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";
import { HERMES_EVIDENCE_PROOF_MAX_SKEW_MS } from "./attestation-validation.js";

export const PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.private-telegram-fixture-attestation.v1";
export const PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SOURCE =
	"telclaude-private-telegram-fixture-runner";
export const PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_RUNNER =
	"telclaude-hermes-private-telegram-fixtures";
export const PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_PATH =
	"/v1/hermes.private-telegram.fixture-attestation";
const PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SCOPE = "operator";

export type PrivateTelegramFixtureInvocationLike = {
	readonly command: readonly string[];
	readonly cwd: string;
	readonly exitCode: number;
	readonly startedAt: string;
	readonly endedAt: string;
	readonly reportPath: string;
	readonly reportSha256: string;
	readonly sourceDigests: Readonly<Record<string, string>>;
};

export type PrivateTelegramFixtureAttestationInput = {
	readonly fixtureId: string;
	readonly status: string;
	readonly observedAt?: string;
	readonly generatedAt?: string;
	readonly provenanceRunner: string;
	readonly provenanceSource?: string;
	readonly testReportPath: string;
	readonly testReportSha256: `sha256:${string}`;
	readonly invocation: PrivateTelegramFixtureInvocationLike;
	readonly requiredTests: readonly string[];
	readonly requiredAssertions: readonly { readonly file: string; readonly fullName: string }[];
	readonly checks: readonly {
		readonly name: string;
		readonly status: string;
		readonly detail: string;
	}[];
};

export type PrivateTelegramFixtureAttestationSignedFields = {
	readonly schemaVersion: typeof PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SOURCE;
	readonly runner: typeof PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_RUNNER;
	readonly fixtureId: string;
	readonly status: string;
	readonly observedAt?: string;
	readonly generatedAt?: string;
	readonly provenanceRunner: string;
	readonly provenanceSource?: string;
	readonly testReportPath: string;
	readonly testReportSha256: `sha256:${string}`;
	readonly invocationReportPath: string;
	readonly invocationReportSha256: `sha256:${string}`;
	readonly invocationSha256: `sha256:${string}`;
	readonly requiredTestsSha256: `sha256:${string}`;
	readonly requiredAssertionsSha256: `sha256:${string}`;
	readonly checksSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type PrivateTelegramFixtureAttestation = PrivateTelegramFixtureAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function privateTelegramFixtureAttestationFieldsForEvidence(
	evidence: PrivateTelegramFixtureAttestationInput,
): PrivateTelegramFixtureAttestationSignedFields {
	return {
		schemaVersion: PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SCHEMA_VERSION,
		source: PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SOURCE,
		runner: PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_RUNNER,
		fixtureId: evidence.fixtureId,
		status: evidence.status,
		...(evidence.observedAt ? { observedAt: evidence.observedAt } : {}),
		...(evidence.generatedAt ? { generatedAt: evidence.generatedAt } : {}),
		provenanceRunner: evidence.provenanceRunner,
		...(evidence.provenanceSource ? { provenanceSource: evidence.provenanceSource } : {}),
		testReportPath: evidence.testReportPath,
		testReportSha256: evidence.testReportSha256,
		invocationReportPath: evidence.invocation.reportPath,
		invocationReportSha256: evidence.invocation.reportSha256 as `sha256:${string}`,
		invocationSha256: privateTelegramFixtureInvocationSha256(evidence.invocation),
		requiredTestsSha256: sha256Digest(JSON.stringify([...evidence.requiredTests])),
		requiredAssertionsSha256: sha256Digest(JSON.stringify(evidence.requiredAssertions)),
		checksSha256: sha256Digest(JSON.stringify(evidence.checks)),
		evidenceSha256: privateTelegramFixtureEvidenceSha256(evidence),
	};
}

export function signPrivateTelegramFixtureEvidenceAttestation(
	evidence: PrivateTelegramFixtureAttestationInput,
): PrivateTelegramFixtureAttestation {
	return signPrivateTelegramFixtureAttestation(
		privateTelegramFixtureAttestationFieldsForEvidence(evidence),
	);
}

export function signPrivateTelegramFixtureAttestation(
	attestation: PrivateTelegramFixtureAttestationSignedFields,
): PrivateTelegramFixtureAttestation {
	const payload = privateTelegramFixtureAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SCOPE },
		),
	};
}

export function privateTelegramFixtureInvocationSha256(
	invocation: PrivateTelegramFixtureInvocationLike,
): `sha256:${string}` {
	return sha256Digest(
		JSON.stringify({
			command: [...invocation.command],
			cwd: invocation.cwd,
			exitCode: invocation.exitCode,
			startedAt: invocation.startedAt,
			endedAt: invocation.endedAt,
			reportPath: invocation.reportPath,
			reportSha256: invocation.reportSha256,
			sourceDigests: Object.fromEntries(Object.entries(invocation.sourceDigests).sort()),
		}),
	);
}

export function privateTelegramFixtureEvidenceSha256(
	evidence: PrivateTelegramFixtureAttestationInput,
): `sha256:${string}` {
	return sha256Digest(privateTelegramFixtureEvidenceSignedPayload(evidence));
}

export function privateTelegramFixtureAttestationSignatureFailure(
	attestation: PrivateTelegramFixtureAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
		readonly relayPublicKey?: string;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = privateTelegramFixtureAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: PRIVATE_TELEGRAM_FIXTURE_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
			maxSkewMs: HERMES_EVIDENCE_PROOF_MAX_SKEW_MS,
			relayPublicKey: options?.relayPublicKey,
		},
	);
}

function privateTelegramFixtureEvidenceSignedPayload(
	evidence: PrivateTelegramFixtureAttestationInput,
): string {
	return JSON.stringify({
		fixtureId: evidence.fixtureId,
		status: evidence.status,
		observedAt: evidence.observedAt ?? null,
		generatedAt: evidence.generatedAt ?? null,
		provenanceRunner: evidence.provenanceRunner,
		provenanceSource: evidence.provenanceSource ?? null,
		testReportPath: evidence.testReportPath,
		testReportSha256: evidence.testReportSha256,
		invocationReportPath: evidence.invocation.reportPath,
		invocationReportSha256: evidence.invocation.reportSha256,
		invocationSha256: privateTelegramFixtureInvocationSha256(evidence.invocation),
		requiredTests: [...evidence.requiredTests],
		requiredAssertions: evidence.requiredAssertions,
		checks: evidence.checks,
	});
}

function privateTelegramFixtureAttestationSignedPayload(
	attestation: PrivateTelegramFixtureAttestationSignedFields,
): string {
	return JSON.stringify({
		schemaVersion: attestation.schemaVersion,
		source: attestation.source,
		runner: attestation.runner,
		fixtureId: attestation.fixtureId,
		status: attestation.status,
		observedAt: attestation.observedAt ?? null,
		generatedAt: attestation.generatedAt ?? null,
		provenanceRunner: attestation.provenanceRunner,
		provenanceSource: attestation.provenanceSource ?? null,
		testReportPath: attestation.testReportPath,
		testReportSha256: attestation.testReportSha256,
		invocationReportPath: attestation.invocationReportPath,
		invocationReportSha256: attestation.invocationReportSha256,
		invocationSha256: attestation.invocationSha256,
		requiredTestsSha256: attestation.requiredTestsSha256,
		requiredAssertionsSha256: attestation.requiredAssertionsSha256,
		checksSha256: attestation.checksSha256,
		evidenceSha256: attestation.evidenceSha256,
	});
}

function sha256Digest(value: string): `sha256:${string}` {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}
