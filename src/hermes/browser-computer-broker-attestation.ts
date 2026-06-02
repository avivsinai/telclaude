import crypto from "node:crypto";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import {
	buildInternalResponseProof,
	type InternalResponseProof,
	internalResponseProofVerificationFailure,
} from "../internal-auth.js";

export const BROWSER_COMPUTER_BROKER_ATTESTATION_SCHEMA_VERSION =
	"telclaude.hermes.browser-computer-broker-attestation.v1";
export const BROWSER_COMPUTER_BROKER_ATTESTATION_SOURCE =
	"telclaude-browser-computer-broker-probe-runner";
export const BROWSER_COMPUTER_BROKER_ATTESTATION_RUNNER = "telclaude-browser-computer-broker-probe";
export const BROWSER_COMPUTER_BROKER_ATTESTATION_PATH =
	"/v1/hermes.browser-computer-broker.attestation";

const BROWSER_COMPUTER_BROKER_ATTESTATION_SCOPE = "operator";

type BrowserComputerBrokerAttestationProbeId =
	| "browser.profiles"
	| "computer.broker"
	| "network.egress-broker";

type BrowserComputerBrokerEvidenceLike = {
	readonly schemaVersion: string;
	readonly probeId: BrowserComputerBrokerAttestationProbeId;
	readonly status: "pass" | "fail";
	readonly ran: boolean;
	readonly observedAt: string;
	readonly source: string;
	readonly checks: readonly unknown[];
	readonly observations: unknown;
};

export type BrowserComputerBrokerAttestationSignedFields = {
	readonly schemaVersion: typeof BROWSER_COMPUTER_BROKER_ATTESTATION_SCHEMA_VERSION;
	readonly source: typeof BROWSER_COMPUTER_BROKER_ATTESTATION_SOURCE;
	readonly runner: typeof BROWSER_COMPUTER_BROKER_ATTESTATION_RUNNER;
	readonly probeEvidenceSchemaVersion: string;
	readonly probeId: BrowserComputerBrokerAttestationProbeId;
	readonly status: "pass" | "fail";
	readonly ran: boolean;
	readonly observedAt: string;
	readonly evidenceSource: string;
	readonly checksSha256: `sha256:${string}`;
	readonly observationsSha256: `sha256:${string}`;
	readonly evidenceSha256: `sha256:${string}`;
};

export type BrowserComputerBrokerAttestation = BrowserComputerBrokerAttestationSignedFields & {
	readonly signature: InternalResponseProof;
};

export function browserComputerBrokerAttestationFieldsForEvidence(
	evidence: BrowserComputerBrokerEvidenceLike,
): BrowserComputerBrokerAttestationSignedFields {
	return {
		schemaVersion: BROWSER_COMPUTER_BROKER_ATTESTATION_SCHEMA_VERSION,
		source: BROWSER_COMPUTER_BROKER_ATTESTATION_SOURCE,
		runner: BROWSER_COMPUTER_BROKER_ATTESTATION_RUNNER,
		probeEvidenceSchemaVersion: evidence.schemaVersion,
		probeId: evidence.probeId,
		status: evidence.status,
		ran: evidence.ran,
		observedAt: evidence.observedAt,
		evidenceSource: evidence.source,
		checksSha256: sha256Json(evidence.checks),
		observationsSha256: sha256Json(evidence.observations),
		evidenceSha256: browserComputerBrokerEvidenceSha256(evidence),
	};
}

export function signBrowserComputerBrokerAttestation(
	evidence: BrowserComputerBrokerEvidenceLike,
): BrowserComputerBrokerAttestation {
	const attestation = browserComputerBrokerAttestationFieldsForEvidence(evidence);
	const payload = browserComputerBrokerAttestationSignedPayload(attestation);
	return {
		...attestation,
		signature: buildInternalResponseProof(
			"POST",
			BROWSER_COMPUTER_BROKER_ATTESTATION_PATH,
			payload,
			payload,
			{ scope: BROWSER_COMPUTER_BROKER_ATTESTATION_SCOPE },
		),
	};
}

export function browserComputerBrokerAttestationSignatureFailure(
	attestation: BrowserComputerBrokerAttestationSignedFields & {
		readonly signature?: InternalResponseProof;
	},
	options?: {
		readonly allowStale?: boolean;
	},
): string | null {
	if (!attestation.signature) return "signature is missing";
	const payload = browserComputerBrokerAttestationSignedPayload(attestation);
	return internalResponseProofVerificationFailure(
		attestation.signature,
		"POST",
		BROWSER_COMPUTER_BROKER_ATTESTATION_PATH,
		payload,
		payload,
		{
			scope: BROWSER_COMPUTER_BROKER_ATTESTATION_SCOPE,
			allowStale: options?.allowStale,
		},
	);
}

export function browserComputerBrokerEvidenceSha256(
	evidence: BrowserComputerBrokerEvidenceLike,
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

function browserComputerBrokerAttestationSignedPayload(
	attestation: BrowserComputerBrokerAttestationSignedFields,
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
