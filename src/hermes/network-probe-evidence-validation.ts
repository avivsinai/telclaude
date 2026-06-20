import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import {
	NETWORK_PROBE_ATTESTATION_RUNNER,
	NETWORK_PROBE_ATTESTATION_SCHEMA_VERSION,
	NETWORK_PROBE_ATTESTATION_SOURCE,
	type NetworkProbeAttestation,
	networkProbeAttestationFieldsForEvidence,
	networkProbeAttestationSignatureFailure,
} from "./network-probe-attestation.js";
import { NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION } from "./network-probe-schema.js";
import { networkProbeSemanticProofFailures } from "./network-probe-semantic-proof.js";

export const NETWORK_PROBE_IDS = [
	"network.relay-control-allowed",
	"network.direct-provider-denied",
	"network.direct-vault-denied",
	"network.direct-model-provider-denied",
	"network.dns-exfil-denied",
] as const;

export type NetworkProbeId = (typeof NETWORK_PROBE_IDS)[number];
export type NetworkProbeStatus = "pass" | "fail" | "pending";

export const NETWORK_PROBE_POSTURES = ["agent-iptables", "contained-internal"] as const;
export type NetworkProbePosture = (typeof NETWORK_PROBE_POSTURES)[number];

export type NetworkProbeAttempt = {
	name: string;
	kind: "http" | "unix_socket" | "dns_guard" | "firewall_sentinel" | "configuration";
	target: string;
	expectation: "allow" | "deny" | "present" | "configured";
	status: "pass" | "fail";
	observed: string;
	detail: string;
	durationMs?: number;
	httpStatus?: number;
	errorName?: string;
	errorCode?: string;
	resolvedAddresses?: Array<{ address: string; blocked: boolean; nonOverridable: boolean }>;
};

export type NetworkProbeEvidence = {
	schemaVersion: typeof NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION;
	id: NetworkProbeId;
	posture: NetworkProbePosture;
	status: NetworkProbeStatus;
	ran: boolean;
	summary: string;
	generatedAt: string;
	evidence_path: string;
	attempts: NetworkProbeAttempt[];
	attestation?: NetworkProbeAttestation;
};

export type NetworkProbeEvidenceValidationOptions = {
	readonly expectedId?: NetworkProbeId;
	readonly requiredAttemptNames?: readonly string[];
	readonly requiredPosture?: NetworkProbePosture;
	readonly requireAttestation?: boolean;
} & HermesSignedEvidenceValidationOptions;

export function networkProbeEvidenceFailure(
	evidence: unknown,
	options: NetworkProbeEvidenceValidationOptions = {},
): string | null {
	try {
		assertNetworkProbeEvidence(evidence, options);
		return null;
	} catch (error) {
		return error instanceof Error ? error.message : String(error);
	}
}

export function assertNetworkProbeEvidence(
	evidence: unknown,
	options: NetworkProbeEvidenceValidationOptions = {},
): NetworkProbeEvidence {
	const validated = validateNetworkProbeEvidenceObject(evidence, options.expectedId);
	if (options.requiredPosture && validated.posture !== options.requiredPosture) {
		throw new Error(
			`network probe evidence ${validated.id} posture is ${validated.posture}; expected ${options.requiredPosture}`,
		);
	}
	for (const [index, attempt] of validated.attempts.entries()) {
		validatePassingNetworkProbeAttempt(validated.id, index, attempt);
	}
	if (validated.attestation || options.requireAttestation !== false) {
		validateNetworkProbeAttestation(validated, options);
	}
	validateNetworkProbeSemanticProof(validated, options);
	for (const attemptName of options.requiredAttemptNames ?? []) {
		validateRequiredNetworkDenialAttempt(validated, attemptName);
	}
	return validated;
}

function validateNetworkProbeEvidenceObject(
	evidence: unknown,
	expectedId?: NetworkProbeId,
): NetworkProbeEvidence {
	if (!isRecord(evidence)) {
		throw new Error("network probe evidence must be a JSON object");
	}
	if (evidence.schemaVersion !== NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION) {
		throw new Error("network probe evidence has an unsupported schemaVersion");
	}
	if (!NETWORK_PROBE_IDS.includes(evidence.id as NetworkProbeId)) {
		throw new Error(`network probe evidence has unsupported id ${String(evidence.id)}`);
	}
	if (expectedId && evidence.id !== expectedId) {
		throw new Error(`network probe evidence id is ${String(evidence.id)}; expected ${expectedId}`);
	}
	if (!NETWORK_PROBE_POSTURES.includes(evidence.posture as NetworkProbePosture)) {
		throw new Error(
			`network probe evidence ${String(evidence.id)} posture is ${String(evidence.posture)}`,
		);
	}
	if (evidence.ran !== true) {
		throw new Error(`network probe evidence ${String(evidence.id)} was not run`);
	}
	if (evidence.status !== "pass") {
		throw new Error(
			`network probe evidence ${String(evidence.id)} status is ${String(evidence.status)}`,
		);
	}
	if (!Array.isArray(evidence.attempts) || evidence.attempts.length === 0) {
		throw new Error(`network probe evidence ${String(evidence.id)} has no attempts`);
	}
	return evidence as NetworkProbeEvidence;
}

function validatePassingNetworkProbeAttempt(
	id: NetworkProbeId,
	index: number,
	attempt: unknown,
): void {
	if (!isRecord(attempt)) {
		throw new Error(`network probe evidence ${id} attempt ${index} must be a JSON object`);
	}
	if (typeof attempt.name !== "string" || attempt.name.trim().length === 0) {
		throw new Error(`network probe evidence ${id} attempt ${index} name is missing`);
	}
	if (
		!["http", "unix_socket", "dns_guard", "firewall_sentinel", "configuration"].includes(
			String(attempt.kind),
		)
	) {
		throw new Error(`network probe evidence ${id} attempt ${index} kind is unsupported`);
	}
	if (!["allow", "deny", "present", "configured"].includes(String(attempt.expectation))) {
		throw new Error(`network probe evidence ${id} attempt ${index} expectation is unsupported`);
	}
	if (attempt.status !== "pass") {
		throw new Error(
			`network probe evidence ${id} attempt ${index} status is ${String(attempt.status)}`,
		);
	}
	for (const key of ["target", "observed", "detail"]) {
		if (typeof attempt[key] !== "string" || attempt[key].trim().length === 0) {
			throw new Error(`network probe evidence ${id} attempt ${index} ${key} is missing`);
		}
	}
}

function validateNetworkProbeSemanticProof(
	evidence: NetworkProbeEvidence,
	options?: {
		readonly requiredPosture?: NetworkProbePosture;
	},
): void {
	const [failure] = networkProbeSemanticProofFailures(evidence, {
		requiredProbeIds: NETWORK_PROBE_IDS,
		requiredPosture: options?.requiredPosture ?? "contained-internal",
	});
	if (failure) throw new Error(failure);
}

function validateNetworkProbeAttestation(
	evidence: NetworkProbeEvidence,
	options: HermesSignedEvidenceValidationOptions,
): void {
	if (!evidence.attestation) {
		throw new Error(`network probe evidence ${evidence.id} attestation is missing`);
	}
	if (evidence.attestation.schemaVersion !== NETWORK_PROBE_ATTESTATION_SCHEMA_VERSION) {
		throw new Error(`network probe evidence ${evidence.id} attestation schemaVersion is invalid`);
	}
	if (evidence.attestation.source !== NETWORK_PROBE_ATTESTATION_SOURCE) {
		throw new Error(`network probe evidence ${evidence.id} attestation source is invalid`);
	}
	if (evidence.attestation.runner !== NETWORK_PROBE_ATTESTATION_RUNNER) {
		throw new Error(`network probe evidence ${evidence.id} attestation runner is invalid`);
	}
	const freshnessFailure = hermesAttestationFreshnessFailure(
		`network probe evidence ${evidence.id} attestation generatedAt`,
		evidence.attestation.generatedAt,
		options,
	);
	if (freshnessFailure) {
		throw new Error(freshnessFailure);
	}
	const signatureFailure = networkProbeAttestationSignatureFailure(evidence.attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) {
		throw new Error(
			`network probe evidence ${evidence.id} attestation signature is invalid: ${signatureFailure}`,
		);
	}
	const expected = networkProbeAttestationFieldsForEvidence(evidence);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"posture",
		"status",
		"ran",
		"generatedAt",
		"attemptsSha256",
		"evidenceSha256",
	] as const) {
		if (evidence.attestation[field] !== expected[field]) {
			throw new Error(`network probe evidence ${evidence.id} attestation ${field} mismatch`);
		}
	}
}

function validateRequiredNetworkDenialAttempt(
	evidence: NetworkProbeEvidence,
	attemptName: string,
): void {
	const attempt = evidence.attempts.find((candidate) => candidate.name === attemptName);
	if (!attempt) {
		throw new Error(`network probe evidence ${evidence.id} attempt ${attemptName} is missing`);
	}
	if (
		attempt.kind !== "http" ||
		attempt.expectation !== "deny" ||
		attempt.status !== "pass" ||
		!isPassingHttpDenialAttempt(attempt)
	) {
		throw new Error(
			`network probe evidence ${evidence.id} attempt ${attemptName} is not a passing denial`,
		);
	}
}

function isPassingHttpDenialAttempt(attempt: NetworkProbeAttempt): boolean {
	return attempt.observed === "policy_denied" && attempt.httpStatus === 403;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
