import {
	NETWORK_PROBE_ATTESTATION_RUNNER,
	NETWORK_PROBE_ATTESTATION_SOURCE,
} from "./network-probe-attestation.js";

export const DNS_GUARD_NETWORK_DENIAL_ERROR_CODES = new Set([
	"EHOSTDOWN",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EACCES",
	"EPERM",
]);
export const DIRECT_EGRESS_NETWORK_DENIAL_ERROR_CODES = new Set([
	...DNS_GUARD_NETWORK_DENIAL_ERROR_CODES,
	"ECONNREFUSED",
]);
export const REQUIRED_FIREWALL_SENTINEL_PATH = "/run/telclaude/firewall-active";
export const REQUIRED_CONTAINED_PROVIDER_DENY_NAMES = [
	"bank",
	"clalit",
	"government",
	"google",
] as const;

export type NetworkProbeSemanticAttempt = {
	readonly name?: string;
	readonly kind?: string;
	readonly target?: string;
	readonly expectation?: string;
	readonly status?: string;
	readonly observed?: string;
	readonly httpStatus?: number;
	readonly errorCode?: string;
	readonly resolvedAddresses?: ReadonlyArray<{ readonly nonOverridable?: boolean }>;
};

export type NetworkProbeSemanticEvidence = {
	readonly id: string;
	readonly posture?: string;
	readonly attempts: readonly NetworkProbeSemanticAttempt[];
	readonly attestation?: {
		readonly source?: string;
		readonly runner?: string;
	};
};

export type NetworkProbeSemanticProofOptions = {
	readonly requiredProbeIds: ReadonlySet<string> | readonly string[];
	readonly requiredPosture: string;
	readonly allowFirewallSentinelFallback?: boolean;
};

export function networkProbeSemanticProofFailures(
	evidence: NetworkProbeSemanticEvidence,
	options: NetworkProbeSemanticProofOptions,
): string[] {
	if (!requiredProbeIds(options.requiredProbeIds).has(evidence.id)) return [];
	const failures: string[] = [];
	if (evidence.posture !== options.requiredPosture) {
		failures.push(
			`network probe evidence ${evidence.id} posture is ${
				evidence.posture ?? "missing"
			}; expected ${options.requiredPosture}`,
		);
	}
	const posture = evidence.posture ?? "agent-iptables";
	if (posture === "contained-internal") {
		const directAttributionFailure = directNetworkDenialAttributionFailure(evidence);
		if (directAttributionFailure) {
			failures.push(directAttributionFailure);
		}
		if (!hasContainedInternalProof(evidence)) {
			failures.push(
				`network probe evidence ${evidence.id} contained-internal denial proof is missing or not pass`,
			);
		}
		if (evidence.id === "network.direct-provider-denied") {
			failures.push(...containedInternalProviderDenyFailures(evidence));
		}
	} else if (hasAnyDirectNetworkDenial(evidence)) {
		failures.push(
			`network probe evidence ${evidence.id} direct network denial requires contained-internal posture`,
		);
	} else if (options.allowFirewallSentinelFallback === true) {
		if (!hasPassingFirewallSentinel(evidence)) {
			failures.push(
				`network probe evidence ${evidence.id} firewall_sentinel attempt is missing or not pass`,
			);
		}
	} else if (!hasContainedInternalProof(evidence)) {
		failures.push(
			`network probe evidence ${evidence.id} contained-internal denial proof is missing or not pass`,
		);
	}
	if (evidence.id === "network.dns-exfil-denied" && !hasNonOverridableDnsGuard(evidence)) {
		failures.push(
			`network probe evidence ${evidence.id} dns_guard lacks nonOverridable resolved address`,
		);
	}
	return failures;
}

function requiredProbeIds(ids: ReadonlySet<string> | readonly string[]): ReadonlySet<string> {
	return ids instanceof Set ? ids : new Set(ids);
}

function hasPassingFirewallSentinel(evidence: NetworkProbeSemanticEvidence): boolean {
	return evidence.attempts.some(
		(attempt) =>
			attempt.name === "firewall-sentinel" &&
			attempt.kind === "firewall_sentinel" &&
			attempt.target === REQUIRED_FIREWALL_SENTINEL_PATH &&
			attempt.expectation === "present" &&
			attempt.status === "pass" &&
			attempt.observed === "present",
	);
}

function hasContainedInternalProof(evidence: NetworkProbeSemanticEvidence): boolean {
	switch (evidence.id) {
		case "network.relay-control-allowed":
			return evidence.attempts.some(
				(attempt) =>
					attempt.kind === "http" && attempt.expectation === "allow" && attempt.status === "pass",
			);
		case "network.direct-vault-denied":
			return evidence.attempts.some(
				(attempt) =>
					attempt.expectation === "deny" &&
					attempt.status === "pass" &&
					((attempt.kind === "unix_socket" && attempt.observed === "absent") ||
						hasPolicyProxyDenial(attempt) ||
						hasSentinelAttributedDirectNetworkDenial(evidence, attempt)),
			);
		case "network.dns-exfil-denied":
			return evidence.attempts.some(hasPositiveDnsGuardDenial);
		default:
			return evidence.attempts.some(
				(attempt) =>
					hasPolicyProxyDenial(attempt) ||
					hasSentinelAttributedDirectNetworkDenial(evidence, attempt),
			);
	}
}

function hasPositiveDnsGuardDenial(attempt: NetworkProbeSemanticAttempt): boolean {
	return (
		attempt.kind === "dns_guard" &&
		attempt.expectation === "deny" &&
		attempt.status === "pass" &&
		attempt.observed === "denied" &&
		attempt.errorCode !== undefined &&
		DNS_GUARD_NETWORK_DENIAL_ERROR_CODES.has(attempt.errorCode) &&
		attempt.resolvedAddresses?.some((address) => address.nonOverridable) === true
	);
}

function containedInternalProviderDenyFailures(evidence: NetworkProbeSemanticEvidence): string[] {
	const failures: string[] = [];
	for (const provider of REQUIRED_CONTAINED_PROVIDER_DENY_NAMES) {
		const attemptName = `provider:${provider}`;
		const attempt = evidence.attempts.find((candidate) => candidate.name === attemptName);
		if (!attempt || !hasPositiveContainedProviderHttpDenial(evidence, attempt)) {
			failures.push(
				`network probe evidence ${evidence.id} ${attemptName} contained-internal denial proof is missing or not pass`,
			);
		}
	}
	return failures;
}

function hasPositiveContainedProviderHttpDenial(
	evidence: NetworkProbeSemanticEvidence,
	attempt: NetworkProbeSemanticAttempt,
): boolean {
	return (
		hasPolicyProxyDenial(attempt) || hasSentinelAttributedDirectNetworkDenial(evidence, attempt)
	);
}

function hasPolicyProxyDenial(attempt: NetworkProbeSemanticAttempt): boolean {
	return (
		attempt.kind === "http" &&
		attempt.expectation === "deny" &&
		attempt.status === "pass" &&
		attempt.observed === "policy_denied" &&
		attempt.httpStatus === 403
	);
}

function hasSentinelAttributedDirectNetworkDenial(
	evidence: NetworkProbeSemanticEvidence,
	attempt: NetworkProbeSemanticAttempt,
): boolean {
	// The sentinel is namespace-scoped: it proves default-deny in the runner's
	// single internal-only egress namespace, not per-target reachability.
	return (
		evidence.posture === "contained-internal" &&
		hasRunnerAttestation(evidence) &&
		hasPassingFirewallSentinel(evidence) &&
		hasDirectNetworkDenial(attempt)
	);
}

function directNetworkDenialAttributionFailure(
	evidence: NetworkProbeSemanticEvidence,
): string | null {
	if (!hasAnyDirectNetworkDenial(evidence)) return null;
	if (!hasRunnerAttestation(evidence)) {
		return `network probe evidence ${evidence.id} direct network denial requires signed runner attestation`;
	}
	if (!hasPassingFirewallSentinel(evidence)) {
		return `network probe evidence ${evidence.id} direct network denial lacks firewall_sentinel attribution`;
	}
	return null;
}

function hasAnyDirectNetworkDenial(evidence: NetworkProbeSemanticEvidence): boolean {
	return evidence.attempts.some(hasDirectNetworkDenial);
}

function hasDirectNetworkDenial(attempt: NetworkProbeSemanticAttempt): boolean {
	return (
		attempt.kind === "http" &&
		attempt.expectation === "deny" &&
		attempt.status === "pass" &&
		attempt.observed === "denied" &&
		attempt.errorCode !== undefined &&
		DIRECT_EGRESS_NETWORK_DENIAL_ERROR_CODES.has(attempt.errorCode)
	);
}

function hasRunnerAttestation(evidence: NetworkProbeSemanticEvidence): boolean {
	// This marker only routes semantic proof; evidence validation verifies the
	// runner-scope signature and attempts/evidence digests before this point.
	return (
		evidence.attestation?.source === NETWORK_PROBE_ATTESTATION_SOURCE &&
		evidence.attestation.runner === NETWORK_PROBE_ATTESTATION_RUNNER
	);
}

function hasNonOverridableDnsGuard(evidence: NetworkProbeSemanticEvidence): boolean {
	return evidence.attempts.some(
		(attempt) =>
			attempt.kind === "dns_guard" &&
			attempt.resolvedAddresses?.some((address) => address.nonOverridable) === true,
	);
}
