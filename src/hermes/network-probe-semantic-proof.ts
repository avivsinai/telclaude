export const POSITIVE_NETWORK_DENIAL_ERROR_CODES = new Set([
	"ECONNREFUSED",
	"EHOSTUNREACH",
	"ENETUNREACH",
	"EACCES",
	"EPERM",
]);
export const REQUIRED_CONTAINED_PROVIDER_DENY_NAMES = [
	"bank",
	"clalit",
	"government",
	"google",
] as const;

export type NetworkProbeSemanticAttempt = {
	readonly name?: string;
	readonly kind?: string;
	readonly expectation?: string;
	readonly status?: string;
	readonly observed?: string;
	readonly errorCode?: string;
	readonly resolvedAddresses?: ReadonlyArray<{ readonly nonOverridable?: boolean }>;
};

export type NetworkProbeSemanticEvidence = {
	readonly id: string;
	readonly posture?: string;
	readonly attempts: readonly NetworkProbeSemanticAttempt[];
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
		if (!hasContainedInternalProof(evidence)) {
			failures.push(
				`network probe evidence ${evidence.id} contained-internal denial proof is missing or not pass`,
			);
		}
		if (evidence.id === "network.direct-provider-denied") {
			failures.push(...containedInternalProviderDenyFailures(evidence));
		}
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
		(attempt) => attempt.kind === "firewall_sentinel" && attempt.status === "pass",
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
						hasPositiveContainedHttpDenial(attempt)),
			);
		default:
			return evidence.attempts.some(hasPositiveContainedHttpDenial);
	}
}

function hasPositiveContainedHttpDenial(attempt: NetworkProbeSemanticAttempt): boolean {
	return (
		(attempt.kind === "http" || attempt.kind === "dns_guard") &&
		attempt.expectation === "deny" &&
		attempt.status === "pass" &&
		attempt.observed === "denied" &&
		attempt.errorCode !== undefined &&
		POSITIVE_NETWORK_DENIAL_ERROR_CODES.has(attempt.errorCode)
	);
}

function containedInternalProviderDenyFailures(evidence: NetworkProbeSemanticEvidence): string[] {
	const failures: string[] = [];
	for (const provider of REQUIRED_CONTAINED_PROVIDER_DENY_NAMES) {
		const attemptName = `provider:${provider}`;
		const attempt = evidence.attempts.find((candidate) => candidate.name === attemptName);
		if (!attempt || !hasPositiveContainedProviderHttpDenial(attempt)) {
			failures.push(
				`network probe evidence ${evidence.id} ${attemptName} contained-internal denial proof is missing or not pass`,
			);
		}
	}
	return failures;
}

function hasPositiveContainedProviderHttpDenial(attempt: NetworkProbeSemanticAttempt): boolean {
	return (
		attempt.kind === "http" &&
		attempt.expectation === "deny" &&
		attempt.status === "pass" &&
		attempt.observed === "denied" &&
		attempt.errorCode !== undefined &&
		POSITIVE_NETWORK_DENIAL_ERROR_CODES.has(attempt.errorCode)
	);
}

function hasNonOverridableDnsGuard(evidence: NetworkProbeSemanticEvidence): boolean {
	return evidence.attempts.some(
		(attempt) =>
			attempt.kind === "dns_guard" &&
			attempt.resolvedAddresses?.some((address) => address.nonOverridable) === true,
	);
}
