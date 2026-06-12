const MAX_CUTOVER_PROOF_ARTIFACT_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Freshness window for evidence-attestation proof signatures (Ed25519
 * InternalResponseProof timestamps) under live evidence validation.
 *
 * Deliberately wider than the RPC anti-replay skew (DEFAULT_SKEW_MS, 5 min,
 * src/internal-auth.ts): evidence is captured by a multi-step operator-driven
 * sequence (probes → network promote → no-fork → doctor), and the prover and
 * verifier are the same operator shell —
 * a tighter window buys no additional trust, it only turns the capture into a
 * speedrun. Replay protection for live RPC keeps the tight default.
 */
export const HERMES_EVIDENCE_PROOF_MAX_SKEW_MS = 60 * 60 * 1000;

export type HermesSignedEvidenceValidationOptions = {
	readonly allowStaleAttestations?: boolean;
	readonly requireRunnerAttestation?: boolean;
	readonly now?: Date;
	readonly relayPublicKey?: string;
};

export function hermesAllowsStaleAttestations(
	options: HermesSignedEvidenceValidationOptions = {},
): boolean {
	return options.allowStaleAttestations ?? true;
}

export function hermesRequiresRunnerAttestation(
	options: HermesSignedEvidenceValidationOptions = {},
): boolean {
	return options.requireRunnerAttestation === true || !hermesAllowsStaleAttestations(options);
}

export function hermesAttestationFreshnessFailure(
	label: string,
	timestamp: string | undefined,
	options: HermesSignedEvidenceValidationOptions = {},
): string | null {
	if (hermesAllowsStaleAttestations(options)) return null;
	if (!timestamp) return `${label} is missing`;
	const now = options.now ?? new Date();
	return isHermesEvidenceTimestampStale(timestamp, now)
		? `${label} is stale or future-dated`
		: null;
}

export function isHermesEvidenceTimestampStale(timestamp: string, now: Date): boolean {
	const parsed = Date.parse(timestamp);
	if (Number.isNaN(parsed)) return true;
	const nowMs = now.getTime();
	return parsed > nowMs || nowMs - parsed > MAX_CUTOVER_PROOF_ARTIFACT_AGE_MS;
}
