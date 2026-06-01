const MAX_CUTOVER_PROOF_ARTIFACT_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export type HermesSignedEvidenceValidationOptions = {
	readonly allowStaleAttestations?: boolean;
	readonly now?: Date;
};

export function hermesAllowsStaleAttestations(
	options: HermesSignedEvidenceValidationOptions = {},
): boolean {
	return options.allowStaleAttestations ?? true;
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
