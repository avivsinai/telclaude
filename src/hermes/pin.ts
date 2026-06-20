export const DEFAULT_HERMES_UPSTREAM_REF = "v2026.5.29";
export const DEFAULT_HERMES_UPSTREAM_VERSION = "0.15.1";
export const DEFAULT_HERMES_SOURCE_COMMIT = "e71a2bd11b733f3be7cf99deafde0066c343d462";
export const DEFAULT_HERMES_IMAGE_TAG = "nousresearch/hermes-agent:v2026.5.29";
export const DEFAULT_HERMES_IMAGE_DIGEST =
	"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7";
export const DEFAULT_HERMES_DOCKER_IMAGE =
	`nousresearch/hermes-agent@${DEFAULT_HERMES_IMAGE_DIGEST}` as const;

export const DEFAULT_HERMES_PIN = {
	version: DEFAULT_HERMES_UPSTREAM_VERSION,
	commit: DEFAULT_HERMES_SOURCE_COMMIT,
	imageDigest: DEFAULT_HERMES_IMAGE_DIGEST,
} as const;

export const HERMES_VERSION_UPDATE_TARGET = {
	ref: "v2026.6.19",
	version: "0.17.0",
	sourceCommit: "2bd1977d8fad185c9b4be47884f7e87f1add0ce3",
	imageTag: "nousresearch/hermes-agent:v2026.6.19",
	imageDigest: "sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e",
	image:
		"nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e",
	releaseDate: "2026-06-19",
	versionSource: "NousResearch/hermes-agent pyproject.toml at v2026.6.19",
	digestSource: "Docker registry manifest digest for nousresearch/hermes-agent:v2026.6.19",
} as const;

export type HermesVersionUpdateGate = {
	readonly id: string;
	readonly description: string;
	readonly command: string;
	readonly requiredEvidence: string;
};

export const HERMES_VERSION_UPDATE_GATES: readonly HermesVersionUpdateGate[] = [
	{
		id: "upstream.no_fork_clean",
		description: "Prove the target checkout is exactly the upstream tag with no local diff.",
		command:
			"pnpm dev hermes prove --upstream-clean --checkout artifacts/hermes/version-update-v2026.6.19/hermes-agent-v2026.6.19-git --expected-ref v2026.6.19 --expected-version 0.17.0 --expected-commit 2bd1977d8fad185c9b4be47884f7e87f1add0ce3 --wrapper-run artifacts/hermes/version-update-v2026.6.19/wrapper-run.json --out artifacts/hermes/version-update-v2026.6.19/no-fork.json",
		requiredEvidence:
			"hermesCheckoutClean=true with signed checkout-bound wrapper-run evidence and signed runner/P0 attestation",
	},
	{
		id: "feature_probes.regenerated",
		description: "Regenerate the feature-probe matrix from observed target-pin evidence.",
		command:
			"pnpm dev hermes probes --pin 0.17.0 --out artifacts/hermes/version-update-v2026.6.19/feature-probes.json",
		requiredEvidence:
			"Every feature probe is pass for the target pin; dry matrix drafts that fail stay out of tracked seeds.",
	},
	{
		id: "network_probes.signed",
		description: "Run signed contained-network probes against the target image.",
		command:
			"TELCLAUDE_HERMES_IMAGE=nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e pnpm dev hermes network-probes --allow-run --posture contained-internal --out artifacts/hermes/version-update-v2026.6.19/network-probes.json --evidence-dir artifacts/hermes/version-update-v2026.6.19/network-probes",
		requiredEvidence:
			"Runner-scoped signed report with relay-control allowed and direct provider/vault/model/DNS exfil denied.",
	},
	{
		id: "compat_lock.bound",
		description: "Bind the target pin, feature matrix, no-fork proof, and source digests.",
		command:
			"pnpm dev hermes compat-lock --dry-run --pin 0.17.0 --feature-probes artifacts/hermes/version-update-v2026.6.19/feature-probes.json --nofork-proof artifacts/hermes/version-update-v2026.6.19/no-fork.json --out artifacts/hermes/version-update-v2026.6.19/hermes-compat.lock.json",
		requiredEvidence: "Lockfile digest matches the regenerated target-pin feature matrix.",
	},
	{
		id: "doctor.gate",
		description: "Run the static production gate against the target pin and regenerated artifacts.",
		command:
			"pnpm dev hermes doctor --pin 0.17.0 --feature-probes artifacts/hermes/version-update-v2026.6.19/feature-probes.json --probes --lockfile artifacts/hermes/version-update-v2026.6.19/hermes-compat.lock.json --compat-lock --json",
		requiredEvidence: "doctor status=pass",
	},
	{
		id: "live.verify",
		description: "Exercise the live contained runtime on the target image.",
		command:
			"TELCLAUDE_HERMES_IMAGE=nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e pnpm dev hermes verify-live --json --out artifacts/hermes/version-update-v2026.6.19/verify-live.json",
		requiredEvidence:
			"verify-live report status=pass including runtime.toolset_inventory and runtime.skill_manage_write_denied",
	},
] as const;

export function buildHermesVersionUpdatePlan() {
	return {
		schemaVersion: "telclaude.hermes.version-update.v1",
		current: {
			ref: DEFAULT_HERMES_UPSTREAM_REF,
			version: DEFAULT_HERMES_UPSTREAM_VERSION,
			sourceCommit: DEFAULT_HERMES_SOURCE_COMMIT,
			imageTag: DEFAULT_HERMES_IMAGE_TAG,
			imageDigest: DEFAULT_HERMES_IMAGE_DIGEST,
			image: DEFAULT_HERMES_DOCKER_IMAGE,
		},
		target: HERMES_VERSION_UPDATE_TARGET,
		status: "target_identified_production_bump_pending_evidence",
		productionDefaultRule:
			"Do not move docker/script defaults or tracked pass artifacts to the target pin until every required gate passes on the target image.",
		requiredGates: HERMES_VERSION_UPDATE_GATES,
	};
}

export type HermesVersionUpdatePlan = ReturnType<typeof buildHermesVersionUpdatePlan>;
