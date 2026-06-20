import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
	buildHermesVersionUpdatePlan,
	DEFAULT_HERMES_DOCKER_IMAGE,
	DEFAULT_HERMES_IMAGE_DIGEST,
	DEFAULT_HERMES_IMAGE_TAG,
	DEFAULT_HERMES_PIN,
	DEFAULT_HERMES_SOURCE_COMMIT,
	DEFAULT_HERMES_UPSTREAM_REF,
	DEFAULT_HERMES_UPSTREAM_VERSION,
	HERMES_VERSION_UPDATE_TARGET,
} from "../../src/hermes/pin.js";

describe("Hermes pinned upstream", () => {
	it("records the current production pin facts in one canonical module", () => {
		expect(DEFAULT_HERMES_UPSTREAM_REF).toBe("v2026.5.29");
		expect(DEFAULT_HERMES_UPSTREAM_VERSION).toBe("0.15.1");
		expect(DEFAULT_HERMES_SOURCE_COMMIT).toBe("e71a2bd11b733f3be7cf99deafde0066c343d462");
		expect(DEFAULT_HERMES_IMAGE_DIGEST).toBe(
			"sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		);
		expect(DEFAULT_HERMES_IMAGE_TAG).toBe("nousresearch/hermes-agent:v2026.5.29");
		expect(DEFAULT_HERMES_DOCKER_IMAGE).toBe(
			"nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7",
		);
		expect(DEFAULT_HERMES_PIN).toEqual({
			version: DEFAULT_HERMES_UPSTREAM_VERSION,
			commit: DEFAULT_HERMES_SOURCE_COMMIT,
			imageDigest: DEFAULT_HERMES_IMAGE_DIGEST,
		});
	});

	it("names the next upstream target without moving production defaults before evidence", () => {
		expect(HERMES_VERSION_UPDATE_TARGET).toMatchObject({
			ref: "v2026.6.19",
			version: "0.17.0",
			sourceCommit: "2bd1977d8fad185c9b4be47884f7e87f1add0ce3",
			imageDigest: "sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e",
			image:
				"nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e",
		});

		const plan = buildHermesVersionUpdatePlan();
		expect(plan.current.image).toBe(DEFAULT_HERMES_DOCKER_IMAGE);
		expect(plan.target.image).toBe(HERMES_VERSION_UPDATE_TARGET.image);
		expect(plan.productionDefaultRule).toContain("Do not move docker/script defaults");
		expect(plan.requiredGates.map((gate) => gate.id)).toEqual([
			"upstream.no_fork_clean",
			"feature_probes.regenerated",
			"network_probes.signed",
			"compat_lock.bound",
			"doctor.gate",
			"live.verify",
		]);
		expect(plan.requiredGates.find((gate) => gate.id === "live.verify")?.requiredEvidence).toContain(
			"runtime.toolset_inventory",
		);
		expect(plan.requiredGates.find((gate) => gate.id === "live.verify")?.requiredEvidence).toContain(
			"runtime.skill_manage_write_denied",
		);
		expect(plan.requiredGates.find((gate) => gate.id === "upstream.no_fork_clean")?.command).toContain(
			"--expected-commit 2bd1977d8fad185c9b4be47884f7e87f1add0ce3",
		);
		expect(plan.requiredGates.map((gate) => gate.command).join("\n")).not.toContain(
			"--write-tracked-seed",
		);
		expect(
			plan.requiredGates.find((gate) => gate.id === "feature_probes.regenerated")?.command,
		).toContain("artifacts/hermes/version-update-v2026.6.19/feature-probes.json");
		expect(plan.requiredGates.find((gate) => gate.id === "network_probes.signed")?.command).toContain(
			"--out artifacts/hermes/version-update-v2026.6.19/network-probes.json",
		);
		expect(plan.requiredGates.find((gate) => gate.id === "compat_lock.bound")?.command).toContain(
			"artifacts/hermes/version-update-v2026.6.19/no-fork.json",
		);
		expect(plan.requiredGates.find((gate) => gate.id === "doctor.gate")?.command).toContain(
			"--feature-probes artifacts/hermes/version-update-v2026.6.19/feature-probes.json",
		);
		expect(plan.requiredGates.find((gate) => gate.id === "doctor.gate")?.command).toContain(
			"--lockfile artifacts/hermes/version-update-v2026.6.19/hermes-compat.lock.json",
		);
		expect(plan.requiredGates.find((gate) => gate.id === "live.verify")?.command).toContain(
			"--out artifacts/hermes/version-update-v2026.6.19/verify-live.json",
		);
	});

	it("keeps operator-facing defaults aligned with the canonical pinned image", () => {
		const compose = readProjectFile("docker/docker-compose.hermes.yml");
		const envExample = readProjectFile("docker/.env.example");
		const cliProbe = readProjectFile("scripts/hermes-contained-cli-probe.sh");
		const architecture = readProjectFile("docs/architecture.md");

		expect(compose).toContain(DEFAULT_HERMES_DOCKER_IMAGE);
		expect(cliProbe).toContain(DEFAULT_HERMES_DOCKER_IMAGE);
		expect(envExample).toContain(DEFAULT_HERMES_DOCKER_IMAGE);
		expect(envExample).toContain(DEFAULT_HERMES_IMAGE_TAG);
		expect(architecture).toContain(
			`Hermes is pinned to upstream ref \`${DEFAULT_HERMES_UPSTREAM_REF}\` (version \`${DEFAULT_HERMES_UPSTREAM_VERSION}\`)`,
		);
	});
});

function readProjectFile(relativePath: string): string {
	return fs.readFileSync(path.resolve(process.cwd(), relativePath), "utf8");
}
