import { describe, expect, it } from "vitest";
import {
	evaluateSkillsAllowlistEvidence,
	runSkillsAllowlistProbe,
	type SkillsAllowlistRunner,
} from "../../src/hermes/skills-allowlist-probe.js";

const containedTopology = async () => ({
	containerName: "tc-hermes-contained",
	topologyInternal: true,
	relayContainerPresent: true,
});

// Simulates docker-exec observations from the contained Hermes runtime profile.
const dockerRunner: SkillsAllowlistRunner = async (scenario) => ({
	passed: true,
	observationLayer: "docker_exec",
	...(scenario.kind === "pretooluse" ? { enforcementLayer: "pretooluse" as const } : {}),
});

describe("runSkillsAllowlistProbe", () => {
	it("produces evidence the evaluator accepts (round-trip)", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: containedTopology,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.status).toBe("pass");
		expect(evidence.origin.kind).toBe("contained-runtime");
		const report = evaluateSkillsAllowlistEvidence(evidence);
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
	});

	it("yields evaluator-REJECTED evidence when checks are not docker-exec observed", async () => {
		const localRunner: SkillsAllowlistRunner = async () => ({ passed: true });
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: localRunner,
			observeTopology: containedTopology,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.status).toBe("fail");
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("fail");
	});

	it("fails origin when the runtime topology is not contained", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: dockerRunner,
			observeTopology: async () => ({
				containerName: "tc-hermes-contained",
				topologyInternal: false,
				relayContainerPresent: false,
			}),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.origin.kind).toBe("unknown");
		expect(evidence.status).toBe("fail");
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("fail");
	});

	it("returns a fail-closed pending artifact without --allow-run", async () => {
		const evidence = await runSkillsAllowlistProbe({ allowRun: false });
		expect(evidence.ran).toBe(false);
		expect(evidence.status).toBe("pending");
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("fail");
	});
});
