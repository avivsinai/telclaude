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

// Simulates the contained runtime: an allowlisted skill is allowed; everything
// else is denied by the primary PreToolUse hook.
const hookRunner: SkillsAllowlistRunner = async (scenario) => {
	const allowed = scenario.allowedSkills?.includes(scenario.skill) ?? false;
	return allowed ? { allowed: true } : { allowed: false, enforcementLayer: "pretooluse_hook" };
};

describe("runSkillsAllowlistProbe", () => {
	it("produces evidence the evaluator accepts (round-trip)", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: hookRunner,
			observeTopology: containedTopology,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.status).toBe("pass");
		expect(evidence.origin.kind).toBe("contained-runtime");
		const report = evaluateSkillsAllowlistEvidence(evidence);
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
	});

	it("yields evaluator-REJECTED evidence when denials come only from the canUseTool fallback", async () => {
		const fallbackRunner: SkillsAllowlistRunner = async (scenario) => {
			const allowed = scenario.allowedSkills?.includes(scenario.skill) ?? false;
			return allowed ? { allowed: true } : { allowed: false, enforcementLayer: "can_use_tool" };
		};
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: fallbackRunner,
			observeTopology: containedTopology,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		// The producer records the fallback layer; the evaluator's primary-layer gate
		// (skills-1) must reject it — the two halves agree end-to-end.
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("fail");
	});

	it("fails origin when the runtime topology is not contained", async () => {
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: hookRunner,
			observeTopology: async () => ({
				containerName: "tc-hermes-contained",
				topologyInternal: false,
				relayContainerPresent: false,
			}),
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.origin.kind).toBe("unknown");
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("fail");
	});

	it("returns a fail-closed pending artifact without --allow-run", async () => {
		const evidence = await runSkillsAllowlistProbe({ allowRun: false });
		expect(evidence.ran).toBe(false);
		expect(evidence.status).toBe("pending");
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("fail");
	});
});
