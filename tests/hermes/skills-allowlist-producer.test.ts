import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	evaluateSkillsAllowlistEvidence,
	runSkillsAllowlistProbe,
	type SkillsAllowlistRunner,
} from "../../src/hermes/skills-allowlist-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

// The producer signs evidence with the operator relay key; provide a deterministic
// keypair so signSkillsAllowlistAttestation can sign and the evaluator can verify.
const savedRelayKeys = {
	private: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	public: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
};
beforeEach(() => {
	const relayKeys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = relayKeys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = relayKeys.publicKey;
});
afterEach(() => {
	if (savedRelayKeys.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelayKeys.private;
	if (savedRelayKeys.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelayKeys.public;
});

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

// Canonical contract every probe scenario MUST satisfy. A blanket passed:true runner
// would still accept a producer that drifted to the wrong skill, allowlist, decision,
// kind, or dropped/added a scenario; asserting each field (and the full property set)
// makes that drift break the test instead of silently passing.
type ScenarioContract = {
	kind: "profile" | "pretooluse";
	allowlistedSkill: string;
	nonAllowlistedSkill: string;
	expectedDecision?: "allow" | "deny";
	omitAllowedSkills?: boolean;
	allowedSkills?: readonly string[];
};
const EXPECTED_SCENARIOS: Record<string, ScenarioContract> = {
	allowlist_manifest_present: {
		kind: "profile",
		allowlistedSkill: "software-development/plan",
		nonAllowlistedSkill: "red-teaming/godmode",
	},
	allowlisted_skill_present: {
		kind: "profile",
		allowlistedSkill: "software-development/plan",
		nonAllowlistedSkill: "red-teaming/godmode",
	},
	nonallowlisted_skill_absent: {
		kind: "profile",
		allowlistedSkill: "software-development/plan",
		nonAllowlistedSkill: "red-teaming/godmode",
	},
	runtime_skills_match_allowlist: {
		kind: "profile",
		allowlistedSkill: "software-development/plan",
		nonAllowlistedSkill: "red-teaming/godmode",
	},
	skill_creation_nudge_disabled: {
		kind: "profile",
		allowlistedSkill: "software-development/plan",
		nonAllowlistedSkill: "red-teaming/godmode",
	},
	pretooluse_hook_registered: {
		kind: "pretooluse",
		allowlistedSkill: "plan",
		nonAllowlistedSkill: "godmode",
		expectedDecision: "allow",
		allowedSkills: ["plan"],
	},
	allowlisted_skill_invocation_allowed: {
		kind: "pretooluse",
		allowlistedSkill: "plan",
		nonAllowlistedSkill: "godmode",
		expectedDecision: "allow",
		allowedSkills: ["plan"],
	},
	nonallowlisted_skill_invocation_denied: {
		kind: "pretooluse",
		allowlistedSkill: "plan",
		nonAllowlistedSkill: "test-driven-development",
		expectedDecision: "deny",
		allowedSkills: ["plan"],
	},
	social_missing_allowlist_denied: {
		kind: "pretooluse",
		allowlistedSkill: "plan",
		nonAllowlistedSkill: "godmode",
		expectedDecision: "deny",
		omitAllowedSkills: true,
	},
	social_empty_allowlist_denied: {
		kind: "pretooluse",
		allowlistedSkill: "plan",
		nonAllowlistedSkill: "godmode",
		expectedDecision: "deny",
		allowedSkills: [],
	},
};

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

	it("uses filesystem paths for profile proof and Hermes runtime names for hook proof", async () => {
		const scenarios: Parameters<SkillsAllowlistRunner>[0][] = [];
		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: async (scenario) => {
				scenarios.push(scenario);
				return {
					passed: true,
					observationLayer: "docker_exec",
					...(scenario.kind === "pretooluse" ? { enforcementLayer: "pretooluse" as const } : {}),
				};
			},
			observeTopology: containedTopology,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});
		expect(evidence.status).toBe("pass");
		expect(
			scenarios.find((scenario) => scenario.property === "allowlisted_skill_present"),
		).toMatchObject({
			kind: "profile",
			allowlistedSkill: "software-development/plan",
		});
		expect(
			scenarios.find((scenario) => scenario.property === "allowlisted_skill_invocation_allowed"),
		).toMatchObject({
			kind: "pretooluse",
			allowlistedSkill: "plan",
			allowedSkills: ["plan"],
		});
		expect(
			scenarios.find((scenario) => scenario.property === "nonallowlisted_skill_invocation_denied"),
		).toMatchObject({
			kind: "pretooluse",
			allowlistedSkill: "plan",
			nonAllowlistedSkill: "test-driven-development",
			allowedSkills: ["plan"],
		});
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

	it("asserts every producer scenario matches its contract (drift-proof)", async () => {
		const seen: string[] = [];
		const violations: string[] = [];
		const strictRunner: SkillsAllowlistRunner = async (scenario) => {
			seen.push(scenario.property);
			const expected = EXPECTED_SCENARIOS[scenario.property];
			if (!expected) {
				violations.push(`unexpected scenario property: ${scenario.property}`);
			} else {
				// Compare the full contract, key order fixed so the JSON match is exact;
				// undefined fields drop out of both sides, while [] stays distinct from undefined.
				const actual = JSON.stringify({
					kind: scenario.kind,
					allowlistedSkill: scenario.allowlistedSkill,
					nonAllowlistedSkill: scenario.nonAllowlistedSkill,
					expectedDecision: scenario.expectedDecision,
					omitAllowedSkills: scenario.omitAllowedSkills,
					allowedSkills: scenario.allowedSkills,
				});
				const want = JSON.stringify({
					kind: expected.kind,
					allowlistedSkill: expected.allowlistedSkill,
					nonAllowlistedSkill: expected.nonAllowlistedSkill,
					expectedDecision: expected.expectedDecision,
					omitAllowedSkills: expected.omitAllowedSkills,
					allowedSkills: expected.allowedSkills,
				});
				if (actual !== want) {
					violations.push(`${scenario.property} contract drift: got ${actual} want ${want}`);
				}
			}
			return {
				passed: true,
				observationLayer: "docker_exec",
				...(scenario.kind === "pretooluse" ? { enforcementLayer: "pretooluse" as const } : {}),
			};
		};

		const evidence = await runSkillsAllowlistProbe({
			allowRun: true,
			runner: strictRunner,
			observeTopology: containedTopology,
			now: new Date("2026-06-05T20:00:00.000Z"),
		});

		expect(violations).toEqual([]);
		// Set equality catches a dropped OR added scenario, not just a mutated one.
		expect([...seen].sort()).toEqual(Object.keys(EXPECTED_SCENARIOS).sort());
		expect(evidence.status).toBe("pass");
		expect(evaluateSkillsAllowlistEvidence(evidence).status).toBe("pass");
	});
});
