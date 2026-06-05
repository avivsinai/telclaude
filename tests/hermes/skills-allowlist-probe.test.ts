import { describe, expect, it } from "vitest";
import {
	evaluateSkillsAllowlistEvidence,
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	type SkillsAllowlistEvidence,
} from "../../src/hermes/skills-allowlist-probe.js";

function validEvidence(): SkillsAllowlistEvidence {
	const properties = Object.fromEntries(
		SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	) as SkillsAllowlistEvidence["properties"];
	const checks = SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => ({
		name,
		status: "pass" as const,
		detail: `${name} proven`,
	}));
	return {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: "pass",
		ran: true,
		generatedAt: "2026-06-05T20:00:00.000Z",
		summary: "skills allowlist enforced fail-closed in contained runtime",
		provenance: {
			source: "machine-observed-runtime",
			runtime: "tc-hermes-contained",
			detail: "ran the real skill-invocation path",
		},
		properties,
		checks,
	};
}

describe("evaluateSkillsAllowlistEvidence", () => {
	it("passes for complete, check-backed, machine-observed evidence", () => {
		const report = evaluateSkillsAllowlistEvidence(validEvidence());
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
	});

	it("input_errors when evidence is missing", () => {
		expect(evaluateSkillsAllowlistEvidence(undefined).status).toBe("input_error");
	});

	it("input_errors on a schema-invalid artifact", () => {
		expect(evaluateSkillsAllowlistEvidence({ schemaVersion: "nope" }).status).toBe("input_error");
	});

	it("fails provenance for mock or imported evidence", () => {
		const ev = validEvidence();
		for (const source of ["mock", "imported"] as const) {
			const report = evaluateSkillsAllowlistEvidence({
				...ev,
				provenance: { ...ev.provenance, source },
			});
			expect(report.status).toBe("fail");
			expect(report.gates.find((g) => g.name === "skills.provenance")?.status).toBe("fail");
		}
	});

	it("fails when SOCIAL fail-closed (omitted allowlist denies all) is not proven", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, social_omitted_allowlist_denies_all: false },
		});
		expect(report.status).toBe("fail");
		expect(
			report.gates.find((g) => g.name === "skills.social_omitted_allowlist_denies_all")?.status,
		).toBe("fail");
	});

	it("fails when a non-allowlisted skill is not denied", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, nonallowlisted_skill_denied: false },
		});
		expect(report.gates.find((g) => g.name === "skills.nonallowlisted_skill_denied")?.status).toBe(
			"fail",
		);
	});

	it("rejects a self-reported property bit with no passing backing check", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			checks: ev.checks.filter((c) => c.name !== "nonallowlisted_skill_denied"),
		});
		const gate = report.gates.find((g) => g.name === "skills.nonallowlisted_skill_denied");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("lacks a passing backing check");
	});

	it("fails when status is pending or ran is false", () => {
		expect(evaluateSkillsAllowlistEvidence({ ...validEvidence(), status: "pending" }).status).toBe(
			"fail",
		);
		expect(evaluateSkillsAllowlistEvidence({ ...validEvidence(), ran: false }).status).toBe("fail");
	});
});
