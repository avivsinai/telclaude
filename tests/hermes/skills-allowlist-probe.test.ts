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
	const denial = new Set([
		"nonallowlisted_skill_denied",
		"social_omitted_allowlist_denies_all",
		"social_empty_allowlist_denies_all",
	]);
	const checks = SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => ({
		name,
		status: "pass" as const,
		detail: `${name} proven`,
		...(denial.has(name) ? { enforcementLayer: "pretooluse_hook" as const } : {}),
	}));
	return {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: "pass",
		ran: true,
		generatedAt: "2026-06-05T20:00:00.000Z",
		summary: "skills allowlist enforced fail-closed in contained runtime",
		origin: {
			kind: "contained-runtime",
			containerName: "tc-hermes-contained",
			topologyInternal: true,
			relayContainerPresent: true,
			authoritativeBoundary: "docker_internal_network",
			detail: "docker internal-network topology proof",
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

	it("fails origin for an unknown or incomplete docker-topology proof", () => {
		const ev = validEvidence();
		// unknown kind
		expect(
			evaluateSkillsAllowlistEvidence({
				...ev,
				origin: { kind: "unknown", detail: "no topology proof" },
			}).gates.find((g) => g.name === "skills.origin")?.status,
		).toBe("fail");
		// relay container not present on the internal network
		expect(
			evaluateSkillsAllowlistEvidence({
				...ev,
				origin: { ...ev.origin, relayContainerPresent: false },
			}).gates.find((g) => g.name === "skills.origin")?.status,
		).toBe("fail");
		// wrong container identity
		expect(
			evaluateSkillsAllowlistEvidence({
				...ev,
				origin: { ...ev.origin, containerName: "not-contained" },
			}).gates.find((g) => g.name === "skills.origin")?.status,
		).toBe("fail");
	});

	it("passes origin for a contained-runtime docker-topology proof", () => {
		const report = evaluateSkillsAllowlistEvidence(validEvidence());
		expect(report.gates.find((g) => g.name === "skills.origin")?.status).toBe("pass");
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

	it("fails when SOCIAL fail-closed (empty allowlist denies all) is not proven", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, social_empty_allowlist_denies_all: false },
		});
		expect(report.status).toBe("fail");
		expect(
			report.gates.find((g) => g.name === "skills.social_empty_allowlist_denies_all")?.status,
		).toBe("fail");
	});

	it("fails a denial property observed only by the canUseTool fallback (not the primary hook)", () => {
		const ev = validEvidence();
		// nonallowlisted_skill_denied recorded only via the bypassable fallback
		const fallbackOnly = evaluateSkillsAllowlistEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "nonallowlisted_skill_denied"
					? { ...c, enforcementLayer: "can_use_tool" as const }
					: c,
			),
		});
		expect(fallbackOnly.status).toBe("fail");
		expect(
			fallbackOnly.gates.find((g) => g.name === "skills.nonallowlisted_skill_denied")?.detail,
		).toContain("PreToolUse hook");
		// and when enforcementLayer is absent entirely
		const absent = evaluateSkillsAllowlistEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "nonallowlisted_skill_denied"
					? { name: c.name, status: c.status, detail: c.detail }
					: c,
			),
		});
		expect(absent.gates.find((g) => g.name === "skills.nonallowlisted_skill_denied")?.status).toBe(
			"fail",
		);
	});

	it("forces artifact_redacted to fail when evidence bytes contain a secret (not self-attested)", () => {
		const report = evaluateSkillsAllowlistEvidence({
			...validEvidence(),
			summary: "leak AKIAIOSFODNN7EXAMPLE embedded in summary",
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.artifact_redacted")?.status).toBe("fail");
	});

	it("fails when status is pending or ran is false", () => {
		expect(evaluateSkillsAllowlistEvidence({ ...validEvidence(), status: "pending" }).status).toBe(
			"fail",
		);
		expect(evaluateSkillsAllowlistEvidence({ ...validEvidence(), ran: false }).status).toBe("fail");
	});
});
