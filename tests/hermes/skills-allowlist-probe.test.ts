import { describe, expect, it } from "vitest";
import {
	evaluateSkillsAllowlistEvidence,
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	type SkillsAllowlistPropertyName,
	type SkillsAllowlistEvidence,
} from "../../src/hermes/skills-allowlist-probe.js";

const PRETOOLUSE_PROPERTIES = new Set<SkillsAllowlistPropertyName>([
	"pretooluse_hook_registered",
	"allowlisted_skill_invocation_allowed",
	"nonallowlisted_skill_invocation_denied",
	"social_missing_allowlist_denied",
	"social_empty_allowlist_denied",
]);

function validEvidence(): SkillsAllowlistEvidence {
	const properties = Object.fromEntries(
		SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => [name, true]),
	) as SkillsAllowlistEvidence["properties"];
	const checks = SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES.map((name) => ({
		name,
		status: "pass" as const,
		detail: `${name} proven`,
		...(name === "artifact_redacted" ? {} : { observationLayer: "docker_exec" as const }),
		...(PRETOOLUSE_PROPERTIES.has(name) ? { enforcementLayer: "pretooluse" as const } : {}),
	}));
	return {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: "pass",
		ran: true,
		generatedAt: "2026-06-05T20:00:00.000Z",
		summary: "skills allowlist profile proven in contained runtime",
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

	it("fails when the allowlist manifest is not proven", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, allowlist_manifest_present: false },
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.allowlist_manifest_present")?.status).toBe(
			"fail",
		);
	});

	it("fails when a non-allowlisted skill is not absent", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, nonallowlisted_skill_absent: false },
		});
		expect(report.gates.find((g) => g.name === "skills.nonallowlisted_skill_absent")?.status).toBe(
			"fail",
		);
	});

	it("rejects a self-reported property bit with no passing backing check", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			checks: ev.checks.filter((c) => c.name !== "nonallowlisted_skill_absent"),
		});
		const gate = report.gates.find((g) => g.name === "skills.nonallowlisted_skill_absent");
		expect(gate?.status).toBe("fail");
		expect(gate?.detail).toContain("lacks a passing backing check");
	});

	it("fails when runtime skills are not proven to match the allowlist", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, runtime_skills_match_allowlist: false },
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.runtime_skills_match_allowlist")?.status).toBe(
			"fail",
		);
	});

	it("fails when runtime skill creation nudges are not proven disabled", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			properties: { ...ev.properties, skill_creation_nudge_disabled: false },
		});
		expect(report.status).toBe("fail");
		expect(
			report.gates.find((g) => g.name === "skills.skill_creation_nudge_disabled")?.status,
		).toBe("fail");
	});

	it("fails a runtime property not observed through docker exec", () => {
		const ev = validEvidence();
		const localOnly = evaluateSkillsAllowlistEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "nonallowlisted_skill_absent"
					? { name: c.name, status: c.status, detail: c.detail }
					: c,
			),
		});
		expect(localOnly.status).toBe("fail");
		expect(
			localOnly.gates.find((g) => g.name === "skills.nonallowlisted_skill_absent")?.detail,
		).toContain("docker exec");
	});

	it("fails a hook enforcement property not proven by PreToolUse", () => {
		const ev = validEvidence();
		const fallbackOnly = evaluateSkillsAllowlistEvidence({
			...ev,
			checks: ev.checks.map((c) =>
				c.name === "nonallowlisted_skill_invocation_denied"
					? {
							name: c.name,
							status: c.status,
							detail: "denied by fallback only",
							observationLayer: "docker_exec" as const,
						}
					: c,
			),
		});
		expect(fallbackOnly.status).toBe("fail");
		expect(
			fallbackOnly.gates.find(
				(g) => g.name === "skills.nonallowlisted_skill_invocation_denied",
			)?.detail,
		).toContain("PreToolUse");
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

	it("rejects stale generatedAt when strict validation disallows stale attestations", () => {
		const report = evaluateSkillsAllowlistEvidence(validEvidence(), {
			allowStaleAttestations: false,
			now: new Date("2026-06-20T00:00:00.000Z"),
		});
		expect(report.gates.find((g) => g.name === "skills.freshness")?.status).toBe("fail");
	});
});
