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
		origin: {
			kind: "contained-peer",
			containerName: "tc-hermes-contained",
			observedPeerAddress: "172.30.92.11",
			observedPeerSource: "server-peer-echo",
			expectedPeerAddress: "172.30.92.11",
			expectedPeerSource: "configured-contained-ip",
			detail: "server-echoed contained peer",
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

	it("fails origin for relay-self-smoke evidence", () => {
		const ev = validEvidence();
		const report = evaluateSkillsAllowlistEvidence({
			...ev,
			origin: { ...ev.origin, kind: "relay-self-smoke" },
		});
		expect(report.status).toBe("fail");
		expect(report.gates.find((g) => g.name === "skills.origin")?.status).toBe("fail");
	});

	it("fails origin when the peer address is unknown or mismatched", () => {
		const ev = validEvidence();
		// unknown kind (no peer echo)
		expect(
			evaluateSkillsAllowlistEvidence({
				...ev,
				origin: { kind: "unknown", detail: "no peer echo" },
			}).gates.find((g) => g.name === "skills.origin")?.status,
		).toBe("fail");
		// contained-peer but observed != expected
		expect(
			evaluateSkillsAllowlistEvidence({
				...ev,
				origin: { ...ev.origin, observedPeerAddress: "172.30.92.99" },
			}).gates.find((g) => g.name === "skills.origin")?.status,
		).toBe("fail");
	});

	it("passes origin for a server-echoed contained peer", () => {
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
