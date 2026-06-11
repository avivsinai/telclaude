import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { signSkillsAllowlistAttestation } from "../../src/hermes/skills-allowlist-attestation.js";
import {
	evaluateSkillsAllowlistEvidence,
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	type SkillsAllowlistEvidence,
	type SkillsAllowlistPropertyName,
} from "../../src/hermes/skills-allowlist-probe.js";
import { generateKeyPair } from "../../src/internal-auth.js";

// Pro P1#2 for skills.allowlist: under a live cutover the evaluator only grants
// productionEnable when the evidence carries a valid Ed25519 attestation signed by
// the operator relay key. Unsigned / hand-edited / attacker-signed artifacts fail.

const PRETOOLUSE_PROPERTIES = new Set<SkillsAllowlistPropertyName>([
	"pretooluse_hook_registered",
	"allowlisted_skill_invocation_allowed",
	"nonallowlisted_skill_invocation_denied",
	"social_missing_allowlist_denied",
	"social_empty_allowlist_denied",
]);

const savedRelay = {
	private: process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY,
	public: process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY,
	catalogDir: process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR,
};
let relayPublicKey = "";

beforeEach(() => {
	const keys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	relayPublicKey = keys.publicKey;
	// Nonexistent catalog root: a real catalog on the dev machine must not leak a
	// skills.catalog.required gate into these catalog-free tests.
	process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = path.join(
		os.tmpdir(),
		`telclaude-no-catalog-${process.pid}`,
	);
});
afterEach(() => {
	if (savedRelay.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelay.private;
	if (savedRelay.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelay.public;
	if (savedRelay.catalogDir === undefined) delete process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR;
	else process.env.TELCLAUDE_HERMES_SKILL_CATALOG_DIR = savedRelay.catalogDir;
});

function unsignedEvidence(): SkillsAllowlistEvidence {
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
		generatedAt: new Date().toISOString(),
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

function signedEvidence(): SkillsAllowlistEvidence {
	const evidence = unsignedEvidence();
	return { ...evidence, runnerAttestation: signSkillsAllowlistAttestation(evidence) };
}

const liveOptions = () => ({ allowStaleAttestations: false, now: new Date(), relayPublicKey });

describe("skills-allowlist attestation gate (live cutover)", () => {
	it("grants productionEnable for valid signed evidence", () => {
		const report = evaluateSkillsAllowlistEvidence(signedEvidence(), liveOptions());
		expect(report.status).toBe("pass");
		expect(report.productionEnable).toBe(true);
		expect(report.gates.find((gate) => gate.name === "skills.attestation")).toBeUndefined();
	});

	it("rejects unsigned evidence (runnerAttestation missing)", () => {
		const report = evaluateSkillsAllowlistEvidence(unsignedEvidence(), liveOptions());
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "skills.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("runnerAttestation is missing"),
		});
	});

	it("rejects a hand-edited body whose signed digest no longer matches", () => {
		const tampered = { ...signedEvidence(), summary: "attacker-substituted summary" };
		const report = evaluateSkillsAllowlistEvidence(tampered, liveOptions());
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "skills.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("evidenceSha256 mismatch"),
		});
	});

	it("rejects an attestation signed by a non-relay (attacker) key", () => {
		const attacker = generateKeyPair();
		const report = evaluateSkillsAllowlistEvidence(signedEvidence(), {
			...liveOptions(),
			relayPublicKey: attacker.publicKey,
		});
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "skills.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("signature is invalid"),
		});
	});

	it("does not require an attestation when stale attestations are allowed (non-live)", () => {
		const report = evaluateSkillsAllowlistEvidence(unsignedEvidence(), {
			allowStaleAttestations: true,
			now: new Date(),
		});
		expect(report.gates.find((gate) => gate.name === "skills.attestation")).toBeUndefined();
	});

	it("accepts evidence signed within the evidence-freshness window (multi-step capture)", () => {
		// The evidence window (HERMES_EVIDENCE_PROOF_MAX_SKEW_MS, 60 min) is wider
		// than the RPC anti-replay skew (5 min): a capture step signed 30 minutes
		// before cutover-check must still verify under live validation.
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
			const evidence = signedEvidence();
			vi.setSystemTime(new Date("2000-01-01T00:30:00.000Z"));
			const report = evaluateSkillsAllowlistEvidence(evidence, liveOptions());
			expect(report.gates.find((gate) => gate.name === "skills.attestation")).toBeUndefined();
			expect(report.productionEnable).toBe(true);

			// Beyond the window it still fails closed.
			vi.setSystemTime(new Date("2000-01-01T01:00:01.000Z"));
			const stale = evaluateSkillsAllowlistEvidence(evidence, liveOptions());
			expect(stale.productionEnable).toBe(false);
			expect(stale.gates.find((gate) => gate.name === "skills.attestation")).toMatchObject({
				status: "fail",
				detail: expect.stringContaining("timestamp outside allowed skew"),
			});
		} finally {
			vi.useRealTimers();
		}
	});

	it("requires an attestation when strict archival validation asks for one", () => {
		const report = evaluateSkillsAllowlistEvidence(unsignedEvidence(), {
			allowStaleAttestations: true,
			requireRunnerAttestation: true,
			now: new Date(),
		});
		expect(report.productionEnable).toBe(false);
		expect(report.gates.find((gate) => gate.name === "skills.attestation")).toMatchObject({
			status: "fail",
			detail: expect.stringContaining("runnerAttestation is missing"),
		});
	});
});
