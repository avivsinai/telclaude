import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
};
let relayPublicKey = "";

beforeEach(() => {
	const keys = generateKeyPair();
	process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = keys.privateKey;
	process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = keys.publicKey;
	relayPublicKey = keys.publicKey;
});
afterEach(() => {
	if (savedRelay.private === undefined) delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
	else process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY = savedRelay.private;
	if (savedRelay.public === undefined) delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
	else process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY = savedRelay.public;
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
});
