import type { ZodError } from "zod";
import { redactSecrets } from "../security/output-filter.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
} from "./attestation-validation.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import { DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME } from "./served-mcp-containment.js";
import {
	signSkillsAllowlistAttestation,
	skillsAllowlistAttestationFieldsForEvidence,
	skillsAllowlistAttestationSignatureFailure,
} from "./skills-allowlist-attestation.js";

export {
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	SKILLS_ALLOWLIST_SCHEMA_VERSION,
	type SkillsAllowlistCheck,
	type SkillsAllowlistEvidence,
	SkillsAllowlistEvidenceSchema,
	type SkillsAllowlistPropertyName,
} from "./skills-allowlist-schema.js";

import {
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	type SkillsAllowlistEvidence,
	SkillsAllowlistEvidenceSchema,
	type SkillsAllowlistPropertyName,
} from "./skills-allowlist-schema.js";

export const DEFAULT_SKILLS_ALLOWLIST_EVIDENCE_PATH =
	"artifacts/hermes/probes/skills-allowlist.json";

export const SKILLS_ALLOWLIST_REPORT_SCHEMA_VERSION = "telclaude.hermes.skills-allowlist-report.v1";

const SKILLS_ALLOWLIST_PRETOOLUSE_PROPERTY_NAMES = new Set<SkillsAllowlistPropertyName>([
	"pretooluse_hook_registered",
	"allowlisted_skill_invocation_allowed",
	"nonallowlisted_skill_invocation_denied",
	"social_missing_allowlist_denied",
	"social_empty_allowlist_denied",
]);

export type SkillsAllowlistGate = {
	readonly name: string;
	readonly status: "pass" | "fail";
	readonly detail: string;
};

export type SkillsAllowlistReport = {
	readonly schemaVersion: typeof SKILLS_ALLOWLIST_REPORT_SCHEMA_VERSION;
	readonly status: "pass" | "fail" | "input_error";
	readonly productionEnable: boolean;
	readonly gates: SkillsAllowlistGate[];
};

function inputError(detail: string): SkillsAllowlistReport {
	return {
		schemaVersion: SKILLS_ALLOWLIST_REPORT_SCHEMA_VERSION,
		status: "input_error",
		productionEnable: false,
		gates: [{ name: "skills.evidence", status: "fail", detail }],
	};
}

// The skills proof is produced inside the contained Hermes runtime, so origin is
// proven by docker internal-network topology + container identity (mirroring
// api-server-containment), NOT a network server-peer-echo header.
function originGate(origin: SkillsAllowlistEvidence["origin"]): SkillsAllowlistGate {
	if (
		origin.kind === "contained-runtime" &&
		origin.containerName === DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME &&
		origin.topologyInternal === true &&
		origin.relayContainerPresent === true &&
		origin.authoritativeBoundary === "docker_internal_network"
	) {
		return {
			name: "skills.origin",
			status: "pass",
			detail:
				"skills-allowlist evidence proven from tc-hermes-contained on the docker internal network",
		};
	}
	return {
		name: "skills.origin",
		status: "fail",
		detail:
			"skills-allowlist evidence must prove contained-runtime origin (docker internal-network topology + tc-hermes-contained container identity)",
	};
}

/**
 * Deterministic evaluator the cutover-check consumes. As with the memory probe, a
 * property is proven only when its boolean bit is true AND backed by at least one
 * check of the same name whose every occurrence is "pass". Runtime/profile checks
 * must also be observed through docker exec inside the contained Hermes runtime.
 */
// Signed runner attestation provenance gate: binds this evidence body to an Ed25519
// signature from the operator relay key (which contained agents never hold). Under a
// live cutover (allowStaleAttestations === false) it is REQUIRED; otherwise skipped
// if absent but still verified if present so a tampered attestation cannot slip.
function skillsAllowlistRunnerAttestationFailure(
	data: SkillsAllowlistEvidence,
	options: HermesSignedEvidenceValidationOptions,
): string | null {
	const attestation = data.runnerAttestation;
	if (!attestation) {
		return hermesAllowsStaleAttestations(options) ? null : "runnerAttestation is missing";
	}
	const signatureFailure = skillsAllowlistAttestationSignatureFailure(attestation, {
		allowStale: hermesAllowsStaleAttestations(options),
		relayPublicKey: options.relayPublicKey,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = skillsAllowlistAttestationFieldsForEvidence(data);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"generatedAt",
		"originSha256",
		"propertiesSha256",
		"checksSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) {
			return `runnerAttestation ${field} mismatch`;
		}
	}
	return null;
}

export function evaluateSkillsAllowlistEvidence(
	evidence: unknown,
	options: { missingPath?: string } & HermesSignedEvidenceValidationOptions = {},
): SkillsAllowlistReport {
	if (evidence === undefined) {
		return inputError(
			`required skills-allowlist evidence is missing: ${options.missingPath ?? DEFAULT_SKILLS_ALLOWLIST_EVIDENCE_PATH}`,
		);
	}
	const parsed = SkillsAllowlistEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return inputError(flattenZodError(parsed.error));
	}

	const gates: SkillsAllowlistGate[] = [];
	gates.push(originGate(parsed.data.origin));
	const freshnessFailure = hermesAttestationFreshnessFailure(
		"skills-allowlist generatedAt",
		parsed.data.generatedAt,
		options,
	);
	if (freshnessFailure) {
		gates.push({
			name: "skills.freshness",
			status: "fail",
			detail: freshnessFailure,
		});
	}
	const attestationFailure = skillsAllowlistRunnerAttestationFailure(parsed.data, options);
	if (attestationFailure) {
		gates.push({
			name: "skills.attestation",
			status: "fail",
			detail: attestationFailure,
		});
	}

	if (parsed.data.status !== "pass") {
		gates.push({
			name: "skills.status",
			status: "fail",
			detail: `skills-allowlist evidence status is ${parsed.data.status}`,
		});
	}
	if (parsed.data.ran !== true) {
		gates.push({
			name: "skills.ran",
			status: "fail",
			detail: `skills-allowlist evidence ran is ${String(parsed.data.ran)}`,
		});
	}

	const checkPass = new Map<string, boolean>();
	const dockerExecEvidence = new Map<string, boolean>();
	const preToolUseEvidence = new Map<string, boolean>();
	for (const check of parsed.data.checks) {
		const prior = checkPass.get(check.name);
		const thisPass = check.status === "pass";
		checkPass.set(check.name, prior === undefined ? thisPass : prior && thisPass);
		if (thisPass && check.observationLayer === "docker_exec") {
			dockerExecEvidence.set(check.name, true);
		}
		if (thisPass && check.enforcementLayer === "pretooluse") {
			preToolUseEvidence.set(check.name, true);
		}
	}

	// artifact_redacted is not trusted as a self-reported bit: independently scan the
	// evidence bytes and force the gate to fail on any credential-shaped match.
	const serialized = JSON.stringify(parsed.data);
	const redactionLeak = redactSecrets(serialized) !== serialized;

	for (const property of SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES) {
		const bit = parsed.data.properties[property] === true;
		const backed = checkPass.get(property) === true;
		const leaked = property === "artifact_redacted" && redactionLeak;
		const dockerExecOk =
			property === "artifact_redacted" || dockerExecEvidence.get(property) === true;
		const preToolUseOk =
			!SKILLS_ALLOWLIST_PRETOOLUSE_PROPERTY_NAMES.has(property) ||
			preToolUseEvidence.get(property) === true;
		const proven = bit && backed && !leaked && dockerExecOk && preToolUseOk;
		gates.push({
			name: `skills.${property}`,
			status: proven ? "pass" : "fail",
			detail: leaked
				? "skills-allowlist evidence bytes contain credential-shaped text; artifact_redacted forced to fail"
				: !bit
					? `skills-allowlist property ${property} is ${parsed.data.properties[property] === undefined ? "missing" : "false"}`
					: !backed
						? `skills-allowlist property ${property} bit is set but lacks a passing backing check`
						: !dockerExecOk
							? `skills-allowlist property ${property} must be observed through docker exec inside the contained runtime`
							: !preToolUseOk
								? `skills-allowlist property ${property} must be enforced by the PreToolUse hook`
								: `skills-allowlist property ${property} is proven and check-backed`,
		});
	}

	const productionEnable = gates.every((gate) => gate.status === "pass");
	return {
		schemaVersion: SKILLS_ALLOWLIST_REPORT_SCHEMA_VERSION,
		status: productionEnable ? "pass" : "fail",
		productionEnable,
		gates,
	};
}

export function writeSkillsAllowlistEvidence(
	evidence: SkillsAllowlistEvidence,
	filePath: string,
	options: HermesArtifactWriteOptions = {},
): void {
	writeHermesJsonArtifact(filePath, evidence, options);
}

function flattenZodError(error: ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}

// ---------------------------------------------------------------------------
// Live producer (runtime/exec)
// ---------------------------------------------------------------------------
// The skills allowlist proof is a RUNTIME profile probe (docker-exec /
// contained invocation), modeled on api-server-containment — NOT a network fetch
// probe and NOT a host SDK-hook simulation. It proves the copied allowlist
// manifest, curated runtime skills tree, and negative absence of a known
// non-allowlisted skill inside HERMES_HOME. Origin is proven by docker
// internal-network topology, not a server-peer-echo header. The CLI wires the
// real runner + topology observer; tests inject mocks.

export type SkillInvocationOutcome = {
	readonly passed: boolean;
	/** Runtime/profile checks must be observed through docker exec. */
	readonly observationLayer?: "docker_exec";
	/** Enforcement checks must prove the primary SDK hook, not canUseTool fallback. */
	readonly enforcementLayer?: "pretooluse";
	readonly detail?: string;
};

export type SkillsAllowlistScenario = {
	readonly label: string;
	readonly property: Exclude<SkillsAllowlistPropertyName, "artifact_redacted">;
	readonly allowlistedSkill: string;
	readonly nonAllowlistedSkill: string;
	readonly kind: "profile" | "pretooluse";
	readonly expectedDecision?: "allow" | "deny";
	readonly omitAllowedSkills?: boolean;
	readonly allowedSkills?: readonly string[];
};

export type SkillsAllowlistRunner = (
	scenario: SkillsAllowlistScenario,
) => Promise<SkillInvocationOutcome>;

export type SkillsTopologyObservation = {
	readonly containerName: string;
	readonly topologyInternal: boolean;
	readonly relayContainerPresent: boolean;
};

export type RunSkillsAllowlistProbeOptions = {
	readonly allowRun: boolean;
	readonly runner?: SkillsAllowlistRunner;
	readonly observeTopology?: () => Promise<SkillsTopologyObservation>;
	readonly now?: Date;
};

function falseSkillProperties(): SkillsAllowlistEvidence["properties"] {
	return {
		allowlist_manifest_present: false,
		allowlisted_skill_present: false,
		nonallowlisted_skill_absent: false,
		runtime_skills_match_allowlist: false,
		pretooluse_hook_registered: false,
		allowlisted_skill_invocation_allowed: false,
		nonallowlisted_skill_invocation_denied: false,
		social_missing_allowlist_denied: false,
		social_empty_allowlist_denied: false,
		artifact_redacted: false,
	};
}

/**
 * Live producer: returns evidence shaped to satisfy evaluateSkillsAllowlistEvidence.
 * Without --allow-run (or a runner/topology observer) it returns a fail-closed
 * pending artifact.
 */
export async function runSkillsAllowlistProbe(
	options: RunSkillsAllowlistProbeOptions,
): Promise<SkillsAllowlistEvidence> {
	const generatedAt = (options.now ?? new Date()).toISOString();

	if (!options.allowRun || !options.runner || !options.observeTopology) {
		return {
			schemaVersion: "telclaude.hermes.skills-allowlist.v1",
			probeId: "skills.allowlist",
			status: "pending",
			ran: false,
			generatedAt,
			summary: options.allowRun
				? "skills-allowlist probe requires a runner + topology observer"
				: "skills-allowlist probe requires --allow-run",
			origin: { kind: "unknown", detail: "probe did not run" },
			properties: falseSkillProperties(),
			checks: [],
		};
	}

	const topo = await options.observeTopology();
	const origin: SkillsAllowlistEvidence["origin"] =
		topo.topologyInternal && topo.relayContainerPresent
			? {
					kind: "contained-runtime",
					containerName: topo.containerName,
					topologyInternal: true,
					relayContainerPresent: true,
					authoritativeBoundary: "docker_internal_network",
					detail: "docker internal-network topology proof",
				}
			: { kind: "unknown", detail: "contained-runtime topology not proven" };

	const checks: SkillsAllowlistEvidence["checks"] = [];
	const scenarios: ReadonlyArray<SkillsAllowlistScenario> = [
		{
			label: "allowlist manifest",
			property: "allowlist_manifest_present",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "profile",
		},
		{
			label: "allowlisted runtime skill",
			property: "allowlisted_skill_present",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "profile",
		},
		{
			label: "non-allowlisted runtime skill",
			property: "nonallowlisted_skill_absent",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "profile",
		},
		{
			label: "runtime skills match manifest",
			property: "runtime_skills_match_allowlist",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "profile",
		},
		{
			label: "PreToolUse hook registered",
			property: "pretooluse_hook_registered",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "pretooluse",
			expectedDecision: "allow",
			allowedSkills: ["software-development/plan"],
		},
		{
			label: "allowlisted Skill invocation",
			property: "allowlisted_skill_invocation_allowed",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "pretooluse",
			expectedDecision: "allow",
			allowedSkills: ["software-development/plan"],
		},
		{
			label: "non-allowlisted Skill invocation denied",
			property: "nonallowlisted_skill_invocation_denied",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "pretooluse",
			expectedDecision: "deny",
			allowedSkills: ["software-development/plan"],
		},
		{
			label: "SOCIAL missing allowlist denied",
			property: "social_missing_allowlist_denied",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "pretooluse",
			expectedDecision: "deny",
			omitAllowedSkills: true,
		},
		{
			label: "SOCIAL empty allowlist denied",
			property: "social_empty_allowlist_denied",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "pretooluse",
			expectedDecision: "deny",
			allowedSkills: [],
		},
	];
	for (const scenario of scenarios) {
		const outcome = await options.runner(scenario);
		checks.push({
			name: scenario.property,
			status: outcome.passed ? "pass" : "fail",
			detail:
				outcome.detail ??
				(outcome.passed
					? `${scenario.label} proven inside contained runtime`
					: `${scenario.label} was not proven inside contained runtime`),
			...(outcome.observationLayer ? { observationLayer: outcome.observationLayer } : {}),
			...(outcome.enforcementLayer ? { enforcementLayer: outcome.enforcementLayer } : {}),
		});
	}

	const properties = falseSkillProperties();
	for (const check of checks) {
		properties[check.name] = check.status === "pass";
	}
	properties.artifact_redacted = true;
	checks.push({
		name: "artifact_redacted",
		status: "pass",
		detail: "producer redacted observed detail; evaluator re-scans the artifact bytes",
	});

	const draft: SkillsAllowlistEvidence = {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: "pass",
		ran: true,
		generatedAt,
		summary: "skills allowlist profile proven in the contained runtime",
		origin,
		properties,
		checks,
	};
	const evaluated = evaluateSkillsAllowlistEvidence(draft, {
		allowStaleAttestations: true,
		now: options.now,
	});
	const allPass = evaluated.status === "pass" && evaluated.productionEnable;
	const finalEvidence: SkillsAllowlistEvidence = {
		...draft,
		status: allPass ? "pass" : "fail",
		summary: allPass
			? "skills allowlist profile proven in the contained runtime"
			: "skills-allowlist probe recorded failing checks",
	};
	// Sign the finalized evidence body with the operator relay key so the written
	// artifact carries provenance the cutover evaluator can verify. The relay signing
	// key is present in the real --allow-run (relay/operator) context.
	return {
		...finalEvidence,
		runnerAttestation: signSkillsAllowlistAttestation(finalEvidence),
	};
}
