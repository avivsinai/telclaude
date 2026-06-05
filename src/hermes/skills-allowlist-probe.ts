import type { ZodError } from "zod";
import { redactSecrets } from "../security/output-filter.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import { DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME } from "./served-mcp-containment.js";

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

// Properties that assert a DENIAL — these must be observed by the primary
// PreToolUse hook layer, not only the bypassable canUseTool fallback.
const SKILLS_DENIAL_PROPERTY_NAMES: ReadonlySet<string> = new Set([
	"nonallowlisted_skill_denied",
	"social_omitted_allowlist_denies_all",
	"social_empty_allowlist_denies_all",
]);

function inputError(detail: string): SkillsAllowlistReport {
	return {
		schemaVersion: SKILLS_ALLOWLIST_REPORT_SCHEMA_VERSION,
		status: "input_error",
		productionEnable: false,
		gates: [{ name: "skills.evidence", status: "fail", detail }],
	};
}

// Skill enforcement is the SDK PreToolUse hook inside the contained runtime, so
// origin is proven by docker internal-network topology + container identity
// (mirroring api-server-containment), NOT a network server-peer-echo header.
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
 * check of the same name whose every occurrence is "pass". The live producer drives
 * the real skill-invocation path in the contained runtime; this validates its
 * artifact.
 */
export function evaluateSkillsAllowlistEvidence(
	evidence: unknown,
	options: { missingPath?: string } = {},
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
	// Denial properties must be observed by the PRIMARY layer (PreToolUse hook, which
	// runs unconditionally) — a denial recorded only by the canUseTool fallback (which
	// is bypassed in acceptEdits mode) does not prove fail-closed enforcement.
	const primaryLayerProven = new Map<string, boolean>();
	for (const check of parsed.data.checks) {
		const prior = checkPass.get(check.name);
		const thisPass = check.status === "pass";
		checkPass.set(check.name, prior === undefined ? thisPass : prior && thisPass);
		if (
			thisPass &&
			(check.enforcementLayer === "pretooluse_hook" || check.enforcementLayer === "both")
		) {
			primaryLayerProven.set(check.name, true);
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
		const isDenial = SKILLS_DENIAL_PROPERTY_NAMES.has(property);
		const primaryOk = !isDenial || primaryLayerProven.get(property) === true;
		const proven = bit && backed && !leaked && primaryOk;
		gates.push({
			name: `skills.${property}`,
			status: proven ? "pass" : "fail",
			detail: leaked
				? "skills-allowlist evidence bytes contain credential-shaped text; artifact_redacted forced to fail"
				: !bit
					? `skills-allowlist property ${property} is ${parsed.data.properties[property] === undefined ? "missing" : "false"}`
					: !backed
						? `skills-allowlist property ${property} bit is set but lacks a passing backing check`
						: !primaryOk
							? `skills-allowlist denial property ${property} must be observed by the PreToolUse hook (primary layer), not only the canUseTool fallback`
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
// Skill-allowlist enforcement is the SDK PreToolUse hook in the contained
// runtime, so this is a RUNTIME probe (docker-exec / contained invocation),
// modeled on api-server-containment — NOT a network fetch probe. It launches the
// contained Hermes/private runtime profile with explicit allowedSkills, proves an
// allowlisted skill reaches the runtime, and proves non-allowlisted / SOCIAL
// fail-closed Skill calls are denied by the PreToolUse hook. Origin is proven by
// docker internal-network topology, not a server-peer-echo header. The CLI wires
// the real runner + topology observer; tests inject mocks.

export type SkillInvocationOutcome = {
	readonly allowed: boolean;
	/** Which enforcement layer observed the denial (PreToolUse hook is primary). */
	readonly enforcementLayer?: "pretooluse_hook" | "can_use_tool" | "both";
	readonly detail?: string;
};

export type SkillsAllowlistScenario = {
	readonly label: string;
	readonly tier: string;
	readonly enableSkills: boolean;
	readonly allowedSkills?: readonly string[];
	readonly skill: string;
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
		positive_allowlisted_skill_allowed: false,
		nonallowlisted_skill_denied: false,
		social_omitted_allowlist_denies_all: false,
		social_empty_allowlist_denies_all: false,
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

	// Positive: an allowlisted skill is invocable.
	const allowlisted = await options.runner({
		label: "allowlisted",
		tier: "WRITE_LOCAL",
		enableSkills: true,
		allowedSkills: ["telegram-reply"],
		skill: "telegram-reply",
	});
	checks.push({
		name: "positive_allowlisted_skill_allowed",
		status: allowlisted.allowed ? "pass" : "fail",
		detail: allowlisted.allowed
			? "allowlisted skill reached the runtime"
			: "allowlisted skill was not allowed",
	});

	// Denial controls — each must be denied by the PRIMARY PreToolUse hook layer.
	const denialScenarios: ReadonlyArray<
		readonly [SkillsAllowlistPropertyName, SkillsAllowlistScenario]
	> = [
		[
			"nonallowlisted_skill_denied",
			{
				label: "non-allowlisted",
				tier: "WRITE_LOCAL",
				enableSkills: true,
				allowedSkills: ["telegram-reply"],
				skill: "external-provider",
			},
		],
		[
			"social_omitted_allowlist_denies_all",
			{
				label: "SOCIAL omitted-allowlist",
				tier: "SOCIAL",
				enableSkills: true,
				allowedSkills: undefined,
				skill: "telegram-reply",
			},
		],
		[
			"social_empty_allowlist_denies_all",
			{
				label: "SOCIAL empty-allowlist",
				tier: "SOCIAL",
				enableSkills: true,
				allowedSkills: [],
				skill: "telegram-reply",
			},
		],
	];
	for (const [name, scenario] of denialScenarios) {
		const outcome = await options.runner(scenario);
		const deniedByHook =
			!outcome.allowed &&
			(outcome.enforcementLayer === "pretooluse_hook" || outcome.enforcementLayer === "both");
		checks.push({
			name,
			status: deniedByHook ? "pass" : "fail",
			detail: deniedByHook
				? `${scenario.label} Skill call denied by the PreToolUse hook`
				: `${scenario.label} Skill call was not denied by the primary hook`,
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

	const allPass = checks.every((check) => check.status === "pass");
	return {
		schemaVersion: "telclaude.hermes.skills-allowlist.v1",
		probeId: "skills.allowlist",
		status: allPass ? "pass" : "fail",
		ran: true,
		generatedAt,
		summary: allPass
			? "skills allowlist enforced fail-closed in the contained runtime"
			: "skills-allowlist probe recorded failing checks",
		origin,
		properties,
		checks,
	};
}
