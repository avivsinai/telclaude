import net from "node:net";
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

function originGate(origin: SkillsAllowlistEvidence["origin"]): SkillsAllowlistGate {
	if (origin.kind === "relay-self-smoke") {
		return {
			name: "skills.origin",
			status: "fail",
			detail:
				"skills-allowlist evidence originated from relay-self smoke and is not production evidence",
		};
	}
	const matchesPeer =
		origin.observedPeerAddress !== undefined &&
		origin.expectedPeerAddress !== undefined &&
		origin.observedPeerSource === "server-peer-echo" &&
		origin.expectedPeerSource === "configured-contained-ip" &&
		net.isIP(origin.observedPeerAddress) !== 0 &&
		net.isIP(origin.expectedPeerAddress) !== 0 &&
		origin.observedPeerAddress === origin.expectedPeerAddress;
	if (
		origin.kind === "contained-peer" &&
		origin.containerName === DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME &&
		matchesPeer
	) {
		return {
			name: "skills.origin",
			status: "pass",
			detail:
				"skills-allowlist evidence originated from tc-hermes-contained at the expected peer address",
		};
	}
	return {
		name: "skills.origin",
		status: "fail",
		detail:
			"skills-allowlist evidence must include a server-observed contained peer IP from tc-hermes-contained matching the configured contained IP",
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
