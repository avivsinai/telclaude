import { spawnSync } from "node:child_process";
import { type ZodError, z } from "zod";
import { redactSecrets } from "../security/output-filter.js";
import {
	type HermesSignedEvidenceValidationOptions,
	hermesAllowsStaleAttestations,
	hermesAttestationFreshnessFailure,
	hermesRequiresRunnerAttestation,
} from "./attestation-validation.js";
import { type HermesArtifactWriteOptions, writeHermesJsonArtifact } from "./foundation.js";
import { DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME } from "./served-mcp-containment.js";
import {
	signSkillsAllowlistAttestation,
	skillsAllowlistAttestationFieldsForEvidence,
	skillsAllowlistAttestationSignatureFailure,
} from "./skills-allowlist-attestation.js";
import {
	catalogManifestDigestSha256,
	type HermesSkillCatalogKind,
	listCatalog,
	type RelaySkillCatalogState,
	resolveRelaySkillCatalogState,
} from "./skills-catalog.js";

export {
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	SKILLS_ALLOWLIST_SCHEMA_VERSION,
	SKILLS_CATALOG_REQUIRED_CHECK_NAMES,
	type SkillsAllowlistCheck,
	type SkillsAllowlistEvidence,
	SkillsAllowlistEvidenceSchema,
	type SkillsAllowlistPropertyName,
	type SkillsCatalogCheckName,
	type SkillsCatalogSection,
} from "./skills-allowlist-schema.js";

import {
	SKILLS_ALLOWLIST_REQUIRED_PROPERTY_NAMES,
	SKILLS_CATALOG_REQUIRED_CHECK_NAMES,
	type SkillsAllowlistEvidence,
	SkillsAllowlistEvidenceSchema,
	type SkillsAllowlistPropertyName,
	type SkillsCatalogCheckName,
	type SkillsCatalogSection,
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
		return hermesRequiresRunnerAttestation(options) ? "runnerAttestation is missing" : null;
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
	options: {
		missingPath?: string;
		/** Injected relay catalog state for tests; defaults to live resolution. */
		relayCatalog?: RelaySkillCatalogState;
		/** Injected social relay catalog state for tests; defaults to live resolution. */
		socialRelayCatalog?: RelaySkillCatalogState;
	} & HermesSignedEvidenceValidationOptions = {},
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

	appendCatalogGates(gates, {
		section: parsed.data.catalog,
		relayCatalog: options.relayCatalog ?? resolveRelaySkillCatalogState({ catalogKind: "private" }),
		gatePrefix: "skills.catalog",
		label: "catalog",
	});
	appendCatalogGates(gates, {
		section: parsed.data.socialCatalog,
		relayCatalog:
			options.socialRelayCatalog ?? resolveRelaySkillCatalogState({ catalogKind: "social" }),
		gatePrefix: "skills.socialCatalog",
		label: "social catalog",
	});

	const productionEnable = gates.every((gate) => gate.status === "pass");
	return {
		schemaVersion: SKILLS_ALLOWLIST_REPORT_SCHEMA_VERSION,
		status: productionEnable ? "pass" : "fail",
		productionEnable,
		gates,
	};
}

function appendCatalogGates(
	gates: SkillsAllowlistGate[],
	input: {
		readonly section: SkillsCatalogSection | undefined;
		readonly relayCatalog: RelaySkillCatalogState;
		readonly gatePrefix: "skills.catalog" | "skills.socialCatalog";
		readonly label: "catalog" | "social catalog";
	},
): void {
	// Relay-owned catalog containment proof. The deployment fact "does the relay
	// serve a skill catalog?" is resolved relay-side (the contained runtime cannot
	// vote), so a catalog-serving cutover cannot pass on catalog-free evidence.
	if (input.relayCatalog.configured) {
		if ("error" in input.relayCatalog) {
			gates.push({
				name: `${input.gatePrefix}.required`,
				status: "fail",
				detail: `relay ${input.label} manifest is unreadable: ${redactSecrets(input.relayCatalog.error)}`,
			});
		} else if (!input.section) {
			gates.push({
				name: `${input.gatePrefix}.required`,
				status: "fail",
				detail: `relay serves a ${input.label} (${input.relayCatalog.skillCount} skill(s)) but the evidence carries no ${input.label} section; re-run the skills.allowlist probe with catalog observation wired`,
			});
		} else if (input.section.manifestSha256 !== input.relayCatalog.manifestSha256) {
			gates.push({
				name: `${input.gatePrefix}.required`,
				status: "fail",
				detail: `${input.label} evidence manifestSha256 does not match the live relay ${input.label} manifest; the evidence is stale or was probed against a different manifest`,
			});
		} else {
			gates.push({
				name: `${input.gatePrefix}.required`,
				status: "pass",
				detail: `${input.label} evidence is bound to the live relay manifest (${input.relayCatalog.skillCount} skill(s))`,
			});
		}
	}

	// Catalog section gates: every required catalog check must exist and pass;
	// the schema already pins docker_exec observation.
	if (!input.section) return;
	const catalogPass = new Map<SkillsCatalogCheckName, boolean>();
	for (const check of input.section.checks) {
		const prior = catalogPass.get(check.name);
		const thisPass = check.status === "pass";
		catalogPass.set(check.name, prior === undefined ? thisPass : prior && thisPass);
	}
	for (const name of SKILLS_CATALOG_REQUIRED_CHECK_NAMES) {
		const backed = catalogPass.get(name);
		gates.push({
			name: `${input.gatePrefix}.${name}`,
			status: backed === true ? "pass" : "fail",
			detail:
				backed === true
					? `${input.label} check ${name} is proven against the container-visible mount`
					: backed === false
						? `${input.label} check ${name} failed`
						: `${input.label} section is present but check ${name} is missing`,
		});
	}
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
	/** Enforcement checks must prove the primary PreToolUse gate, not a fallback. */
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

export type SkillsCatalogManifestDigestEntry = {
	readonly name: string;
	readonly sha256: string;
};

export type SkillsCatalogObservedEntry = {
	readonly name: string;
	readonly sha256: string;
	readonly hasScriptsDir: boolean;
	readonly hasSymlink: boolean;
	readonly hasExecutable: boolean;
};

export type SkillsCatalogProbeInput = {
	readonly mountPath: string;
	/** Relay-side catalog manifest digests (names + canonical content hashes). */
	readonly manifest: ReadonlyArray<SkillsCatalogManifestDigestEntry>;
	/** Observe the container-visible catalog dir via docker exec inside the runtime. */
	readonly observe: () => Promise<ReadonlyArray<SkillsCatalogObservedEntry>>;
};

export type RunSkillsAllowlistProbeOptions = {
	readonly allowRun: boolean;
	readonly runner?: SkillsAllowlistRunner;
	readonly observeTopology?: () => Promise<SkillsTopologyObservation>;
	/**
	 * Relay-owned catalog proof (see buildRelaySkillsCatalogProbeInput). Omitting
	 * it while the relay serves a catalog fails the evidence closed: the final
	 * self-evaluation requires a catalog section bound to the live relay manifest.
	 */
	readonly catalog?: SkillsCatalogProbeInput;
	/** Social runtime catalog proof; required when the relay serves a social catalog. */
	readonly socialCatalog?: SkillsCatalogProbeInput;
	/** Injected relay catalog state for tests; defaults to live resolution. */
	readonly relayCatalog?: RelaySkillCatalogState;
	/** Injected social relay catalog state for tests; defaults to live resolution. */
	readonly socialRelayCatalog?: RelaySkillCatalogState;
	readonly now?: Date;
};

function falseSkillProperties(): SkillsAllowlistEvidence["properties"] {
	return {
		allowlist_manifest_present: false,
		allowlisted_skill_present: false,
		nonallowlisted_skill_absent: false,
		runtime_skills_match_allowlist: false,
		skill_creation_nudge_disabled: false,
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
			label: "skill creation nudge disabled",
			property: "skill_creation_nudge_disabled",
			allowlistedSkill: "software-development/plan",
			nonAllowlistedSkill: "red-teaming/godmode",
			kind: "profile",
		},
		{
			label: "PreToolUse hook registered",
			property: "pretooluse_hook_registered",
			allowlistedSkill: "plan",
			nonAllowlistedSkill: "godmode",
			kind: "pretooluse",
			expectedDecision: "allow",
			allowedSkills: ["plan"],
		},
		{
			label: "allowlisted Skill invocation",
			property: "allowlisted_skill_invocation_allowed",
			allowlistedSkill: "plan",
			nonAllowlistedSkill: "godmode",
			kind: "pretooluse",
			expectedDecision: "allow",
			allowedSkills: ["plan"],
		},
		{
			label: "non-allowlisted Skill invocation denied",
			property: "nonallowlisted_skill_invocation_denied",
			allowlistedSkill: "plan",
			nonAllowlistedSkill: "test-driven-development",
			kind: "pretooluse",
			expectedDecision: "deny",
			allowedSkills: ["plan"],
		},
		{
			label: "SOCIAL missing allowlist denied",
			property: "social_missing_allowlist_denied",
			allowlistedSkill: "plan",
			nonAllowlistedSkill: "godmode",
			kind: "pretooluse",
			expectedDecision: "deny",
			omitAllowedSkills: true,
		},
		{
			label: "SOCIAL empty allowlist denied",
			property: "social_empty_allowlist_denied",
			allowlistedSkill: "plan",
			nonAllowlistedSkill: "godmode",
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

	const catalog = options.catalog ? await observeCatalogSection(options.catalog) : undefined;
	const socialCatalog = options.socialCatalog
		? await observeCatalogSection(options.socialCatalog)
		: undefined;

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
		...(catalog ? { catalog } : {}),
		...(socialCatalog ? { socialCatalog } : {}),
	};
	const evaluated = evaluateSkillsAllowlistEvidence(draft, {
		allowStaleAttestations: true,
		now: options.now,
		relayCatalog: options.relayCatalog ?? resolveRelaySkillCatalogState({ catalogKind: "private" }),
		socialRelayCatalog:
			options.socialRelayCatalog ?? resolveRelaySkillCatalogState({ catalogKind: "social" }),
	});
	const allPass = evaluated.status === "pass" && evaluated.productionEnable;
	const failingGates = evaluated.gates
		.filter((gate) => gate.status === "fail")
		.map((gate) => gate.name);
	const finalEvidence: SkillsAllowlistEvidence = {
		...draft,
		status: allPass ? "pass" : "fail",
		summary: allPass
			? "skills allowlist profile proven in the contained runtime"
			: `skills-allowlist probe recorded failing gates: ${failingGates.join(", ") || evaluated.status}`,
	};
	// Sign the finalized evidence body with the operator relay key so the written
	// artifact carries provenance the cutover evaluator can verify. The relay signing
	// key is present in the real --allow-run (relay/operator) context.
	return {
		...finalEvidence,
		runnerAttestation: signSkillsAllowlistAttestation(finalEvidence),
	};
}

function catalogCheck(
	name: SkillsCatalogCheckName,
	violations: readonly string[],
	passDetail: string,
): SkillsCatalogSection["checks"][number] {
	return {
		name,
		status: violations.length === 0 ? "pass" : "fail",
		detail: violations.length === 0 ? passDetail : `${name} violated by: ${violations.join(", ")}`,
		observationLayer: "docker_exec",
	};
}

async function observeCatalogSection(
	input: SkillsCatalogProbeInput,
): Promise<SkillsCatalogSection> {
	const manifestSha256 = catalogManifestDigestSha256(input.manifest);
	let observed: ReadonlyArray<SkillsCatalogObservedEntry>;
	try {
		observed = await input.observe();
	} catch (error) {
		// Fail closed: an unobservable catalog proves nothing, so every required
		// check records a failure instead of the section silently disappearing.
		const detail = `catalog observation failed: ${redactSecrets(
			String(error instanceof Error ? error.message : error),
		)}`;
		return {
			mountPath: input.mountPath,
			manifestSkillCount: input.manifest.length,
			manifestSha256,
			checks: SKILLS_CATALOG_REQUIRED_CHECK_NAMES.map((name) => ({
				name,
				status: "fail",
				detail,
				observationLayer: "docker_exec",
			})),
		};
	}
	const observedByName = new Map(observed.map((entry) => [entry.name, entry]));

	const manifestMismatches: string[] = [];
	for (const entry of input.manifest) {
		const seen = observedByName.get(entry.name);
		if (!seen) {
			manifestMismatches.push(`${entry.name} (missing in container)`);
		} else if (seen.sha256 !== entry.sha256) {
			manifestMismatches.push(`${entry.name} (content hash mismatch)`);
		}
	}
	const manifestNames = new Set(input.manifest.map((entry) => entry.name));
	for (const entry of observed) {
		if (!manifestNames.has(entry.name)) {
			manifestMismatches.push(`${entry.name} (not in relay manifest)`);
		}
	}

	return {
		mountPath: input.mountPath,
		manifestSkillCount: input.manifest.length,
		manifestSha256,
		checks: [
			catalogCheck(
				"catalog_manifest_match",
				manifestMismatches,
				"container-visible catalog matches the relay manifest (names + content hashes)",
			),
			catalogCheck(
				"catalog_no_scripts",
				observed.filter((entry) => entry.hasScriptsDir).map((entry) => entry.name),
				"no catalog entry contains a scripts/ directory",
			),
			catalogCheck(
				"catalog_no_symlinks",
				observed.filter((entry) => entry.hasSymlink).map((entry) => entry.name),
				"no catalog entry contains a symlink",
			),
			catalogCheck(
				"catalog_no_executables",
				observed.filter((entry) => entry.hasExecutable).map((entry) => entry.name),
				"no catalog entry contains an executable file",
			),
		],
	};
}

// ---------------------------------------------------------------------------
// Live catalog probe input (relay manifest + docker-exec observer)
// ---------------------------------------------------------------------------

/** In-container catalog mount default; mirrors docker/hermes-contained-entrypoint.sh. */
export const DEFAULT_HERMES_SKILL_CATALOG_MOUNT = "/opt/data/telclaude-hermes-skill-catalog";
export const DEFAULT_HERMES_SOCIAL_SKILL_CATALOG_MOUNT =
	"/opt/data/telclaude-hermes-social-skill-catalog";

/**
 * Container-side catalog walk. Mirrors walkSkillDir/computeCatalogSkillSha256 in
 * skills-catalog.ts: per skill dir, sha256 over the rel-path-sorted listing of
 * `<rel>\0<sha256(bytes) hex>\n` for regular non-executable files, with
 * scripts/symlink/executable violations reported as flags instead of throwing.
 * Exported so tests can prove hash equivalence with the relay-side hasher by
 * running the script under a local node.
 */
export const SKILLS_CATALOG_OBSERVER_SCRIPT = `
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const mount = process.argv[1];
const skillsDir = path.join(mount, "skills");
const entries = [];
let dirents = [];
try {
  dirents = fs.readdirSync(skillsDir, { withFileTypes: true });
} catch {
  dirents = [];
}
for (const dirent of dirents) {
  if (dirent.name.startsWith(".")) continue;
  const dir = path.join(skillsDir, dirent.name);
  const top = fs.lstatSync(dir);
  if (top.isSymbolicLink() || !top.isDirectory()) {
    entries.push({
      name: dirent.name,
      sha256: "",
      hasScriptsDir: false,
      hasSymlink: top.isSymbolicLink(),
      hasExecutable: false,
    });
    continue;
  }
  let hasScriptsDir = false;
  let hasSymlink = false;
  let hasExecutable = false;
  const files = [];
  const visit = (current, relPrefix) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const abs = path.join(current, entry.name);
      const rel = relPrefix ? relPrefix + "/" + entry.name : entry.name;
      const stat = fs.lstatSync(abs);
      if (stat.isSymbolicLink()) { hasSymlink = true; continue; }
      if (stat.isDirectory()) {
        if (entry.name === "scripts") { hasScriptsDir = true; continue; }
        visit(abs, rel);
        continue;
      }
      if (!stat.isFile()) continue;
      if ((stat.mode & 0o111) !== 0) { hasExecutable = true; continue; }
      files.push({ rel, abs });
    }
  };
  visit(dir, "");
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  const hash = crypto.createHash("sha256");
  for (const file of files) {
    hash.update(file.rel);
    hash.update("\\0");
    hash.update(crypto.createHash("sha256").update(fs.readFileSync(file.abs)).digest("hex"));
    hash.update("\\n");
  }
  entries.push({
    name: dirent.name,
    sha256: hash.digest("hex"),
    hasScriptsDir,
    hasSymlink,
    hasExecutable,
  });
}
console.log(JSON.stringify(entries));
`;

const SkillsCatalogObservedEntrySchema = z
	.object({
		name: z.string().min(1),
		sha256: z.string(),
		hasScriptsDir: z.boolean(),
		hasSymlink: z.boolean(),
		hasExecutable: z.boolean(),
	})
	.strict();

export type BuildRelaySkillsCatalogProbeInputOptions = {
	readonly containerName: string;
	readonly dockerBin?: string;
	readonly mountPath?: string;
	readonly timeoutMs?: number;
	/** Override the relay catalog root (tests / non-default deployments). */
	readonly catalogRoot?: string;
	readonly catalogKind?: HermesSkillCatalogKind;
};

/**
 * Build the catalog probe input for the live skills.allowlist probe: the relay
 * manifest digests from listCatalog() plus a docker-exec observer of the
 * container-visible mount. Returns undefined when no relay catalog is
 * configured (catalog-free deployment); throws on an unreadable manifest so a
 * broken catalog cannot quietly produce catalog-free evidence.
 */
export function buildRelaySkillsCatalogProbeInput(
	options: BuildRelaySkillsCatalogProbeInputOptions,
): SkillsCatalogProbeInput | undefined {
	const catalogKind = options.catalogKind ?? "private";
	const catalogOptions = options.catalogRoot
		? { catalogRoot: options.catalogRoot }
		: { catalogKind };
	const state = resolveRelaySkillCatalogState(catalogOptions);
	if (!state.configured) return undefined;
	if ("error" in state) {
		throw new Error(`relay skill catalog manifest is unreadable: ${state.error}`);
	}
	const manifest = listCatalog(catalogOptions).map(({ name, sha256 }) => ({ name, sha256 }));
	const mountPath =
		options.mountPath?.trim() ||
		(catalogKind === "social"
			? process.env.TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_MOUNT?.trim()
			: process.env.TELCLAUDE_HERMES_SKILL_CATALOG_MOUNT?.trim()) ||
		(catalogKind === "social"
			? DEFAULT_HERMES_SOCIAL_SKILL_CATALOG_MOUNT
			: DEFAULT_HERMES_SKILL_CATALOG_MOUNT);
	const dockerBin = options.dockerBin?.trim() || process.env.DOCKER_BIN?.trim() || "docker";
	const containerName = options.containerName.trim() || DEFAULT_SERVED_MCP_CONTAINED_CONTAINER_NAME;
	return {
		mountPath,
		manifest,
		observe: async () => {
			const result = spawnSync(
				dockerBin,
				[
					"exec",
					containerName,
					"node",
					"--input-type=module",
					"-e",
					SKILLS_CATALOG_OBSERVER_SCRIPT,
					mountPath,
				],
				{
					encoding: "utf8",
					env: { PATH: process.env.PATH ?? "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" },
					timeout: options.timeoutMs,
				},
			);
			if (result.status !== 0 || result.error) {
				throw new Error(
					redactSecrets(
						result.stderr?.trim() ||
							result.error?.message ||
							"docker exec catalog observation failed",
					),
				);
			}
			const parsed = z
				.array(SkillsCatalogObservedEntrySchema)
				.safeParse(JSON.parse(result.stdout?.trim() || "[]"));
			if (!parsed.success) {
				throw new Error(
					`catalog observer returned malformed entries: ${flattenZodError(parsed.error)}`,
				);
			}
			return parsed.data;
		},
	};
}
