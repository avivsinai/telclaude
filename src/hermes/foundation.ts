import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

export const DEFAULT_FEATURE_PROBE_MATRIX_PATH = "docs/hermes/feature-probes.json";
export const DEFAULT_COMPAT_LOCKFILE_PATH = "docs/hermes/hermes-compat.lock.json";
export const DEFAULT_CUTOVER_SCOPE_PATH = "docs/hermes/cutover-scope.json";
export const DEFAULT_DECISION_LOG_PATH = "docs/hermes/decisions.json";
export const DEFAULT_FIXTURE_RESULTS_PATH = "docs/hermes/fixture-results.json";
export const DEFAULT_NETWORK_PROBES_PATH = "docs/hermes/network-probes.json";
export const DEFAULT_NO_FORK_PROOF_PATH = "docs/hermes/no-fork-proof.json";
export const DEFAULT_ROLLBACK_REHEARSAL_PATH = "docs/hermes/rollback-rehearsal.json";
export const REQUIRED_CUTOVER_NETWORK_PROBE_IDS = [
	"network.direct-provider-denied",
	"network.direct-vault-denied",
	"network.direct-model-provider-denied",
	"network.dns-exfil-denied",
] as const;

const NonEmptyString = z.string().trim().min(1);

export const HermesPinSchema = z
	.object({
		version: NonEmptyString.optional(),
		commit: NonEmptyString.optional(),
		package: NonEmptyString.optional(),
		imageDigest: NonEmptyString.optional(),
	})
	.strict()
	.refine((pin) => Object.values(pin).some((value) => value !== undefined), {
		message: "at least one Hermes pin field is required",
	});

export type HermesPin = z.infer<typeof HermesPinSchema>;

export const FeatureProbeSchema = z
	.object({
		surface_id: NonEmptyString,
		hermes_pin: HermesPinSchema,
		documented_seam: NonEmptyString,
		probe_command: NonEmptyString,
		expected_result: NonEmptyString,
		negative_probe: NonEmptyString,
		evidence_path: NonEmptyString,
		lockfile_key: NonEmptyString,
		security_scope: z
			.enum([
				"headless-availability-only",
				"approval-continuation",
				"edge-adapter",
				"model-relay",
				"nofork-proof",
			])
			.optional(),
		approval_equivalent: z.boolean().optional(),
		failure_outcome: z.enum(["disable", "downgrade"]),
		status: z.enum(["pass", "fail", "skip"]).optional(),
	})
	.strict();

export const FeatureProbeMatrixSchema = z
	.object({
		schemaVersion: z.literal(1),
		probes: z.array(FeatureProbeSchema),
	})
	.strict();

export type FeatureProbeMatrix = z.infer<typeof FeatureProbeMatrixSchema>;

export const CompatibilityLockfileSchema = z
	.object({
		schemaVersion: z.literal(1),
		hermes: HermesPinSchema,
		featureProbeMatrixDigest: NonEmptyString,
		featureProbes: z.array(
			z
				.object({
					surface_id: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					evidence_path: NonEmptyString,
				})
				.strict(),
		),
		adapterApiSignatures: z.record(NonEmptyString, NonEmptyString),
		capabilities: z
			.object({
				plugins: z.array(NonEmptyString),
				mcp: z.array(NonEmptyString),
				modelProviders: z.array(NonEmptyString),
				memoryProviders: z.array(NonEmptyString),
			})
			.strict(),
		requiredUpgradeTests: z.array(NonEmptyString),
		generatedProfileSchemaVersion: NonEmptyString,
		wrapperPackageVersion: NonEmptyString,
		paritySuiteDigests: z.record(NonEmptyString, NonEmptyString),
		noForkProofEvidencePath: NonEmptyString,
		sourceDriftSignals: z
			.object({
				sourceCommit: NonEmptyString.optional(),
				docsCommit: NonEmptyString.optional(),
			})
			.strict(),
	})
	.strict();

export type CompatibilityLockfile = z.infer<typeof CompatibilityLockfileSchema>;

const WorkflowScopeSchema = z
	.object({
		workflow_id: NonEmptyString,
		owner: NonEmptyString,
		trust_domain: NonEmptyString,
		current_behavior: NonEmptyString,
		hermes_target_behavior: NonEmptyString,
		cutover_class: z.enum(["P0", "P1", "P2"]),
		cutover_requirement: NonEmptyString,
		status: z.enum(["included", "excluded", "disabled"]),
		rollback_owner: NonEmptyString.optional(),
		fixture_ids: z.array(NonEmptyString).default([]),
		negative_fixture_ids: z.array(NonEmptyString).default([]),
		required_surface_ids: z.array(NonEmptyString).default([]),
		unresolved_decision_ids: z.array(NonEmptyString).default([]),
	})
	.strict();

export const CutoverScopeManifestSchema = z
	.object({
		schemaVersion: z.literal(1),
		workflows: z.array(WorkflowScopeSchema),
	})
	.strict();

export type CutoverScopeManifest = z.infer<typeof CutoverScopeManifestSchema>;

const InventoryWorkflowSchema = z
	.object({
		workflow_id: NonEmptyString,
		owner: NonEmptyString,
		trust_domain: NonEmptyString,
		active: z.boolean(),
	})
	.passthrough();

const InventorySnapshotSchema = z
	.object({
		workflows: z.array(InventoryWorkflowSchema),
	})
	.catchall(z.unknown());

export const DecisionLogSchema = z
	.object({
		schemaVersion: z.literal(1),
		decisions: z.array(
			z
				.object({
					id: NonEmptyString,
					status: z.enum(["accepted", "unresolved", "downgrade_accepted"]),
					owner: NonEmptyString,
					deadline_phase: NonEmptyString,
					accepted_answer: NonEmptyString.optional(),
					affected_workflows: z.array(NonEmptyString).default([]),
					cutover_impact: NonEmptyString,
					downgrade_note: NonEmptyString.optional(),
				})
				.strict()
				.refine(
					(decision) => decision.status === "unresolved" || decision.accepted_answer !== undefined,
					{
						message: "accepted decisions require accepted_answer",
					},
				)
				.refine(
					(decision) =>
						decision.status !== "downgrade_accepted" || decision.downgrade_note !== undefined,
					{
						message: "downgrade decisions require downgrade_note",
					},
				),
		),
	})
	.strict();

export type DecisionLog = z.infer<typeof DecisionLogSchema>;

export const FixtureResultBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		results: z.array(
			z
				.object({
					id: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					evidence_path: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

export type FixtureResultBundle = z.infer<typeof FixtureResultBundleSchema>;

export const ProbeBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		probes: z.array(
			z
				.object({
					id: NonEmptyString,
					status: z.enum(["pass", "fail"]),
					evidence_path: NonEmptyString,
				})
				.strict(),
		),
	})
	.strict();

export type ProbeBundle = z.infer<typeof ProbeBundleSchema>;

export const NoForkProofSchema = z
	.object({
		schemaVersion: z.literal(1),
		hermesCheckoutClean: z.boolean(),
		evidence_path: NonEmptyString,
	})
	.strict();

export type NoForkProof = z.infer<typeof NoForkProofSchema>;

export const QueueOwnershipSnapshotSchema = z
	.object({
		unownedActiveCount: z.number().int().min(0),
	})
	.strict();

export type QueueOwnershipSnapshot = z.infer<typeof QueueOwnershipSnapshotSchema>;

export const RollbackRehearsalSchema = z
	.object({
		schemaVersion: z.literal(1),
		passed: z.boolean(),
		evidence_path: NonEmptyString,
	})
	.strict();

export type RollbackRehearsal = z.infer<typeof RollbackRehearsalSchema>;

export const CutoverInputBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		inventory: InventorySnapshotSchema,
		scopeManifest: CutoverScopeManifestSchema,
		decisionLog: DecisionLogSchema,
		lockfile: CompatibilityLockfileSchema,
		featureProbeMatrix: FeatureProbeMatrixSchema,
		fixtureResults: FixtureResultBundleSchema,
		noForkProof: NoForkProofSchema,
		networkProbes: ProbeBundleSchema,
		queueSnapshot: QueueOwnershipSnapshotSchema,
		rollbackRehearsal: RollbackRehearsalSchema,
	})
	.strict();

export type CutoverInputBundle = z.infer<typeof CutoverInputBundleSchema>;

export type ValidationResult = {
	valid: boolean;
	errors: string[];
};

export type HermesDoctorReport = {
	status: "pass" | "fail";
	pin: HermesPin | null;
	checks: Array<{ name: string; status: "pass" | "fail"; detail: string }>;
};

export type GeneratedPathClass = "secret" | "sensitive" | "derived" | "safe-to-diff";

export type HermesGenerateDryRun = {
	dryRun: true;
	outDir: string;
	pin: HermesPin;
	profileSchemaVersion: "1";
	outputs: Array<{ path: string; classification: GeneratedPathClass }>;
	secretManifest: Array<{ id: string; owner: "telclaude-vault" | "telclaude-edge" }>;
};

export type CutoverReport = {
	status: "safe" | "fail" | "input_error";
	exitCode: 0 | 1 | 2;
	mode: { strict: true; dryRun: boolean };
	gates: Array<{ name: string; status: "pass" | "fail"; detail: string }>;
};

export function parseHermesPin(rawPin: string | undefined): HermesPin | null {
	const pin = rawPin?.trim();
	if (!pin) return null;
	if (pin.startsWith("sha256:")) return { imageDigest: pin };
	if (/^[0-9a-f]{7,40}$/i.test(pin)) return { commit: pin };
	if (pin.includes("/") || pin.includes("@")) return { package: pin };
	return { version: pin };
}

export function validateFeatureProbeMatrix(value: unknown): ValidationResult {
	return formatValidationResult(FeatureProbeMatrixSchema.safeParse(value));
}

export function validateCompatibilityLockfile(value: unknown): ValidationResult {
	return formatValidationResult(CompatibilityLockfileSchema.safeParse(value));
}

export function computeHermesArtifactDigest(value: unknown): string {
	return `sha256:${crypto.createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

export function readJsonFile(filePath: string): unknown {
	return JSON.parse(fs.readFileSync(filePath, "utf8")) as unknown;
}

export function readOptionalJsonFile(filePath: string): unknown | undefined {
	if (!fs.existsSync(filePath)) return undefined;
	return readJsonFile(filePath);
}

export function buildCutoverInputBundleFromArtifacts(input: {
	inventory: unknown;
	scopeManifest: unknown;
	decisionLog: unknown;
	lockfile: unknown;
	featureProbeMatrix: unknown;
	fixtureResults: unknown;
	noForkProof: unknown;
	networkProbes: unknown;
	queueSnapshot?: unknown;
	rollbackRehearsal: unknown;
}): CutoverInputBundle {
	const bundle = {
		schemaVersion: 1,
		inventory: input.inventory,
		scopeManifest: input.scopeManifest,
		decisionLog: input.decisionLog,
		lockfile: input.lockfile,
		featureProbeMatrix: input.featureProbeMatrix,
		fixtureResults: input.fixtureResults,
		noForkProof: input.noForkProof,
		networkProbes: input.networkProbes,
		queueSnapshot: input.queueSnapshot ?? deriveQueueOwnershipSnapshot(input.inventory),
		rollbackRehearsal: input.rollbackRehearsal,
	};
	const parsed = CutoverInputBundleSchema.safeParse(bundle);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return parsed.data;
}

export function buildCutoverScopeManifestFromInventory(inventory: unknown): CutoverScopeManifest {
	const parsed = InventorySnapshotSchema.safeParse(inventory);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return {
		schemaVersion: 1,
		workflows: parsed.data.workflows.map((workflow) => {
			const metadata = workflow as Record<string, unknown>;
			const active = workflow.active;
			return {
				workflow_id: workflow.workflow_id,
				owner: workflow.owner,
				trust_domain: workflow.trust_domain,
				current_behavior:
					typeof metadata.current_surface === "string"
						? metadata.current_surface
						: "TODO: describe current Telclaude behavior",
				hermes_target_behavior:
					typeof metadata.hermes_target === "string"
						? metadata.hermes_target
						: "TODO: describe Hermes target behavior",
				cutover_class:
					metadata.p_class === "P1" || metadata.p_class === "P2" ? metadata.p_class : "P0",
				cutover_requirement: "Resolve parity evidence before inclusion.",
				status: active ? "excluded" : "disabled",
				fixture_ids: [],
				negative_fixture_ids: [],
				required_surface_ids: [],
				unresolved_decision_ids: active ? ["D-first-cutover-workflow-set"] : [],
			};
		}),
	};
}

export function buildCompatibilityLockfileDraft(input: {
	pin: HermesPin | null;
	featureProbeMatrix: unknown;
	wrapperPackageVersion: string;
}): CompatibilityLockfile {
	if (!input.pin) {
		throw new Error(
			"Cannot generate Hermes compatibility lockfile without a pinned Hermes artifact.",
		);
	}
	const parsed = FeatureProbeMatrixSchema.safeParse(input.featureProbeMatrix);
	if (!parsed.success) {
		throw new Error(flattenZodError(parsed.error));
	}
	return {
		schemaVersion: 1,
		hermes: input.pin,
		featureProbeMatrixDigest: computeHermesArtifactDigest(parsed.data),
		featureProbes: parsed.data.probes.map((probe) => ({
			surface_id: probe.surface_id,
			status: probe.status === "pass" ? "pass" : "fail",
			evidence_path: probe.evidence_path,
		})),
		adapterApiSignatures: {},
		capabilities: {
			plugins: [],
			mcp: [],
			modelProviders: [],
			memoryProviders: [],
		},
		requiredUpgradeTests: [
			"pnpm dev hermes doctor --probes --compat-lock --json",
			"pnpm dev hermes cutover-check --strict --dry-run --json",
			"pnpm dev hermes prove --upstream-clean --p0",
		],
		generatedProfileSchemaVersion: "1",
		wrapperPackageVersion: input.wrapperPackageVersion,
		paritySuiteDigests: {},
		noForkProofEvidencePath: "artifacts/hermes/no-fork.json",
		sourceDriftSignals: {},
	};
}

export function buildHermesDoctorReport(options: {
	pin?: HermesPin | null;
	featureProbeMatrix?: unknown;
	featureProbeMatrixMissing?: string;
	lockfile?: unknown;
	lockfileMissing?: string;
}): HermesDoctorReport {
	const checks: HermesDoctorReport["checks"] = [];
	const pin = options.pin ?? null;
	if (pin) {
		checks.push({ name: "hermes.pin", status: "pass", detail: "pinned Hermes artifact supplied" });
	} else {
		checks.push({
			name: "hermes.pin",
			status: "fail",
			detail: "production requires a pinned Hermes artifact",
		});
	}

	if (options.featureProbeMatrixMissing !== undefined) {
		checks.push({
			name: "hermes.featureProbes",
			status: "fail",
			detail: options.featureProbeMatrixMissing,
		});
	} else if (options.featureProbeMatrix !== undefined) {
		const parsed = FeatureProbeMatrixSchema.safeParse(options.featureProbeMatrix);
		const result = formatValidationResult(parsed);
		const statusFailures = parsed.success
			? [
					...(parsed.data.probes.length === 0 ? ["feature-probe matrix is empty"] : []),
					...parsed.data.probes.flatMap((probe) =>
						probe.status === "pass"
							? []
							: [`${probe.surface_id} status is ${probe.status ?? "missing"}`],
					),
				]
			: [];
		checks.push({
			name: "hermes.featureProbes",
			status: result.valid && statusFailures.length === 0 ? "pass" : "fail",
			detail: !result.valid
				? result.errors.join("; ")
				: statusFailures.length === 0
					? "feature-probe matrix schema is valid and all probes passed"
					: statusFailures.join("; "),
		});
	}

	if (options.lockfileMissing !== undefined) {
		checks.push({
			name: "hermes.compatLockfile",
			status: "fail",
			detail: options.lockfileMissing,
		});
	} else if (options.lockfile !== undefined) {
		const parsed = CompatibilityLockfileSchema.safeParse(options.lockfile);
		const result = formatValidationResult(parsed);
		const consistencyFailures =
			parsed.success === true
				? collectLockfileConsistencyFailures({
						lockfile: parsed.data,
						pin,
						featureProbeMatrix: options.featureProbeMatrix,
					})
				: [];
		checks.push({
			name: "hermes.compatLockfile",
			status: result.valid && consistencyFailures.length === 0 ? "pass" : "fail",
			detail: !result.valid
				? result.errors.join("; ")
				: consistencyFailures.length === 0
					? "compatibility lockfile schema is valid and tied to the current probe matrix"
					: consistencyFailures.join("; "),
		});
	}

	return {
		status: checks.every((check) => check.status === "pass") ? "pass" : "fail",
		pin,
		checks,
	};
}

export function buildHermesGenerateDryRun(options: {
	pin: HermesPin | null;
	outDir: string;
}): HermesGenerateDryRun {
	if (!options.pin) {
		throw new Error("Cannot generate Hermes profiles without a pinned Hermes artifact.");
	}
	return {
		dryRun: true,
		outDir: options.outDir,
		pin: options.pin,
		profileSchemaVersion: "1",
		outputs: [
			{ path: "config.yaml", classification: "sensitive" },
			{ path: ".env.EXAMPLE", classification: "safe-to-diff" },
			{ path: "secret-manifest.json", classification: "sensitive" },
			{ path: "SOUL.md", classification: "safe-to-diff" },
			{ path: "mcp.json", classification: "sensitive" },
			{ path: "toolsets.json", classification: "safe-to-diff" },
			{ path: "memory-provider.json", classification: "sensitive" },
			{ path: DEFAULT_COMPAT_LOCKFILE_PATH, classification: "derived" },
		],
		secretManifest: [
			{ id: "model-provider-credentials", owner: "telclaude-vault" },
			{ id: "provider-sidecar-credentials", owner: "telclaude-vault" },
			{ id: "public-channel-credentials", owner: "telclaude-edge" },
		],
	};
}

export function evaluateCutoverCheck(
	input: unknown,
	options: { strict?: boolean; dryRun?: boolean } = {},
): CutoverReport {
	const dryRun = options.dryRun ?? false;
	const strict = options.strict ?? true;
	if (!strict) {
		return {
			status: "input_error",
			exitCode: 2,
			mode: { strict: true, dryRun },
			gates: [
				{
					name: "inputs.strict",
					status: "fail",
					detail: "non-strict cutover evaluation is not supported",
				},
			],
		};
	}

	const parsed = CutoverInputBundleSchema.safeParse(input);
	if (!parsed.success) {
		return {
			status: "input_error",
			exitCode: 2,
			mode: { strict: true, dryRun },
			gates: [{ name: "inputs.valid", status: "fail", detail: flattenZodError(parsed.error) }],
		};
	}

	const bundle = parsed.data;
	const gates: CutoverReport["gates"] = [];
	const included = bundle.scopeManifest.workflows.filter(
		(workflow) => workflow.status === "included",
	);
	const includedWorkflowIds = new Set(included.map((workflow) => workflow.workflow_id));
	const scopedWorkflowIds = new Set(
		bundle.scopeManifest.workflows.map((workflow) => workflow.workflow_id),
	);
	const activeInventoryWorkflowIds = new Set(
		bundle.inventory.workflows
			.filter((workflow) => workflow.active)
			.map((workflow) => workflow.workflow_id),
	);
	const unmappedActiveWorkflowIds = [...activeInventoryWorkflowIds].filter(
		(workflowId) => !scopedWorkflowIds.has(workflowId),
	);
	const duplicateScopeWorkflowIds = findDuplicates(
		bundle.scopeManifest.workflows.map((workflow) => workflow.workflow_id),
	);
	const workflowScopeFailures = [
		...(included.length === 0 ? ["no included workflows"] : []),
		...duplicateScopeWorkflowIds.map((id) => `duplicate scope workflow ${id}`),
		...unmappedActiveWorkflowIds.map((id) => `active inventory workflow ${id} is unmapped`),
		...included.flatMap((workflow) => {
			const failures: string[] = [];
			if (!workflow.rollback_owner) failures.push(`${workflow.workflow_id} missing rollback_owner`);
			if (workflow.fixture_ids.length === 0)
				failures.push(`${workflow.workflow_id} missing fixtures`);
			if (workflow.negative_fixture_ids.length === 0) {
				failures.push(`${workflow.workflow_id} missing negative fixtures`);
			}
			if (workflow.required_surface_ids.length === 0) {
				failures.push(`${workflow.workflow_id} missing required surfaces`);
			}
			return failures;
		}),
	];
	const decisionById = new Map(
		bundle.decisionLog.decisions.map((decision) => [decision.id, decision]),
	);
	const unresolvedDecisionFailures = [
		...included.flatMap((workflow) =>
			workflow.unresolved_decision_ids.map((id) =>
				decisionById.has(id)
					? `${workflow.workflow_id} still lists unresolved decision ${id}`
					: `${workflow.workflow_id} references unknown unresolved decision ${id}`,
			),
		),
		...bundle.decisionLog.decisions.flatMap((decision) =>
			decision.status === "unresolved"
				? decision.affected_workflows
						.filter((workflowId) => includedWorkflowIds.has(workflowId))
						.map((workflowId) => `unresolved decision ${decision.id} affects ${workflowId}`)
				: [],
		),
	];
	const requiredSurfaceIds = unique(included.flatMap((workflow) => workflow.required_surface_ids));
	const probeBySurfaceId = new Map(
		bundle.featureProbeMatrix.probes.map((probe) => [probe.surface_id, probe]),
	);
	const requiredSurfaceFailures = requiredSurfaceIds.flatMap((surfaceId) => {
		const probe = probeBySurfaceId.get(surfaceId);
		if (!probe) return [`missing feature probe ${surfaceId}`];
		if (probe.status !== "pass")
			return [`feature probe ${surfaceId} status is ${probe.status ?? "missing"}`];
		return [];
	});
	const featureProbeFailures = [
		...(bundle.featureProbeMatrix.probes.length === 0 ? ["feature probe matrix is empty"] : []),
		...(requiredSurfaceIds.length === 0 ? ["no required surfaces declared"] : []),
		...requiredSurfaceFailures,
		...bundle.featureProbeMatrix.probes.flatMap((probe) =>
			probe.status === "pass"
				? []
				: [`feature probe ${probe.surface_id} status is ${probe.status ?? "missing"}`],
		),
	];
	const lockfileProbeBySurfaceId = new Map(
		bundle.lockfile.featureProbes.map((probe) => [probe.surface_id, probe]),
	);
	const lockfileFailures = [
		...(bundle.lockfile.featureProbeMatrixDigest ===
		computeHermesArtifactDigest(bundle.featureProbeMatrix)
			? []
			: ["lockfile feature-probe matrix digest does not match current matrix"]),
		...bundle.lockfile.featureProbes.flatMap((probe) =>
			probe.status === "pass"
				? []
				: [`lockfile feature probe ${probe.surface_id} status is ${probe.status}`],
		),
		...bundle.featureProbeMatrix.probes.flatMap((probe) =>
			sameJson(probe.hermes_pin, bundle.lockfile.hermes)
				? []
				: [`feature probe ${probe.surface_id} is not tied to the lockfile Hermes pin`],
		),
		...requiredSurfaceIds.flatMap((surfaceId) => {
			const lockedProbe = lockfileProbeBySurfaceId.get(surfaceId);
			if (!lockedProbe) return [`lockfile is missing feature probe ${surfaceId}`];
			if (lockedProbe.status !== "pass")
				return [`lockfile feature probe ${surfaceId} status is ${lockedProbe.status}`];
			return [];
		}),
	];
	const requiredFixtureIds = unique(
		included.flatMap((workflow) => [...workflow.fixture_ids, ...workflow.negative_fixture_ids]),
	);
	const fixtureById = new Map(bundle.fixtureResults.results.map((result) => [result.id, result]));
	const fixtureFailures = [
		...(bundle.fixtureResults.results.length === 0 ? ["fixture result bundle is empty"] : []),
		...(requiredFixtureIds.length === 0 ? ["no required fixtures declared"] : []),
		...requiredFixtureIds.flatMap((fixtureId) => {
			const result = fixtureById.get(fixtureId);
			if (!result) return [`missing fixture result ${fixtureId}`];
			if (result.status !== "pass") return [`fixture ${fixtureId} status is ${result.status}`];
			return [];
		}),
		...bundle.fixtureResults.results.flatMap((result) =>
			result.status === "pass" ? [] : [`fixture ${result.id} status is ${result.status}`],
		),
	];
	const networkProbeById = new Map(bundle.networkProbes.probes.map((probe) => [probe.id, probe]));
	const networkProbeFailures = [
		...(bundle.networkProbes.probes.length === 0 ? ["network probe bundle is empty"] : []),
		...REQUIRED_CUTOVER_NETWORK_PROBE_IDS.flatMap((probeId) => {
			const probe = networkProbeById.get(probeId);
			if (!probe) return [`missing network probe ${probeId}`];
			if (probe.status !== "pass") return [`network probe ${probeId} status is ${probe.status}`];
			return [];
		}),
		...bundle.networkProbes.probes.flatMap((probe) =>
			probe.status === "pass" ? [] : [`network probe ${probe.id} status is ${probe.status}`],
		),
	];

	gates.push({
		name: "workflow.scope",
		status: workflowScopeFailures.length === 0 ? "pass" : "fail",
		detail:
			workflowScopeFailures.length === 0
				? "included workflows are inventoried and have owner, trust domain, fixtures, surfaces, and rollback owners"
				: workflowScopeFailures.join("; "),
	});
	gates.push({
		name: "decisions.resolved",
		status: unresolvedDecisionFailures.length === 0 ? "pass" : "fail",
		detail:
			unresolvedDecisionFailures.length === 0
				? "included workflows do not depend on unresolved decisions"
				: unresolvedDecisionFailures.join("; "),
	});
	gates.push({
		name: "featureProbes.pass",
		status: featureProbeFailures.length === 0 ? "pass" : "fail",
		detail:
			featureProbeFailures.length === 0
				? "feature probes for included surfaces passed"
				: unique(featureProbeFailures).join("; "),
	});
	gates.push({
		name: "lockfile.consistent",
		status: lockfileFailures.length === 0 ? "pass" : "fail",
		detail:
			lockfileFailures.length === 0
				? "compatibility lockfile is tied to the pinned probes and included surfaces"
				: unique(lockfileFailures).join("; "),
	});
	gates.push({
		name: "fixtures.pass",
		status: fixtureFailures.length === 0 ? "pass" : "fail",
		detail:
			fixtureFailures.length === 0
				? "required parity and negative fixtures passed"
				: unique(fixtureFailures).join("; "),
	});
	gates.push({
		name: "nofork.clean",
		status: bundle.noForkProof.hermesCheckoutClean ? "pass" : "fail",
		detail: "pinned Hermes checkout must remain clean",
	});
	gates.push({
		name: "networkProbes.pass",
		status: networkProbeFailures.length === 0 ? "pass" : "fail",
		detail:
			networkProbeFailures.length === 0
				? "required network-denial probes passed"
				: unique(networkProbeFailures).join("; "),
	});
	gates.push({
		name: "queues.owned",
		status: bundle.queueSnapshot.unownedActiveCount === 0 ? "pass" : "fail",
		detail: "active queues, approvals, cards, cron, social, and provider work must be owned",
	});
	gates.push({
		name: "rollback.rehearsed",
		status: bundle.rollbackRehearsal.passed ? "pass" : "fail",
		detail: "rollback rehearsal evidence is required",
	});

	const safe = gates.every((gate) => gate.status === "pass");
	return {
		status: safe ? "safe" : "fail",
		exitCode: safe ? 0 : 1,
		mode: { strict: true, dryRun },
		gates,
	};
}

export function resolveHermesArtifactPath(relativePath: string): string {
	return path.resolve(relativePath);
}

function formatValidationResult(
	result: { success: true } | { success: false; error: z.ZodError },
): ValidationResult {
	if (result.success) return { valid: true, errors: [] };
	return { valid: false, errors: [flattenZodError(result.error)] };
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
		.join("; ");
}

function unique(values: string[]): string[] {
	return [...new Set(values)];
}

function findDuplicates(values: string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) {
			duplicates.add(value);
		} else {
			seen.add(value);
		}
	}
	return [...duplicates];
}

function sameJson(left: unknown, right: unknown): boolean {
	return JSON.stringify(left) === JSON.stringify(right);
}

function deriveQueueOwnershipSnapshot(inventory: unknown): QueueOwnershipSnapshot {
	const pendingQueues = (inventory as { summary?: { pendingQueues?: Record<string, unknown> } })
		.summary?.pendingQueues;
	const unownedActiveCount = Object.values(pendingQueues ?? {}).reduce<number>(
		(total, value) => total + (typeof value === "number" && Number.isFinite(value) ? value : 0),
		0,
	);
	return { unownedActiveCount };
}

function collectLockfileConsistencyFailures(input: {
	lockfile: CompatibilityLockfile;
	pin: HermesPin | null;
	featureProbeMatrix?: unknown;
}): string[] {
	const failures: string[] = [];
	if (input.pin && !sameJson(input.lockfile.hermes, input.pin)) {
		failures.push("lockfile Hermes pin does not match requested pin");
	}
	for (const probe of input.lockfile.featureProbes) {
		if (probe.status !== "pass") {
			failures.push(`lockfile feature probe ${probe.surface_id} status is ${probe.status}`);
		}
	}
	if (input.featureProbeMatrix !== undefined) {
		const parsed = FeatureProbeMatrixSchema.safeParse(input.featureProbeMatrix);
		if (parsed.success) {
			const digest = computeHermesArtifactDigest(parsed.data);
			if (input.lockfile.featureProbeMatrixDigest !== digest) {
				failures.push("lockfile feature-probe matrix digest does not match current matrix");
			}
		}
	}
	return unique(failures);
}

function stableStringify(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
	const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
		left.localeCompare(right),
	);
	return `{${entries
		.map(([key, entry]) => `${JSON.stringify(key)}:${stableStringify(entry)}`)
		.join(",")}}`;
}
