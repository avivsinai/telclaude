import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { z } from "zod";
import { type InternalResponseProof, verifyInternalResponseProof } from "../internal-auth.js";
import { redactSecrets } from "../security/output-filter.js";
import { evaluateServedMcpContainmentEvidence } from "./served-mcp-containment.js";

export const DEFAULT_FEATURE_PROBE_MATRIX_PATH = "docs/hermes/feature-probes.json";
export const DEFAULT_COMPAT_LOCKFILE_PATH = "docs/hermes/hermes-compat.lock.json";
export const DEFAULT_CUTOVER_SCOPE_PATH = "docs/hermes/cutover-scope.json";
export const DEFAULT_DECISION_LOG_PATH = "docs/hermes/decisions.json";
export const DEFAULT_FIXTURE_RESULTS_PATH = "docs/hermes/fixture-results.json";
export const DEFAULT_NETWORK_PROBES_PATH = "docs/hermes/network-probes.json";
export const DEFAULT_NO_FORK_PROOF_PATH = "docs/hermes/no-fork-proof.json";
export const DEFAULT_ROLLBACK_REHEARSAL_PATH = "docs/hermes/rollback-rehearsal.json";
export const HERMES_PROBE_RESULT_SCHEMA_VERSION = "telclaude.hermes.probe-result.v1";
export const NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION = "telclaude.hermes.network-probe.v1";
export const REQUIRED_CUTOVER_NETWORK_PROBE_IDS = [
	"network.relay-control-allowed",
	"network.direct-provider-denied",
	"network.direct-vault-denied",
	"network.direct-model-provider-denied",
	"network.dns-exfil-denied",
] as const;

const NonEmptyString = z.string().trim().min(1);
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;
const GIT_COMMIT_PATTERN = /^[0-9a-f]{7,40}$/i;
const PLACEHOLDER_VALUES = new Set([
	"pending",
	"todo",
	"tbd",
	"fixme",
	"sha256:pending",
	"sha256:todo",
	"sha256:tbd",
]);

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
				"api-server-containment",
				"edge-adapter",
				"model-relay",
				"nofork-proof",
				"served-mcp-containment",
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

const FeatureProbeEvidenceResultSchema = z
	.object({
		surface_id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		evidence_path: NonEmptyString,
		detail: NonEmptyString,
	})
	.strict();

export const FeatureProbeEvidenceBundleSchema = z
	.object({
		schemaVersion: z.literal(1),
		results: z.array(FeatureProbeEvidenceResultSchema),
	})
	.strict();

export type FeatureProbeEvidenceBundle = z.infer<typeof FeatureProbeEvidenceBundleSchema>;

const CliHeadlessProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(HERMES_PROBE_RESULT_SCHEMA_VERSION),
		probeId: z.literal("execution.cli_headless"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		exitCode: z.number().int(),
		invocation: z
			.object({
				command: NonEmptyString,
				args: z.array(z.string()),
				cwd: NonEmptyString,
				envKeys: z.array(NonEmptyString),
			})
			.passthrough(),
		findings: z.array(
			z
				.object({
					location: NonEmptyString,
					reason: NonEmptyString,
				})
				.passthrough(),
		),
	})
	.passthrough();

const API_SERVER_CONTAINMENT_SCHEMA_VERSION = "telclaude.hermes.api-server-containment.v1";
const MODEL_RELAY_SCHEMA_VERSION = "telclaude.hermes.model-relay.v1";
const REQUIRED_API_SERVER_CONTAINMENT_GATES = [
	"lifecycle.started",
	"readiness.health",
	"readiness.capabilities",
	"network.topology",
	"network.relay_only",
	"network.tamper_resistant",
] as const;
const REQUIRED_MODEL_RELAY_GATES = [
	"modelRelay.allowed",
	"firewall.sentinel",
	"modelRelay.origin",
	"relay.reachable",
	"directModel.denied",
	"profile.noRawModelCredentials",
	"profile.noDirectModelHosts",
	"profile.scanComplete",
] as const;
const DIRECT_MODEL_RELAY_PROVIDER_HOSTS = new Set([
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"openrouter.ai",
	"api.x.ai",
]);
const FEATURE_PROBE_SURFACES_REQUIRING_OBSERVED_EVIDENCE = new Set([
	"execution.cli_headless",
	"execution.approval_continuation",
	"execution.api_server_containment",
	"execution.served_mcp_containment",
	"model.relay",
]);
const REQUIRED_NO_FORK_CHECK_NAMES = [
	"checkout.present",
	"checkout.head",
	"checkout.expectedRef",
	"checkout.pinned",
	"checkout.statusClean",
	"checkout.diffClean",
	"checkout.indexClean",
] as const;
const REQUIRED_ROLLBACK_REHEARSAL_CHECK_NAMES = [
	"rollback.allowed",
	"rollback.relayProofs",
	"rollback.flagBefore",
	"rollback.flagAfter",
	"rollback.fallbackPath",
	"rollback.controlSurface",
	"rollback.observedSources",
] as const;
export const HERMES_ROLLBACK_CONTROL_SURFACE =
	"relay.capabilities:/v1/hermes.private-runtime.mode" as const;
export const HERMES_ROLLBACK_OBSERVATION_SURFACE =
	"relay.capabilities:/v1/hermes.private-runtime.status" as const;

const ApiServerContainmentProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(API_SERVER_CONTAINMENT_SCHEMA_VERSION),
		probeId: z.literal("execution.api_server_containment"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		gates: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.enum(["pass", "fail", "pending"]),
					detail: NonEmptyString,
				})
				.passthrough(),
		),
		findings: z.array(z.unknown()),
	})
	.passthrough();

const ModelRelayProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(MODEL_RELAY_SCHEMA_VERSION),
		probeId: z.literal("model.relay"),
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		origin: z
			.object({
				kind: z.enum(["contained-peer", "relay-self-smoke", "unknown"]),
				containerName: NonEmptyString.optional(),
				observedPeerAddress: NonEmptyString.optional(),
				observedPeerSource: z.literal("server-peer-echo").optional(),
				expectedPeerAddress: NonEmptyString.optional(),
				expectedPeerSource: z.literal("configured-contained-ip").optional(),
				detail: NonEmptyString,
			})
			.passthrough(),
		observation: z
			.object({
				relayUrl: NonEmptyString.optional(),
				directModelUrl: NonEmptyString,
				profileDir: NonEmptyString.optional(),
				scannedProfileFiles: z.array(NonEmptyString).optional(),
			})
			.passthrough(),
		gates: z.array(
			z
				.object({
					name: NonEmptyString,
					status: z.enum(["pass", "fail", "pending"]),
					detail: NonEmptyString,
				})
				.passthrough(),
		),
	})
	.passthrough();

const NetworkProbeAttemptSchema = z
	.object({
		name: NonEmptyString,
		kind: z.enum(["http", "unix_socket", "dns_guard", "firewall_sentinel", "configuration"]),
		target: NonEmptyString,
		expectation: z.enum(["allow", "deny", "present", "configured"]),
		status: z.enum(["pass", "fail"]),
		observed: NonEmptyString,
		detail: NonEmptyString,
		durationMs: z.number().nonnegative().optional(),
		httpStatus: z.number().int().nonnegative().optional(),
		errorName: NonEmptyString.optional(),
		errorCode: NonEmptyString.optional(),
		resolvedAddresses: z
			.array(
				z
					.object({
						address: NonEmptyString,
						blocked: z.boolean(),
						nonOverridable: z.boolean(),
					})
					.strict(),
			)
			.optional(),
	})
	.strict();

const NetworkProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(NETWORK_PROBE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		status: z.enum(["pass", "fail", "pending"]),
		ran: z.boolean(),
		summary: NonEmptyString,
		generatedAt: NonEmptyString,
		evidence_path: NonEmptyString,
		attempts: z.array(NetworkProbeAttemptSchema),
	})
	.strict();

const REQUIRED_CUTOVER_NETWORK_PROBE_ID_SET = new Set<string>(REQUIRED_CUTOVER_NETWORK_PROBE_IDS);

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

const InventoryQueueEvidenceSchema = z
	.object({
		status: z.literal("complete"),
		summary: z
			.object({
				pendingQueues: z
					.object({
						approvals: z.number().int().min(0),
						planApprovals: z.number().int().min(0),
						cards: z.number().int().min(0),
						backgroundJobs: z.number().int().min(0),
						socialItems: z.number().int().min(0),
						curatorItems: z.number().int().min(0),
						pairingPendingRequests: z.number().int().min(0),
						pairingActiveLockouts: z.number().int().min(0),
					})
					.strict(),
			})
			.passthrough(),
	})
	.passthrough();

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

const FixtureEvidenceSchema = z
	.object({
		schemaVersion: NonEmptyString,
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		generatedAt: NonEmptyString.optional(),
		observedAt: NonEmptyString.optional(),
		provenance: z
			.object({
				runner: NonEmptyString,
				command: NonEmptyString.optional(),
				source: NonEmptyString.optional(),
			})
			.passthrough(),
	})
	.passthrough()
	.refine((evidence) => evidence.generatedAt !== undefined || evidence.observedAt !== undefined, {
		message: "fixture evidence requires generatedAt or observedAt",
	});

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
		checkoutPath: NonEmptyString.optional(),
		expectedRef: NonEmptyString.optional(),
		expectedVersion: NonEmptyString.optional(),
		head: NonEmptyString.optional(),
		expectedRefCommit: NonEmptyString.optional(),
		currentBranch: NonEmptyString.optional(),
		exactTags: z.array(NonEmptyString).optional(),
		statusPorcelain: z.string().optional(),
		diffExitCode: z.number().int().optional(),
		cachedDiffExitCode: z.number().int().optional(),
		checks: z
			.array(
				z
					.object({
						name: NonEmptyString,
						status: z.enum(["pass", "fail"]),
						detail: NonEmptyString,
					})
					.strict(),
			)
			.optional(),
	})
	.strict();

export type NoForkProof = z.infer<typeof NoForkProofSchema>;

export const QueueOwnershipSnapshotSchema = z
	.object({
		unownedActiveCount: z.number().int().min(0),
	})
	.strict();

export type QueueOwnershipSnapshot = z.infer<typeof QueueOwnershipSnapshotSchema>;

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: z.string().min(1),
		timestamp: z.string().min(1),
		nonce: z.string().min(1),
		method: z.string().min(1),
		path: z.string().min(1),
		requestBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
		responseBodySha256: z.string().regex(/^[a-f0-9]{64}$/),
		signature: z.string().min(1),
	})
	.strict();

const RollbackRelayStateBodySchema = z
	.object({
		ok: z.literal(true),
		effectiveMode: z.enum(["hermes", "legacy"]),
		effectiveValue: z.enum(["1", "0"]),
		rolloutAllowed: z.boolean(),
		rolloutEnvValue: z.string().optional(),
		controlMode: z.enum(["hermes", "legacy"]),
		controlSource: z.enum([
			"env-disabled",
			"runtime-config",
			"runtime-config-default",
			"runtime-config-invalid",
		]),
		fallbackPath: NonEmptyString,
	})
	.strict();

const RollbackRelayTranscriptSchema = z
	.object({
		request: z
			.object({
				method: NonEmptyString,
				path: NonEmptyString,
				body: z.string(),
			})
			.strict(),
		responseBody: NonEmptyString,
		proof: InternalResponseProofSchema,
	})
	.strict();

export const RollbackRehearsalSchema = z
	.object({
		schemaVersion: z.literal(1),
		passed: z.boolean(),
		evidence_path: NonEmptyString,
		allowedToRun: z.boolean().optional(),
		observedBeforeValue: NonEmptyString.optional(),
		observedAfterValue: NonEmptyString.optional(),
		observedFallbackPath: NonEmptyString.optional(),
		observedAt: NonEmptyString.optional(),
		controlSurface: NonEmptyString.optional(),
		observationSurface: NonEmptyString.optional(),
		observedBeforeSource: NonEmptyString.optional(),
		observedAfterSource: NonEmptyString.optional(),
		observedAfterControlSource: NonEmptyString.optional(),
		signedRelayTranscripts: z
			.object({
				before: RollbackRelayTranscriptSchema,
				afterControl: RollbackRelayTranscriptSchema,
				after: RollbackRelayTranscriptSchema,
			})
			.strict()
			.optional(),
		checks: z
			.array(
				z
					.object({
						name: NonEmptyString,
						status: z.enum(["pass", "fail"]),
						detail: NonEmptyString,
					})
					.strict(),
			)
			.optional(),
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
		featureProbeEvidence: FeatureProbeEvidenceBundleSchema.optional(),
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
	featureProbeEvidence?: unknown;
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
		featureProbeEvidence: input.featureProbeEvidence,
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

export function collectFeatureProbeEvidence(
	featureProbeMatrix: unknown,
): FeatureProbeEvidenceBundle | undefined {
	const parsed = FeatureProbeMatrixSchema.safeParse(featureProbeMatrix);
	if (!parsed.success) return undefined;
	const results = parsed.data.probes.flatMap((probe) => {
		if (probe.surface_id === "execution.cli_headless") {
			return [collectCliHeadlessProbeEvidence(probe)];
		}
		if (probe.surface_id === "execution.served_mcp_containment") {
			return [collectServedMcpContainmentProbeEvidence(probe)];
		}
		if (probe.surface_id === "execution.api_server_containment") {
			return [collectApiServerContainmentProbeEvidence(probe)];
		}
		if (probe.surface_id === "model.relay") {
			return [collectModelRelayProbeEvidence(probe)];
		}
		return [];
	});
	return { schemaVersion: 1, results };
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
			decision.status === "unresolved" && decision.affected_workflows.length === 0
				? [`unresolved decision ${decision.id} has no affected workflows and is treated as global`]
				: [],
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
	const featureProbeEvidenceBySurfaceId = new Map(
		(bundle.featureProbeEvidence?.results ?? []).map((result) => [result.surface_id, result]),
	);
	const requiredSurfaceFailures = requiredSurfaceIds.flatMap((surfaceId) => {
		const probe = probeBySurfaceId.get(surfaceId);
		if (!probe) return [`missing feature probe ${surfaceId}`];
		const failure = featureProbeFailure(probe, featureProbeEvidenceBySurfaceId.get(surfaceId));
		if (failure) return [failure];
		return [];
	});
	const featureProbeFailures = [
		...(bundle.featureProbeMatrix.probes.length === 0 ? ["feature probe matrix is empty"] : []),
		...(requiredSurfaceIds.length === 0 ? ["no required surfaces declared"] : []),
		...requiredSurfaceFailures,
		...bundle.featureProbeMatrix.probes.flatMap((probe) => {
			const failure = featureProbeFailure(
				probe,
				featureProbeEvidenceBySurfaceId.get(probe.surface_id),
			);
			return failure ? [failure] : [];
		}),
	];
	const lockfileProbeBySurfaceId = new Map(
		bundle.lockfile.featureProbes.map((probe) => [probe.surface_id, probe]),
	);
	const lockfileFailures = [
		...lockfileEvidenceFailures(bundle.lockfile, bundle.noForkProof),
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
			const evidenceFailure = fixtureEvidenceFailure(result);
			if (evidenceFailure) return [evidenceFailure];
			return [];
		}),
		...bundle.fixtureResults.results.flatMap((result) => {
			if (result.status !== "pass") return [`fixture ${result.id} status is ${result.status}`];
			const evidenceFailure = fixtureEvidenceFailure(result);
			return evidenceFailure ? [evidenceFailure] : [];
		}),
	];
	const noForkFailures = noForkProofEvidenceFailures(bundle.noForkProof);
	const rollbackRehearsalFailures = rollbackRehearsalEvidenceFailures(bundle.rollbackRehearsal);
	const networkProbeById = new Map(bundle.networkProbes.probes.map((probe) => [probe.id, probe]));
	const networkProbeFailures = [
		...(bundle.networkProbes.probes.length === 0 ? ["network probe bundle is empty"] : []),
		...findDuplicates(bundle.networkProbes.probes.map((probe) => probe.id)).map(
			(id) => `duplicate network probe ${id}`,
		),
		...REQUIRED_CUTOVER_NETWORK_PROBE_IDS.flatMap((probeId) => {
			const probe = networkProbeById.get(probeId);
			if (!probe) return [`missing network probe ${probeId}`];
			return [];
		}),
		...bundle.networkProbes.probes.flatMap((probe) => networkProbeEvidenceFailures(probe)),
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
		status: noForkFailures.length === 0 ? "pass" : "fail",
		detail:
			noForkFailures.length === 0
				? "pinned Hermes checkout proof passed from schema-valid evidence"
				: unique(noForkFailures).join("; "),
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
		status: rollbackRehearsalFailures.length === 0 ? "pass" : "fail",
		detail:
			rollbackRehearsalFailures.length === 0
				? "rollback rehearsal passed from schema-valid evidence"
				: unique(rollbackRehearsalFailures).join("; "),
	});

	const safe = gates.every((gate) => gate.status === "pass");
	return {
		status: safe ? "safe" : "fail",
		exitCode: safe ? 0 : 1,
		mode: { strict: true, dryRun },
		gates,
	};
}

function lockfileEvidenceFailures(
	lockfile: CompatibilityLockfile,
	noForkProof: NoForkProof,
): string[] {
	const failures: string[] = [];
	failures.push(...placeholderFailures("lockfile", lockfile));
	if (!SHA256_DIGEST_PATTERN.test(lockfile.featureProbeMatrixDigest)) {
		failures.push("lockfile featureProbeMatrixDigest is placeholder or invalid");
	}
	for (const [key, value] of Object.entries(lockfile.adapterApiSignatures)) {
		if (!SHA256_DIGEST_PATTERN.test(value)) {
			failures.push(`lockfile adapterApiSignatures.${key} is placeholder or invalid`);
		}
	}
	if (Object.keys(lockfile.adapterApiSignatures).length === 0) {
		failures.push("lockfile adapterApiSignatures is empty");
	}
	for (const [key, value] of Object.entries(lockfile.paritySuiteDigests)) {
		if (!SHA256_DIGEST_PATTERN.test(value)) {
			failures.push(`lockfile paritySuiteDigests.${key} is placeholder or invalid`);
		}
	}
	if (Object.keys(lockfile.paritySuiteDigests).length === 0) {
		failures.push("lockfile paritySuiteDigests is empty");
	}
	for (const [key, value] of Object.entries(lockfile.sourceDriftSignals)) {
		if (value !== undefined && !GIT_COMMIT_PATTERN.test(value)) {
			failures.push(`lockfile sourceDriftSignals.${key} is placeholder or invalid`);
		}
	}
	if (!lockfile.sourceDriftSignals.sourceCommit || !lockfile.sourceDriftSignals.docsCommit) {
		failures.push("lockfile sourceDriftSignals must include sourceCommit and docsCommit");
	}
	if (!sameResolvedArtifactPath(lockfile.noForkProofEvidencePath, noForkProof.evidence_path)) {
		failures.push("lockfile noForkProofEvidencePath does not match no-fork evidence path");
	}
	return failures;
}

function fixtureEvidenceFailure(result: FixtureResultBundle["results"][number]): string | null {
	const resultPlaceholders = placeholderFailures(`fixture result ${result.id}`, result);
	if (resultPlaceholders.length > 0) return resultPlaceholders.join("; ");
	const resolvedPath = resolveHermesArtifactPath(result.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return `missing fixture evidence ${redactDetail(result.id)}: ${redactDetail(resolvedPath)}`;
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return `unreadable fixture evidence ${redactDetail(result.id)}: ${redactDetail(
			error instanceof Error ? error.message : String(error),
		)}`;
	}
	const parsed = FixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid fixture evidence ${redactDetail(result.id)}: ${redactDetail(
			flattenZodError(parsed.error),
		)}`;
	}
	const evidencePlaceholders = placeholderFailures(`fixture evidence ${result.id}`, parsed.data);
	if (evidencePlaceholders.length > 0) return evidencePlaceholders.join("; ");
	if (parsed.data.id !== result.id) {
		return `fixture evidence id mismatch for ${redactDetail(result.id)}`;
	}
	if (parsed.data.status !== "pass") {
		return `fixture evidence ${redactDetail(result.id)} status is ${parsed.data.status}`;
	}
	if (!sameResolvedArtifactPath(parsed.data.evidence_path, result.evidence_path)) {
		return `fixture evidence_path mismatch for ${redactDetail(result.id)}`;
	}
	return null;
}

export function resolveHermesArtifactPath(relativePath: string): string {
	return path.resolve(relativePath);
}

function noForkProofEvidenceFailures(noForkProof: NoForkProof): string[] {
	const failures = noForkProof.hermesCheckoutClean
		? []
		: ["no-fork proof summary hermesCheckoutClean is false"];
	const loaded = readNoForkProofEvidence(noForkProof);
	if (!loaded.valid) return [...failures, loaded.failure];

	const evidence = loaded.evidence;
	failures.push(
		...placeholderFailures("no-fork evidence", {
			checkoutPath: evidence.checkoutPath,
			expectedRef: evidence.expectedRef,
			expectedVersion: evidence.expectedVersion,
			head: evidence.head,
			expectedRefCommit: evidence.expectedRefCommit,
			exactTags: evidence.exactTags,
			evidence_path: evidence.evidence_path,
		}),
	);
	if (!sameResolvedArtifactPath(evidence.evidence_path, noForkProof.evidence_path)) {
		failures.push(`no-fork evidence_path is ${redactDetail(evidence.evidence_path)}`);
	}
	if (evidence.hermesCheckoutClean !== true) {
		failures.push("no-fork evidence hermesCheckoutClean is false");
	}
	if (evidence.checks === undefined || evidence.checks.length === 0) {
		failures.push("no-fork evidence checks are empty");
	}
	for (const field of [
		"checkoutPath",
		"expectedRef",
		"expectedVersion",
		"head",
		"expectedRefCommit",
	]) {
		if (typeof evidence[field as keyof NoForkProof] !== "string") {
			failures.push(`no-fork evidence ${field} is missing`);
		}
	}
	if (
		typeof evidence.head === "string" &&
		typeof evidence.expectedRefCommit === "string" &&
		evidence.head !== evidence.expectedRefCommit
	) {
		failures.push("no-fork evidence HEAD does not match expectedRefCommit");
	}
	if (typeof evidence.head === "string" && !GIT_COMMIT_PATTERN.test(evidence.head)) {
		failures.push("no-fork evidence head is placeholder or invalid");
	}
	if (
		typeof evidence.expectedRefCommit === "string" &&
		!GIT_COMMIT_PATTERN.test(evidence.expectedRefCommit)
	) {
		failures.push("no-fork evidence expectedRefCommit is placeholder or invalid");
	}
	if (
		typeof evidence.expectedRef === "string" &&
		!(evidence.exactTags ?? []).includes(evidence.expectedRef)
	) {
		failures.push(
			`no-fork evidence exactTags does not include ${redactDetail(evidence.expectedRef)}`,
		);
	}
	if (evidence.statusPorcelain !== "") {
		failures.push("no-fork evidence statusPorcelain is not clean");
	}
	if (evidence.diffExitCode !== 0) {
		failures.push(`no-fork evidence diffExitCode is ${String(evidence.diffExitCode)}`);
	}
	if (evidence.cachedDiffExitCode !== 0) {
		failures.push(`no-fork evidence cachedDiffExitCode is ${String(evidence.cachedDiffExitCode)}`);
	}
	const checkByName = new Map((evidence.checks ?? []).map((check) => [check.name, check]));
	for (const duplicate of findDuplicates((evidence.checks ?? []).map((check) => check.name))) {
		failures.push(`duplicate no-fork evidence check ${redactDetail(duplicate)}`);
	}
	for (const checkName of REQUIRED_NO_FORK_CHECK_NAMES) {
		const check = checkByName.get(checkName);
		if (!check) {
			failures.push(`missing no-fork evidence check ${checkName}`);
		} else if (check.status !== "pass") {
			failures.push(
				`no-fork evidence required check ${redactDetail(checkName)} is fail: ${redactDetail(check.detail)}`,
			);
		}
	}
	for (const check of evidence.checks ?? []) {
		if (check.status === "pass") continue;
		failures.push(
			`no-fork evidence check ${redactDetail(check.name)} is fail: ${redactDetail(check.detail)}`,
		);
	}
	return failures;
}

function readNoForkProofEvidence(
	noForkProof: NoForkProof,
): { valid: true; evidence: NoForkProof } | { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(noForkProof.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing no-fork proof evidence: ${redactDetail(resolvedPath)}`,
		};
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable no-fork proof evidence: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}
	const parsed = NoForkProofSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid no-fork proof evidence: ${redactDetail(flattenZodError(parsed.error))}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function rollbackRehearsalEvidenceFailures(rollbackRehearsal: RollbackRehearsal): string[] {
	const failures = rollbackRehearsal.passed ? [] : ["rollback rehearsal summary passed is false"];
	const loaded = readRollbackRehearsalEvidence(rollbackRehearsal);
	if (!loaded.valid) return [...failures, loaded.failure];

	const evidence = loaded.evidence;
	if (!sameResolvedArtifactPath(evidence.evidence_path, rollbackRehearsal.evidence_path)) {
		failures.push(`rollback rehearsal evidence_path is ${redactDetail(evidence.evidence_path)}`);
	}
	if (evidence.passed !== true) {
		failures.push("rollback rehearsal evidence passed is false");
	}
	if (evidence.allowedToRun !== true) {
		failures.push("rollback rehearsal evidence allowedToRun is not true");
	}
	if (evidence.observedBeforeValue !== "1") {
		failures.push("rollback rehearsal evidence observedBeforeValue is not 1");
	}
	if (evidence.observedAfterValue !== "0") {
		failures.push("rollback rehearsal evidence observedAfterValue is not 0");
	}
	if (typeof evidence.observedFallbackPath !== "string") {
		failures.push("rollback rehearsal evidence observedFallbackPath is missing");
	}
	if (typeof evidence.observedAt !== "string") {
		failures.push("rollback rehearsal evidence observedAt is missing");
	}
	if (evidence.controlSurface !== HERMES_ROLLBACK_CONTROL_SURFACE) {
		failures.push("rollback rehearsal evidence controlSurface is not relay durable control");
	}
	if (evidence.observationSurface !== HERMES_ROLLBACK_OBSERVATION_SURFACE) {
		failures.push(
			"rollback rehearsal evidence observationSurface is not relay effective-mode status",
		);
	}
	if (evidence.observedBeforeSource !== "relay-effective-mode") {
		failures.push("rollback rehearsal evidence observedBeforeSource is not relay-effective-mode");
	}
	if (evidence.observedAfterSource !== "relay-effective-mode") {
		failures.push("rollback rehearsal evidence observedAfterSource is not relay-effective-mode");
	}
	if (evidence.observedAfterControlSource !== "runtime-config") {
		failures.push("rollback rehearsal evidence observedAfterControlSource is not runtime-config");
	}
	failures.push(...rollbackRelayTranscriptFailures(evidence));
	if (evidence.checks === undefined || evidence.checks.length === 0) {
		failures.push("rollback rehearsal evidence checks are empty");
	}
	const checkNames = (evidence.checks ?? []).map((check) => check.name);
	const checkByName = new Map((evidence.checks ?? []).map((check) => [check.name, check]));
	for (const duplicate of findDuplicates(checkNames)) {
		failures.push(`duplicate rollback rehearsal evidence check ${redactDetail(duplicate)}`);
	}
	for (const checkName of REQUIRED_ROLLBACK_REHEARSAL_CHECK_NAMES) {
		const check = checkByName.get(checkName);
		if (!check) {
			failures.push(`missing rollback rehearsal evidence check ${checkName}`);
		} else if (check.status !== "pass") {
			failures.push(
				`rollback rehearsal required check ${redactDetail(checkName)} is fail: ${redactDetail(check.detail)}`,
			);
		}
	}
	for (const check of evidence.checks ?? []) {
		if (check.status === "pass") continue;
		failures.push(
			`rollback rehearsal evidence check ${redactDetail(check.name)} is fail: ${redactDetail(check.detail)}`,
		);
	}
	return failures;
}

function rollbackRelayTranscriptFailures(evidence: RollbackRehearsal): string[] {
	const transcripts = evidence.signedRelayTranscripts;
	if (!transcripts) return ["rollback rehearsal signed relay transcripts are missing"];
	return [
		...rollbackRelayTranscriptFailure("before", transcripts.before, evidence, {
			method: "POST",
			path: "/v1/hermes.private-runtime.status",
			body: "{}",
			effectiveValue: "1",
			effectiveMode: "hermes",
		}),
		...rollbackRelayTranscriptFailure("afterControl", transcripts.afterControl, evidence, {
			method: "POST",
			path: "/v1/hermes.private-runtime.mode",
			body: JSON.stringify({ mode: "legacy" }),
			effectiveValue: "0",
			controlMode: "legacy",
			controlSource: "runtime-config",
		}),
		...rollbackRelayTranscriptFailure("after", transcripts.after, evidence, {
			method: "POST",
			path: "/v1/hermes.private-runtime.status",
			body: "{}",
			effectiveValue: "0",
			effectiveMode: "legacy",
			controlSource: "runtime-config",
		}),
	];
}

function rollbackRelayTranscriptFailure(
	label: "before" | "afterControl" | "after",
	transcript: z.infer<typeof RollbackRelayTranscriptSchema>,
	evidence: RollbackRehearsal,
	expected: {
		method: string;
		path: string;
		body: string;
		effectiveValue: "1" | "0";
		effectiveMode?: "hermes" | "legacy";
		controlMode?: "hermes" | "legacy";
		controlSource?:
			| "env-disabled"
			| "runtime-config"
			| "runtime-config-default"
			| "runtime-config-invalid";
	},
): string[] {
	const failures: string[] = [];
	if (transcript.request.method !== expected.method) {
		failures.push(`rollback ${label} relay transcript method is ${transcript.request.method}`);
	}
	if (transcript.request.path !== expected.path) {
		failures.push(`rollback ${label} relay transcript path is ${transcript.request.path}`);
	}
	if (transcript.request.body !== expected.body) {
		failures.push(`rollback ${label} relay transcript body does not match`);
	}
	if (
		!verifyInternalResponseProof(
			transcript.proof as InternalResponseProof,
			expected.method,
			expected.path,
			expected.body,
			transcript.responseBody,
			{ scope: "operator" },
		)
	) {
		failures.push(`rollback ${label} relay transcript signature is invalid`);
		return failures;
	}
	const response = RollbackRelayStateBodySchema.safeParse(safeParseJson(transcript.responseBody));
	if (!response.success) {
		failures.push(`rollback ${label} relay transcript response body is invalid`);
		return failures;
	}
	if (response.data.effectiveValue !== expected.effectiveValue) {
		failures.push(
			`rollback ${label} relay transcript effectiveValue is ${response.data.effectiveValue}`,
		);
	}
	if (expected.effectiveMode && response.data.effectiveMode !== expected.effectiveMode) {
		failures.push(
			`rollback ${label} relay transcript effectiveMode is ${response.data.effectiveMode}`,
		);
	}
	if (expected.controlMode && response.data.controlMode !== expected.controlMode) {
		failures.push(`rollback ${label} relay transcript controlMode is ${response.data.controlMode}`);
	}
	if (expected.controlSource && response.data.controlSource !== expected.controlSource) {
		failures.push(
			`rollback ${label} relay transcript controlSource is ${response.data.controlSource}`,
		);
	}
	if (label === "before" && response.data.effectiveValue !== evidence.observedBeforeValue) {
		failures.push("rollback before relay transcript does not match observedBeforeValue");
	}
	if (label === "after" && response.data.effectiveValue !== evidence.observedAfterValue) {
		failures.push("rollback after relay transcript does not match observedAfterValue");
	}
	if (
		label === "afterControl" &&
		response.data.controlSource !== evidence.observedAfterControlSource
	) {
		failures.push(
			"rollback afterControl relay transcript does not match observedAfterControlSource",
		);
	}
	return failures;
}

function safeParseJson(value: string): unknown {
	try {
		return JSON.parse(value) as unknown;
	} catch {
		return undefined;
	}
}

function readRollbackRehearsalEvidence(
	rollbackRehearsal: RollbackRehearsal,
): { valid: true; evidence: RollbackRehearsal } | { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(rollbackRehearsal.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing rollback rehearsal evidence: ${redactDetail(resolvedPath)}`,
		};
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable rollback rehearsal evidence: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}
	const parsed = RollbackRehearsalSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid rollback rehearsal evidence: ${redactDetail(
				flattenZodError(parsed.error),
			)}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function networkProbeEvidenceFailures(probe: ProbeBundle["probes"][number]): string[] {
	const failures =
		probe.status === "pass" ? [] : [`network probe ${probe.id} status is ${probe.status}`];
	const loaded = readNetworkProbeEvidence(probe);
	if (!loaded.valid) return [...failures, loaded.failure];

	const evidence = loaded.evidence;
	if (evidence.id !== probe.id) {
		failures.push(`network probe evidence ${probe.id} id is ${redactDetail(evidence.id)}`);
	}
	if (!sameResolvedArtifactPath(evidence.evidence_path, probe.evidence_path)) {
		failures.push(
			`network probe evidence ${probe.id} evidence_path is ${redactDetail(evidence.evidence_path)}`,
		);
	}
	if (evidence.status !== "pass") {
		failures.push(`network probe evidence ${probe.id} status is ${evidence.status}`);
	}
	if (evidence.ran !== true) {
		failures.push(`network probe evidence ${probe.id} ran is ${String(evidence.ran)}`);
	}
	if (evidence.attempts.length === 0) {
		failures.push(`network probe evidence ${probe.id} attempts are empty`);
	}
	if (
		REQUIRED_CUTOVER_NETWORK_PROBE_ID_SET.has(probe.id) &&
		!hasPassingFirewallSentinel(evidence)
	) {
		failures.push(
			`network probe evidence ${probe.id} firewall_sentinel attempt is missing or not pass`,
		);
	}
	if (probe.id === "network.dns-exfil-denied" && !hasNonOverridableDnsGuard(evidence)) {
		failures.push(
			`network probe evidence ${probe.id} dns_guard lacks nonOverridable resolved address`,
		);
	}
	for (const attempt of evidence.attempts) {
		if (attempt.status === "pass") continue;
		failures.push(
			`network probe evidence ${probe.id} attempt ${redactDetail(
				attempt.name,
			)} status is ${attempt.status}: ${redactDetail(attempt.detail)}`,
		);
	}
	return failures;
}

function hasPassingFirewallSentinel(evidence: z.infer<typeof NetworkProbeEvidenceSchema>): boolean {
	return evidence.attempts.some(
		(attempt) => attempt.kind === "firewall_sentinel" && attempt.status === "pass",
	);
}

function hasNonOverridableDnsGuard(evidence: z.infer<typeof NetworkProbeEvidenceSchema>): boolean {
	return evidence.attempts.some(
		(attempt) =>
			attempt.kind === "dns_guard" &&
			attempt.resolvedAddresses?.some((address) => address.nonOverridable) === true,
	);
}

function readNetworkProbeEvidence(
	probe: ProbeBundle["probes"][number],
):
	| { valid: true; evidence: z.infer<typeof NetworkProbeEvidenceSchema> }
	| { valid: false; failure: string } {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return {
			valid: false,
			failure: `missing network probe evidence ${probe.id}: ${redactDetail(resolvedPath)}`,
		};
	}

	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return {
			valid: false,
			failure: `unreadable network probe evidence ${probe.id}: ${redactDetail(
				error instanceof Error ? error.message : String(error),
			)}`,
		};
	}

	const parsed = NetworkProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			valid: false,
			failure: `invalid network probe evidence ${probe.id}: ${redactDetail(
				flattenZodError(parsed.error),
			)}`,
		};
	}
	return { valid: true, evidence: parsed.data };
}

function sameResolvedArtifactPath(left: string, right: string): boolean {
	return resolveHermesArtifactPath(left) === resolveHermesArtifactPath(right);
}

function redactDetail(detail: string): string {
	return redactSecrets(detail).replace(/\s+/g, " ").trim();
}

function placeholderFailures(label: string, value: unknown): string[] {
	const failures: string[] = [];
	collectPlaceholderFailures(label, value, failures);
	return failures;
}

function collectPlaceholderFailures(label: string, value: unknown, failures: string[]): void {
	if (typeof value === "string") {
		const normalized = value.trim().toLowerCase();
		if (PLACEHOLDER_VALUES.has(normalized) || normalized.startsWith("todo:")) {
			failures.push(`${label} is placeholder: ${redactDetail(value)}`);
		}
		return;
	}
	if (Array.isArray(value)) {
		value.forEach((item, index) => {
			collectPlaceholderFailures(`${label}[${index}]`, item, failures);
		});
		return;
	}
	if (typeof value !== "object" || value === null) return;
	for (const [key, nested] of Object.entries(value)) {
		collectPlaceholderFailures(`${label}.${key}`, nested, failures);
	}
}

function collectCliHeadlessProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	if (!fs.existsSync(resolvedPath)) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}
	let evidence: unknown;
	try {
		evidence = readJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${String(
				error instanceof Error ? error.message : error,
			)}`,
		);
	}

	const parsed = CliHeadlessProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (parsed.data.exitCode !== 0) failures.push(`exitCode is ${parsed.data.exitCode}`);
	if (parsed.data.findings.length > 0) {
		failures.push(`findings are not empty (${parsed.data.findings.length})`);
	}
	const forbiddenEnvKeys = parsed.data.invocation.envKeys
		.filter(isForbiddenCredentialKey)
		.sort((left, right) => left.localeCompare(right));
	if (forbiddenEnvKeys.length > 0) {
		failures.push(`forbidden credential envKeys: ${redactDetail(forbiddenEnvKeys.join(", "))}`);
	}
	if (failures.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${failures.join("; ")}`,
		);
	}

	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed pass, ran=true, exitCode=0`,
	};
}

function collectServedMcpContainmentProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	const report = evaluateServedMcpContainmentEvidence(evidence, { missingPath: resolvedPath });
	const failingGates = report.gates.filter((gate) => gate.status !== "pass");
	if (report.status !== "pass" || !report.productionEnable || failingGates.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			failingGates.map((gate) => gate.detail).join("; ") ||
				`served-MCP containment evidence status is ${report.status}`,
		);
	}
	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed all served-MCP containment properties`,
	};
}

function collectApiServerContainmentProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}

	const parsed = ApiServerContainmentProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures: string[] = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (parsed.data.findings.length > 0) {
		failures.push(`findings are not empty (${parsed.data.findings.length})`);
	}

	const gateByName = new Map(parsed.data.gates.map((gate) => [gate.name, gate]));
	for (const gateName of REQUIRED_API_SERVER_CONTAINMENT_GATES) {
		const gate = gateByName.get(gateName);
		if (!gate) {
			failures.push(`gate ${gateName} is missing`);
		} else if (gate.status !== "pass") {
			failures.push(`gate ${gateName} is ${gate.status}: ${redactDetail(gate.detail)}`);
		}
	}
	if (failures.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${failures.join("; ")}`,
		);
	}

	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed live API-server containment gates`,
	};
}

function collectModelRelayProbeEvidence(
	probe: FeatureProbeMatrix["probes"][number],
): FeatureProbeEvidenceBundle["results"][number] {
	const resolvedPath = resolveHermesArtifactPath(probe.evidence_path);
	let evidence: unknown;
	try {
		evidence = readOptionalJsonFile(resolvedPath);
	} catch (error) {
		return featureProbeEvidenceFailure(
			probe,
			`unreadable feature probe evidence ${probe.surface_id}: ${redactDetail(
				String(error instanceof Error ? error.message : error),
			)}`,
		);
	}
	if (evidence === undefined) {
		return featureProbeEvidenceFailure(
			probe,
			`missing feature probe evidence ${probe.surface_id}: ${resolvedPath}`,
		);
	}

	const parsed = ModelRelayProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return featureProbeEvidenceFailure(
			probe,
			`invalid feature probe evidence ${probe.surface_id}: ${flattenZodError(parsed.error)}`,
		);
	}

	const failures: string[] = [];
	if (parsed.data.status !== "pass") failures.push(`status is ${parsed.data.status}`);
	if (parsed.data.ran !== true) failures.push(`ran is ${String(parsed.data.ran)}`);
	if (!parsed.data.observation.relayUrl) {
		failures.push("observation.relayUrl is missing");
	} else if (isDirectModelRelayProviderUrl(parsed.data.observation.relayUrl)) {
		failures.push("observation.relayUrl points at a direct model-provider host");
	}
	if (!isDirectModelRelayProviderUrl(parsed.data.observation.directModelUrl)) {
		failures.push("observation.directModelUrl is not a recognized direct model-provider URL");
	}
	const origin = parsed.data.origin;
	if (origin.kind === "relay-self-smoke") {
		failures.push("origin is relay-self-smoke");
	}
	const originMatches =
		origin.kind === "contained-peer" &&
		origin.containerName === "tc-hermes-contained" &&
		origin.observedPeerAddress !== undefined &&
		origin.expectedPeerAddress !== undefined &&
		origin.observedPeerSource === "server-peer-echo" &&
		origin.expectedPeerSource === "configured-contained-ip" &&
		net.isIP(origin.observedPeerAddress) !== 0 &&
		net.isIP(origin.expectedPeerAddress) !== 0 &&
		origin.observedPeerAddress === origin.expectedPeerAddress;
	if (!originMatches) {
		failures.push(
			"origin is not a server-observed tc-hermes-contained peer matching the configured contained IP",
		);
	}
	if (!parsed.data.observation.profileDir) {
		failures.push("observation.profileDir is missing");
	}
	if ((parsed.data.observation.scannedProfileFiles ?? []).length === 0) {
		failures.push("observation.scannedProfileFiles is empty");
	}

	const gateByName = new Map(parsed.data.gates.map((gate) => [gate.name, gate]));
	for (const gateName of REQUIRED_MODEL_RELAY_GATES) {
		const gate = gateByName.get(gateName);
		if (!gate) {
			failures.push(`gate ${gateName} is missing`);
		} else if (gate.status !== "pass") {
			failures.push(`gate ${gateName} is ${gate.status}: ${redactDetail(gate.detail)}`);
		}
	}
	if (failures.length > 0) {
		return featureProbeEvidenceFailure(
			probe,
			`feature probe evidence ${probe.surface_id} did not pass: ${failures.join("; ")}`,
		);
	}

	return {
		surface_id: probe.surface_id,
		status: "pass",
		evidence_path: probe.evidence_path,
		detail: `feature probe evidence ${probe.surface_id} observed model relay reachability, direct-model denial, and profile credential absence`,
	};
}

function isDirectModelRelayProviderUrl(value: string): boolean {
	try {
		return DIRECT_MODEL_RELAY_PROVIDER_HOSTS.has(new URL(value).hostname.toLowerCase());
	} catch {
		return false;
	}
}

function isForbiddenCredentialKey(key: string): boolean {
	return /(^|_)(API_KEY|AUTH_TOKEN|OAUTH_TOKEN|TOKEN|KEY|PASSWORD|SECRET|COOKIE|CREDENTIALS?)(_|$)/i.test(
		key,
	);
}

function featureProbeEvidenceFailure(
	probe: FeatureProbeMatrix["probes"][number],
	detail: string,
): FeatureProbeEvidenceBundle["results"][number] {
	return {
		surface_id: probe.surface_id,
		status: "fail",
		evidence_path: probe.evidence_path,
		detail,
	};
}

function featureProbeFailure(
	probe: FeatureProbeMatrix["probes"][number],
	evidence: FeatureProbeEvidenceBundle["results"][number] | undefined,
): string | null {
	if (evidence) {
		return evidence.status === "pass"
			? null
			: `feature probe ${probe.surface_id} evidence failed: ${evidence.detail}`;
	}
	if (FEATURE_PROBE_SURFACES_REQUIRING_OBSERVED_EVIDENCE.has(probe.surface_id)) {
		return `feature probe ${probe.surface_id} requires observed evidence`;
	}
	if (probe.status !== "pass") {
		return `feature probe ${probe.surface_id} status is ${probe.status ?? "missing"}`;
	}
	return null;
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
	const parsed = InventoryQueueEvidenceSchema.safeParse(inventory);
	if (!parsed.success) {
		throw new Error(
			`inventory queue evidence is missing or incomplete: ${flattenZodError(parsed.error)}`,
		);
	}
	const unownedActiveCount = Object.values(parsed.data.summary.pendingQueues).reduce<number>(
		(total, value) => total + value,
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
