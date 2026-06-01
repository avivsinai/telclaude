import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { sortKeysDeep } from "../crypto/canonical-hash.js";
import { createHermesWorkflowRunLedger } from "./workflow-run-ledger.js";
import {
	HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_RUNNER,
	HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCHEMA_VERSION,
	HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SOURCE,
	type HermesWorkflowRunLedgerAttestation,
	hermesWorkflowRunLedgerAttestationFieldsForEvidence,
	hermesWorkflowRunLedgerAttestationSignatureFailure,
	signHermesWorkflowRunLedgerAttestation,
} from "./workflow-run-ledger-attestation.js";

export const HERMES_WORKFLOW_PROBE_SCHEMA_VERSION = "telclaude.hermes.workflow-probe.v1";
export const HERMES_WORKFLOW_PROBE_SOURCE = "telclaude-workflow-run-ledger-harness";
export const HERMES_WORKFLOW_FIXTURE_EVIDENCE_SCHEMA_VERSION =
	"telclaude.hermes.workflow-fixture-evidence.v1";
export const HERMES_WORKFLOW_FIXTURE_SOURCE = "machine-observed-workflow-probe";
export const HERMES_WORKFLOW_FIXTURE_RUNNER = "telclaude-workflow-fixture-generator";
export const DEFAULT_HERMES_WORKFLOW_FIXTURE_EVIDENCE_DIR = "artifacts/hermes/fixtures";

export const HERMES_WORKFLOW_SURFACE_IDS = ["workflow.cron", "workflow.longrun"] as const;
export type HermesWorkflowSurfaceId = (typeof HERMES_WORKFLOW_SURFACE_IDS)[number];

export const DEFAULT_HERMES_WORKFLOW_EVIDENCE_PATHS: Record<HermesWorkflowSurfaceId, string> = {
	"workflow.cron": "artifacts/hermes/probes/workflow-cron.json",
	"workflow.longrun": "artifacts/hermes/probes/workflow-longrun.json",
};

const NonEmptyString = z.string().trim().min(1);
const Sha256Digest = z.string().regex(/^sha256:[a-f0-9]{64}$/i);
const HexSha256Digest = z.string().regex(/^[a-f0-9]{64}$/);

const WorkflowProbeCheckSchema = z
	.object({
		name: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		detail: NonEmptyString,
	})
	.strict();

const WorkflowProbeObservationSchema = z
	.object({
		workflowRunId: NonEmptyString.optional(),
		idempotencyKey: NonEmptyString.optional(),
		startRecordHash: Sha256Digest.optional(),
		duplicateRecordHash: Sha256Digest.optional(),
		completedRecordHash: Sha256Digest.optional(),
		approvalWaitRecordHash: Sha256Digest.optional(),
		resumedRecordHash: Sha256Digest.optional(),
		staleFailureHash: Sha256Digest.optional(),
		retryRecordHash: Sha256Digest.optional(),
		cancelledRecordHash: Sha256Digest.optional(),
		terminalDenialCode: NonEmptyString.optional(),
	})
	.strict();

const InternalResponseProofSchema = z
	.object({
		version: z.literal("v1"),
		scope: NonEmptyString,
		timestamp: NonEmptyString,
		nonce: NonEmptyString,
		method: NonEmptyString,
		path: NonEmptyString,
		requestBodySha256: HexSha256Digest,
		responseBodySha256: HexSha256Digest,
		signature: NonEmptyString,
	})
	.strict();

const HermesWorkflowRunLedgerAttestationSchema = z
	.object({
		schemaVersion: z.literal(HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SCHEMA_VERSION),
		source: z.literal(HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_SOURCE),
		runner: z.literal(HERMES_WORKFLOW_RUN_LEDGER_ATTESTATION_RUNNER),
		probeEvidenceSchemaVersion: z.literal(HERMES_WORKFLOW_PROBE_SCHEMA_VERSION),
		probeId: z.enum(HERMES_WORKFLOW_SURFACE_IDS),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		evidenceSource: z.literal(HERMES_WORKFLOW_PROBE_SOURCE),
		checksSha256: Sha256Digest,
		observationsSha256: Sha256Digest,
		evidenceSha256: Sha256Digest,
		signature: InternalResponseProofSchema,
	})
	.strict();

export const HermesWorkflowProbeEvidenceSchema = z
	.object({
		schemaVersion: z.literal(HERMES_WORKFLOW_PROBE_SCHEMA_VERSION),
		probeId: z.enum(HERMES_WORKFLOW_SURFACE_IDS),
		status: z.enum(["pass", "fail"]),
		ran: z.boolean(),
		observedAt: NonEmptyString,
		source: z.literal(HERMES_WORKFLOW_PROBE_SOURCE),
		summary: NonEmptyString,
		checks: z.array(WorkflowProbeCheckSchema).min(1),
		observations: WorkflowProbeObservationSchema,
		runnerAttestation: HermesWorkflowRunLedgerAttestationSchema.optional(),
	})
	.strict();

export type HermesWorkflowProbeEvidence = z.infer<typeof HermesWorkflowProbeEvidenceSchema>;
type WorkflowProbeCheck = z.infer<typeof WorkflowProbeCheckSchema>;
type WorkflowProbeObservation = z.infer<typeof WorkflowProbeObservationSchema>;

const WORKFLOW_REQUIRED_CHECKS: Record<HermesWorkflowSurfaceId, readonly string[]> = {
	"workflow.cron": [
		"workflow.cron.server-derived-authority",
		"workflow.cron.background-delivery-completed",
		"workflow.cron.duplicate-delivery-deduped",
	],
	"workflow.longrun": [
		"workflow.longrun.approval-waiter-bound",
		"workflow.longrun.approval-resume-resolved",
		"workflow.longrun.stale-resume-denied",
		"workflow.longrun.retry-backoff-recorded",
		"workflow.longrun.cancellation-terminal",
	],
};

type WorkflowFixtureRequirement = {
	readonly id: string;
	readonly surfaceId: HermesWorkflowSurfaceId;
	readonly requiredChecks: readonly string[];
	readonly requiredObservationHashes: readonly (keyof WorkflowProbeObservation)[];
};

export const HERMES_WORKFLOW_FIXTURE_REQUIREMENTS = [
	{
		id: "fixture.cron.background.delivery",
		surfaceId: "workflow.cron",
		requiredChecks: [
			"workflow.cron.server-derived-authority",
			"workflow.cron.background-delivery-completed",
		],
		requiredObservationHashes: ["startRecordHash", "completedRecordHash"],
	},
	{
		id: "fixture.cron.duplicate-deny",
		surfaceId: "workflow.cron",
		requiredChecks: ["workflow.cron.duplicate-delivery-deduped"],
		requiredObservationHashes: ["duplicateRecordHash"],
	},
	{
		id: "fixture.longrun.approval-resume",
		surfaceId: "workflow.longrun",
		requiredChecks: [
			"workflow.longrun.approval-waiter-bound",
			"workflow.longrun.approval-resume-resolved",
		],
		requiredObservationHashes: ["approvalWaitRecordHash", "resumedRecordHash"],
	},
	{
		id: "fixture.longrun.stale-resume-deny",
		surfaceId: "workflow.longrun",
		requiredChecks: ["workflow.longrun.stale-resume-denied"],
		requiredObservationHashes: ["staleFailureHash"],
	},
] as const satisfies readonly WorkflowFixtureRequirement[];

export type HermesWorkflowFixtureId = (typeof HERMES_WORKFLOW_FIXTURE_REQUIREMENTS)[number]["id"];

export function isHermesWorkflowSurfaceId(value: string): value is HermesWorkflowSurfaceId {
	return HERMES_WORKFLOW_SURFACE_IDS.some((surfaceId) => surfaceId === value);
}

export function runHermesWorkflowProbe(input: {
	readonly surfaceId: HermesWorkflowSurfaceId;
	readonly allowRun: boolean;
	readonly observedAt?: string;
}): HermesWorkflowProbeEvidence {
	const observedAt = input.observedAt ?? new Date().toISOString();
	if (input.allowRun !== true) {
		return {
			schemaVersion: HERMES_WORKFLOW_PROBE_SCHEMA_VERSION,
			probeId: input.surfaceId,
			status: "fail",
			ran: false,
			observedAt,
			source: HERMES_WORKFLOW_PROBE_SOURCE,
			summary: `${input.surfaceId} workflow harness was not allowed to run`,
			checks: [
				{
					name: WORKFLOW_REQUIRED_CHECKS[input.surfaceId][0] ?? `${input.surfaceId}.allow-run`,
					status: "fail",
					detail: "run with --allow-run to execute the deterministic workflow ledger harness",
				},
			],
			observations: {},
		};
	}
	return input.surfaceId === "workflow.cron"
		? runCronWorkflowProbe(input.surfaceId, observedAt)
		: runLongrunWorkflowProbe(input.surfaceId, observedAt);
}

export function workflowProbeEvidenceFailure(
	surfaceId: HermesWorkflowSurfaceId,
	evidence: unknown,
): string | null {
	const parsed = HermesWorkflowProbeEvidenceSchema.safeParse(evidence);
	if (!parsed.success) return `invalid workflow evidence: ${flattenZodError(parsed.error)}`;
	const data = parsed.data;
	const failures: string[] = [];
	if (data.probeId !== surfaceId) failures.push(`probeId is ${data.probeId}`);
	if (data.status !== "pass") failures.push(`status is ${data.status}`);
	if (data.ran !== true) failures.push("harness did not run");
	if (data.source !== HERMES_WORKFLOW_PROBE_SOURCE) failures.push(`source is ${data.source}`);
	const attestationFailure = workflowRunLedgerRunnerAttestationFailure(data);
	if (attestationFailure) failures.push(attestationFailure);
	const checksByName = new Map(data.checks.map((check) => [check.name, check]));
	for (const duplicate of duplicates(data.checks.map((check) => check.name))) {
		failures.push(`duplicate check ${duplicate}`);
	}
	for (const name of WORKFLOW_REQUIRED_CHECKS[surfaceId]) {
		const check = checksByName.get(name);
		if (!check) failures.push(`check ${name} is missing`);
		else if (check.status !== "pass") failures.push(`check ${name} is ${check.status}`);
	}
	if (surfaceId === "workflow.cron") {
		for (const field of [
			"startRecordHash",
			"duplicateRecordHash",
			"completedRecordHash",
		] as const) {
			if (!data.observations[field]) failures.push(`${field} is missing`);
		}
	} else {
		for (const field of [
			"approvalWaitRecordHash",
			"resumedRecordHash",
			"staleFailureHash",
			"retryRecordHash",
			"cancelledRecordHash",
		] as const) {
			if (!data.observations[field]) failures.push(`${field} is missing`);
		}
		if (data.observations.terminalDenialCode !== "run_terminal") {
			failures.push(`terminalDenialCode is ${String(data.observations.terminalDenialCode)}`);
		}
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function workflowRunLedgerRunnerAttestationFailure(
	data: HermesWorkflowProbeEvidence,
): string | null {
	const attestation = data.runnerAttestation as HermesWorkflowRunLedgerAttestation | undefined;
	if (!attestation) return "runnerAttestation is missing";
	const signatureFailure = hermesWorkflowRunLedgerAttestationSignatureFailure(attestation, {
		allowStale: true,
	});
	if (signatureFailure) return `runnerAttestation signature is invalid: ${signatureFailure}`;
	const expected = hermesWorkflowRunLedgerAttestationFieldsForEvidence(data);
	for (const field of [
		"probeEvidenceSchemaVersion",
		"probeId",
		"status",
		"ran",
		"observedAt",
		"evidenceSource",
		"checksSha256",
		"observationsSha256",
		"evidenceSha256",
	] as const) {
		if (attestation[field] !== expected[field]) {
			return `runnerAttestation ${field} mismatch`;
		}
	}
	return null;
}

const WorkflowFixtureEvidenceSchema = z
	.object({
		schemaVersion: z.literal(HERMES_WORKFLOW_FIXTURE_EVIDENCE_SCHEMA_VERSION),
		id: NonEmptyString,
		status: z.enum(["pass", "fail"]),
		ran: z.literal(true),
		evidence_path: NonEmptyString,
		observedAt: NonEmptyString,
		provenance: z
			.object({
				runner: z.literal(HERMES_WORKFLOW_FIXTURE_RUNNER),
				source: z.literal(HERMES_WORKFLOW_FIXTURE_SOURCE),
				command: NonEmptyString,
				probeId: z.enum(HERMES_WORKFLOW_SURFACE_IDS),
				probePath: NonEmptyString,
				probeSha256: Sha256Digest,
			})
			.strict(),
		workflow: z
			.object({
				surfaceId: z.enum(HERMES_WORKFLOW_SURFACE_IDS),
				requiredProbeChecks: z.array(NonEmptyString).min(1),
				requiredObservationHashes: z.array(NonEmptyString),
			})
			.strict(),
		checks: z.array(WorkflowProbeCheckSchema).min(1),
	})
	.strict();

type WorkflowFixtureEvidence = z.infer<typeof WorkflowFixtureEvidenceSchema>;

export function buildHermesWorkflowFixtureEvidenceBundle(
	input: {
		readonly evidenceDir?: string;
		readonly observedAt?: string;
		readonly probePaths?: Partial<Record<HermesWorkflowSurfaceId, string>>;
	} = {},
): {
	readonly schemaVersion: 1;
	readonly results: readonly {
		readonly id: HermesWorkflowFixtureId;
		readonly status: "pass" | "fail";
		readonly evidence_path: string;
	}[];
	readonly evidence: readonly WorkflowFixtureEvidence[];
} {
	const evidenceDir = input.evidenceDir ?? DEFAULT_HERMES_WORKFLOW_FIXTURE_EVIDENCE_DIR;
	const probeCache = new Map<
		HermesWorkflowSurfaceId,
		{
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: HermesWorkflowProbeEvidence;
			readonly failure?: string;
		}
	>();
	const evidence = HERMES_WORKFLOW_FIXTURE_REQUIREMENTS.map((requirement) =>
		buildWorkflowFixtureEvidence(requirement, {
			evidenceDir,
			observedAt: input.observedAt,
			probePath:
				input.probePaths?.[requirement.surfaceId] ??
				DEFAULT_HERMES_WORKFLOW_EVIDENCE_PATHS[requirement.surfaceId],
			probeCache,
		}),
	);
	return {
		schemaVersion: 1,
		results: evidence.map((item) => ({
			id: item.id as HermesWorkflowFixtureId,
			status: item.status,
			evidence_path: item.evidence_path,
		})),
		evidence,
	};
}

export function workflowFixtureEvidenceFailure(
	fixtureId: string,
	evidence: unknown,
): string | null {
	const requirement = HERMES_WORKFLOW_FIXTURE_REQUIREMENTS.find(
		(candidate) => candidate.id === fixtureId,
	);
	if (!requirement) return null;
	const parsed = WorkflowFixtureEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return `invalid workflow fixture evidence ${fixtureId}: ${flattenZodError(parsed.error)}`;
	}
	const data = parsed.data;
	const failures: string[] = [];
	if (data.id !== fixtureId) failures.push(`fixture evidence id is ${data.id}`);
	if (data.status !== "pass") failures.push(`fixture evidence status is ${data.status}`);
	if (data.workflow.surfaceId !== requirement.surfaceId) {
		failures.push(`fixture surfaceId is ${data.workflow.surfaceId}`);
	}
	if (data.provenance.probeId !== requirement.surfaceId) {
		failures.push(`fixture probeId is ${data.provenance.probeId}`);
	}
	if (
		JSON.stringify(data.workflow.requiredProbeChecks) !== JSON.stringify(requirement.requiredChecks)
	) {
		failures.push("fixture requiredProbeChecks do not match workflow contract");
	}
	if (
		JSON.stringify(data.workflow.requiredObservationHashes) !==
		JSON.stringify(requirement.requiredObservationHashes)
	) {
		failures.push("fixture requiredObservationHashes do not match workflow contract");
	}
	const probe = readWorkflowProbeArtifact(data.provenance.probePath, requirement.surfaceId);
	if (probe.sha256 !== data.provenance.probeSha256) {
		failures.push("fixture probeSha256 does not match workflow probe artifact");
	}
	if (probe.failure) {
		failures.push(`fixture probe artifact failed validation: ${probe.failure}`);
	} else if (probe.evidence) {
		failures.push(...workflowFixtureContractFailures(requirement, data, probe.evidence));
	}
	return failures.length > 0 ? failures.join("; ") : null;
}

function runCronWorkflowProbe(
	surfaceId: HermesWorkflowSurfaceId,
	observedAt: string,
): HermesWorkflowProbeEvidence {
	const checks: WorkflowProbeCheck[] = [];
	const observations: WorkflowProbeObservation = {};
	let nowMs = 1_000;
	const ledger = createWorkflowLedger(() => nowMs, "cron-run");
	const startInput = cronStartInput();
	const started = ledger.start(startInput);
	const duplicate = ledger.start(startInput);
	const checkpointed = started.ok
		? ledger.checkpoint(started.record.workflowRunId, {
				checkpointId: "cron-delivered",
				summary: "Background cron delivery completed through Telclaude workflow runner",
				stateRef: "artifact:cron-delivery",
			})
		: started;
	nowMs += 500;
	const completed = started.ok ? ledger.complete(started.record.workflowRunId) : started;

	if (started.ok) {
		observations.workflowRunId = started.record.workflowRunId;
		observations.idempotencyKey = started.record.idempotencyKey;
		observations.startRecordHash = hashJson(started.record);
	}
	if (duplicate.ok) observations.duplicateRecordHash = hashJson(duplicate.record);
	if (completed.ok) observations.completedRecordHash = hashJson(completed.record);

	pushCheck(
		checks,
		"workflow.cron.server-derived-authority",
		started.ok &&
			started.record.authorityActorSource === "server-derived" &&
			started.record.authorityActor === "actor:operator" &&
			started.record.profileId === "tc-private-default" &&
			started.record.scope.includes("cron.run") &&
			started.record.budget.maxRuntimeMs === 120_000,
		"Cron workflow run records server-derived authority, scope, profile, freshness, and budget",
	);
	pushCheck(
		checks,
		"workflow.cron.background-delivery-completed",
		checkpointed.ok &&
			completed.ok &&
			completed.record.status === "completed" &&
			completed.record.checkpoints.some(
				(checkpoint) => checkpoint.checkpointId === "cron-delivered",
			),
		"Cron background delivery persists a checkpoint and terminal completed status",
	);
	pushCheck(
		checks,
		"workflow.cron.duplicate-delivery-deduped",
		started.ok &&
			duplicate.ok &&
			duplicate.duplicate === true &&
			duplicate.record.workflowRunId === started.record.workflowRunId,
		"Duplicate cron delivery is deduplicated by immutable idempotency key",
	);

	return workflowProbeReport(surfaceId, observedAt, checks, observations);
}

function runLongrunWorkflowProbe(
	surfaceId: HermesWorkflowSurfaceId,
	observedAt: string,
): HermesWorkflowProbeEvidence {
	const checks: WorkflowProbeCheck[] = [];
	const observations: WorkflowProbeObservation = {};
	let nowMs = 1_000;
	const ledger = createWorkflowLedger(() => nowMs, "longrun");
	const started = ledger.start(
		longrunStartInput({ idempotencyKey: "longrun:approval:2026-06-01" }),
	);
	const waiting = started.ok
		? ledger.waitForApproval(started.record.workflowRunId, {
				approvalRequestId: "approval-longrun-1",
				authorityActor: "actor:operator",
				sideEffectLedgerRef: "effect:provider-write:1",
				expiresAtMs: 4_000,
			})
		: started;
	nowMs += 250;
	const resumed = started.ok ? ledger.resume(started.record.workflowRunId) : started;

	if (waiting.ok) observations.approvalWaitRecordHash = hashJson(waiting.record);
	if (resumed.ok) observations.resumedRecordHash = hashJson(resumed.record);

	pushCheck(
		checks,
		"workflow.longrun.approval-waiter-bound",
		waiting.ok &&
			waiting.record.status === "waiting_approval" &&
			waiting.record.approvalWaiters.some(
				(waiter) =>
					waiter.approvalRequestId === "approval-longrun-1" &&
					waiter.authorityActor === "actor:operator" &&
					waiter.sideEffectLedgerRef === "effect:provider-write:1" &&
					waiter.status === "open",
			),
		"Long-running workflow records an authority-bound approval waiter and side-effect ref",
	);
	pushCheck(
		checks,
		"workflow.longrun.approval-resume-resolved",
		resumed.ok &&
			resumed.record.status === "running" &&
			resumed.record.approvalWaiters.every((waiter) => waiter.status === "resolved"),
		"Long-running workflow resumes only from ledger state and resolves open approval waiters",
	);

	let staleNowMs = 1_000;
	const staleLedger = createWorkflowLedger(() => staleNowMs, "stale-longrun");
	const staleStarted = staleLedger.start(
		longrunStartInput({
			idempotencyKey: "longrun:stale:2026-06-01",
			freshnessDeadlineMs: 1_500,
		}),
	);
	staleNowMs = 2_000;
	const staleResume = staleStarted.ok
		? staleLedger.resume(staleStarted.record.workflowRunId)
		: staleStarted;
	if (!staleResume.ok && staleResume.record) {
		observations.staleFailureHash = hashJson(staleResume.record);
	}
	pushCheck(
		checks,
		"workflow.longrun.stale-resume-denied",
		!staleResume.ok &&
			staleResume.code === "freshness_deadline_expired" &&
			staleResume.record?.status === "failed",
		"Long-running workflow refuses stale resume and records a non-retryable ledger failure",
	);

	const retryStarted = ledger.start(
		longrunStartInput({ idempotencyKey: "longrun:retry:2026-06-01" }),
	);
	const retry = retryStarted.ok
		? ledger.scheduleRetry(retryStarted.record.workflowRunId, {
				reason: "provider timeout",
				retryAfterMs: 10_000,
				backoffMs: 2_000,
			})
		: retryStarted;
	if (retry.ok) observations.retryRecordHash = hashJson(retry.record);
	pushCheck(
		checks,
		"workflow.longrun.retry-backoff-recorded",
		retry.ok &&
			retry.record.status === "retry_scheduled" &&
			retry.record.retry?.reason === "provider timeout" &&
			retry.record.retry.backoffMs === 2_000,
		"Long-running workflow records retry/backoff in the same workflow-run ledger record",
	);

	const cancelStarted = ledger.start(
		longrunStartInput({ idempotencyKey: "longrun:cancel:2026-06-01" }),
	);
	const cancelled = cancelStarted.ok
		? ledger.cancel(cancelStarted.record.workflowRunId, {
				cancelledBy: "actor:operator",
				reason: "operator stopped the workflow",
			})
		: cancelStarted;
	const afterCancel = cancelStarted.ok
		? ledger.checkpoint(cancelStarted.record.workflowRunId, {
				checkpointId: "after-cancel",
				summary: "must not persist",
			})
		: cancelStarted;
	if (cancelled.ok) observations.cancelledRecordHash = hashJson(cancelled.record);
	if (!afterCancel.ok) observations.terminalDenialCode = afterCancel.code;
	pushCheck(
		checks,
		"workflow.longrun.cancellation-terminal",
		cancelled.ok &&
			cancelled.record.status === "cancelled" &&
			!afterCancel.ok &&
			afterCancel.code === "run_terminal",
		"Cancelled long-running workflows reject later checkpoints as terminal ledger records",
	);

	return workflowProbeReport(surfaceId, observedAt, checks, observations);
}

function buildWorkflowFixtureEvidence(
	requirement: (typeof HERMES_WORKFLOW_FIXTURE_REQUIREMENTS)[number],
	options: {
		readonly evidenceDir: string;
		readonly observedAt?: string;
		readonly probePath: string;
		readonly probeCache: Map<
			HermesWorkflowSurfaceId,
			{
				readonly path: string;
				readonly sha256: string;
				readonly evidence?: HermesWorkflowProbeEvidence;
				readonly failure?: string;
			}
		>;
	},
): WorkflowFixtureEvidence {
	const probe = cachedWorkflowProbeArtifact(
		options.probeCache,
		requirement.surfaceId,
		options.probePath,
	);
	const checks = buildWorkflowFixtureChecks(requirement, probe.evidence, probe.failure);
	const status =
		probe.failure === undefined && checks.every((check) => check.status === "pass")
			? "pass"
			: "fail";
	return {
		schemaVersion: HERMES_WORKFLOW_FIXTURE_EVIDENCE_SCHEMA_VERSION,
		id: requirement.id,
		status,
		ran: true,
		evidence_path: path.join(options.evidenceDir, `${requirement.id}.json`),
		observedAt: probe.evidence?.observedAt ?? options.observedAt ?? new Date().toISOString(),
		provenance: {
			runner: HERMES_WORKFLOW_FIXTURE_RUNNER,
			source: HERMES_WORKFLOW_FIXTURE_SOURCE,
			command: "pnpm dev hermes fixtures --include-workflow --write",
			probeId: requirement.surfaceId,
			probePath: options.probePath,
			probeSha256: probe.sha256,
		},
		workflow: {
			surfaceId: requirement.surfaceId,
			requiredProbeChecks: [...requirement.requiredChecks],
			requiredObservationHashes: [...requirement.requiredObservationHashes],
		},
		checks,
	};
}

function buildWorkflowFixtureChecks(
	requirement: (typeof HERMES_WORKFLOW_FIXTURE_REQUIREMENTS)[number],
	probe: HermesWorkflowProbeEvidence | undefined,
	probeFailure: string | undefined,
): WorkflowProbeCheck[] {
	if (!probe || probeFailure) {
		return [
			{
				name: `${requirement.id}.workflow-probe-valid`,
				status: "fail",
				detail: probeFailure ?? "workflow probe evidence is missing",
			},
		];
	}
	const checksByName = new Map(probe.checks.map((check) => [check.name, check]));
	return [
		...requirement.requiredChecks.map((name) => {
			const check = checksByName.get(name);
			return {
				name,
				status: check?.status === "pass" ? "pass" : "fail",
				detail: check?.detail ?? "required workflow probe check is missing",
			} satisfies WorkflowProbeCheck;
		}),
		...requirement.requiredObservationHashes.map(
			(field) =>
				({
					name: `${requirement.id}.${field}`,
					status: probe.observations[field] ? "pass" : "fail",
					detail: probe.observations[field]
						? `workflow probe recorded ${field}`
						: `workflow probe did not record ${field}`,
				}) satisfies WorkflowProbeCheck,
		),
	];
}

function workflowFixtureContractFailures(
	requirement: (typeof HERMES_WORKFLOW_FIXTURE_REQUIREMENTS)[number],
	fixture: WorkflowFixtureEvidence,
	probe: HermesWorkflowProbeEvidence,
): string[] {
	const failures: string[] = [];
	const probeFailure = workflowProbeEvidenceFailure(requirement.surfaceId, probe);
	if (probeFailure) failures.push(probeFailure);
	const probeChecksByName = new Map(probe.checks.map((check) => [check.name, check]));
	const fixtureChecksByName = new Map(fixture.checks.map((check) => [check.name, check]));
	for (const name of requirement.requiredChecks) {
		const probeCheck = probeChecksByName.get(name);
		const fixtureCheck = fixtureChecksByName.get(name);
		if (probeCheck?.status !== "pass") failures.push(`probe check ${name} is not pass`);
		if (fixtureCheck?.status !== "pass") failures.push(`fixture check ${name} is not pass`);
	}
	for (const field of requirement.requiredObservationHashes) {
		if (!probe.observations[field]) failures.push(`probe observation ${field} is missing`);
		const fixtureCheck = fixtureChecksByName.get(`${requirement.id}.${field}`);
		if (fixtureCheck?.status !== "pass") {
			failures.push(`fixture observation check ${field} is not pass`);
		}
	}
	return failures;
}

function cachedWorkflowProbeArtifact(
	cache: Map<
		HermesWorkflowSurfaceId,
		{
			readonly path: string;
			readonly sha256: string;
			readonly evidence?: HermesWorkflowProbeEvidence;
			readonly failure?: string;
		}
	>,
	surfaceId: HermesWorkflowSurfaceId,
	probePath: string,
) {
	const cached = cache.get(surfaceId);
	if (cached?.path === probePath) return cached;
	const read = readWorkflowProbeArtifact(probePath, surfaceId);
	cache.set(surfaceId, read);
	return read;
}

function readWorkflowProbeArtifact(
	probePath: string,
	surfaceId: HermesWorkflowSurfaceId,
): {
	readonly path: string;
	readonly sha256: string;
	readonly evidence?: HermesWorkflowProbeEvidence;
	readonly failure?: string;
} {
	if (!fs.existsSync(probePath)) {
		return {
			path: probePath,
			sha256: hashText(`${probePath}:missing`),
			failure: `missing workflow probe artifact ${probePath}`,
		};
	}
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(probePath, "utf8")) as unknown;
	} catch (error) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `unreadable workflow probe artifact: ${
				error instanceof Error ? error.message : String(error)
			}`,
		};
	}
	const parsed = HermesWorkflowProbeEvidenceSchema.safeParse(raw);
	if (!parsed.success) {
		return {
			path: probePath,
			sha256: hashFile(probePath),
			failure: `invalid workflow probe artifact: ${flattenZodError(parsed.error)}`,
		};
	}
	const semanticFailure = workflowProbeEvidenceFailure(surfaceId, parsed.data);
	return {
		path: probePath,
		sha256: hashFile(probePath),
		evidence: parsed.data,
		...(semanticFailure ? { failure: semanticFailure } : {}),
	};
}

function cronStartInput() {
	return {
		workflowId: "cron.private.daily_brief",
		initiatingActor: "actor:operator",
		authorityActor: "actor:operator",
		authorityActorSource: "server-derived" as const,
		profileId: "tc-private-default",
		domain: "private",
		scope: ["cron.run", "telegram.notify"],
		capabilities: ["session.resume", "message.send"],
		queuedCapabilities: [],
		budget: { maxRuntimeMs: 120_000, maxToolCalls: 12, maxCostUsd: 0.5 },
		freshnessDeadlineMs: 60_000,
		idempotencyKey: "cron.private.daily_brief:2026-06-01T03:00:00Z",
		approvalPolicy: { mode: "none" as const },
		sideEffectLedgerRefs: [],
	};
}

function longrunStartInput(overrides: { idempotencyKey: string; freshnessDeadlineMs?: number }) {
	return {
		workflowId: "longrun.provider.approval_resume",
		initiatingActor: "actor:family-member",
		authorityActor: "actor:operator",
		authorityActorSource: "server-derived" as const,
		profileId: "tc-private-default",
		domain: "household",
		scope: ["provider.google.read", "provider.google.write", "workflow.resume"],
		capabilities: ["mcp.prepare", "mcp.approve", "mcp.execute"],
		queuedCapabilities: ["provider.google.write"],
		budget: { maxRuntimeMs: 600_000, maxToolCalls: 40, maxCostUsd: 2 },
		freshnessDeadlineMs: overrides.freshnessDeadlineMs ?? 10_000,
		idempotencyKey: overrides.idempotencyKey,
		approvalPolicy: {
			mode: "per_side_effect" as const,
			approverActorId: "actor:operator",
			ttlMs: 300_000,
		},
		sideEffectLedgerRefs: [],
	};
}

function createWorkflowLedger(nowMs: () => number, prefix: string) {
	let sequence = 0;
	return createHermesWorkflowRunLedger({
		nowMs,
		makeWorkflowRunId: () => `${prefix}-${++sequence}`,
	});
}

function workflowProbeReport(
	surfaceId: HermesWorkflowSurfaceId,
	observedAt: string,
	checks: WorkflowProbeCheck[],
	observations: WorkflowProbeObservation,
): HermesWorkflowProbeEvidence {
	const status = checks.every((check) => check.status === "pass") ? "pass" : "fail";
	const evidence: Omit<HermesWorkflowProbeEvidence, "runnerAttestation"> = {
		schemaVersion: HERMES_WORKFLOW_PROBE_SCHEMA_VERSION,
		probeId: surfaceId,
		status,
		ran: true,
		observedAt,
		source: HERMES_WORKFLOW_PROBE_SOURCE,
		summary:
			status === "pass"
				? `${surfaceId} workflow probe passed`
				: `${surfaceId} workflow probe failed`,
		checks,
		observations,
	};
	return status === "pass"
		? {
				...evidence,
				runnerAttestation: signHermesWorkflowRunLedgerAttestation(
					evidence,
				) as HermesWorkflowProbeEvidence["runnerAttestation"],
			}
		: evidence;
}

function pushCheck(checks: WorkflowProbeCheck[], name: string, ok: boolean, detail: string): void {
	checks.push({ name, status: ok ? "pass" : "fail", detail });
}

function hashJson(value: unknown): string {
	return hashText(JSON.stringify(sortKeysDeep(value)));
}

function hashText(value: string): string {
	return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function hashFile(filePath: string): string {
	return `sha256:${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex")}`;
}

function flattenZodError(error: z.ZodError): string {
	return error.issues
		.map((issue) => {
			const pathLabel = issue.path.length > 0 ? issue.path.join(".") : "<root>";
			return `${pathLabel}: ${issue.message}`;
		})
		.join("; ");
}

function duplicates(values: readonly string[]): string[] {
	const seen = new Set<string>();
	const duplicates = new Set<string>();
	for (const value of values) {
		if (seen.has(value)) duplicates.add(value);
		seen.add(value);
	}
	return [...duplicates];
}
