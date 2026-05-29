import { z } from "zod";
import { type HermesPin, HermesPinSchema } from "./foundation.js";

export const DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH =
	"artifacts/hermes/probes/execution-approval-continuation.json";

export const REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS = [
	"provider.prepare-approve-execute",
	"outbound.prepare-approve-execute",
	"cron.approval-wait-resume",
	"long-running.approval-wait-resume",
] as const;

const NonEmptyString = z.string().trim().min(1);

export const ApprovalContinuationEvidenceSchema = z
	.object({
		schemaVersion: z.literal(1),
		hermes: HermesPinSchema,
		native: z
			.object({
				events_wait: z.boolean(),
				permissions_list_open: z.boolean(),
				permissions_respond: z.boolean(),
				responds_to_blocked_run: z.boolean(),
				wrong_actor_denied: z.boolean().optional(),
				stale_request_denied: z.boolean().optional(),
				replay_denied: z.boolean().optional(),
				mutated_decision_denied: z.boolean().optional(),
				evidence_path: NonEmptyString.optional(),
				notes: NonEmptyString.optional(),
			})
			.strict(),
		fallback: z
			.object({
				strategy: z.literal("cross_turn_prepare_approve_execute"),
				fixtures: z.array(
					z
						.object({
							id: NonEmptyString,
							status: z.enum(["pass", "fail"]),
							evidence_path: NonEmptyString,
						})
						.strict(),
				),
			})
			.strict()
			.optional(),
	})
	.strict();

export type ApprovalContinuationEvidence = z.infer<typeof ApprovalContinuationEvidenceSchema>;

export type ApprovalContinuationGate = {
	name: string;
	status: "pass" | "fail";
	detail: string;
};

export type ApprovalContinuationReport = {
	schemaVersion: "telclaude.hermes.approval-continuation-report.v1";
	status: "pass" | "fail" | "input_error";
	mode: "native" | "cross_turn_fallback" | "blocked";
	hermes: HermesPin | null;
	productionEnable: boolean;
	gates: ApprovalContinuationGate[];
};

export function evaluateApprovalContinuationEvidence(
	evidence: unknown,
	options: { missingPath?: string } = {},
): ApprovalContinuationReport {
	if (evidence === undefined) {
		return {
			schemaVersion: "telclaude.hermes.approval-continuation-report.v1",
			status: "input_error",
			mode: "blocked",
			hermes: null,
			productionEnable: false,
			gates: [
				{
					name: "approvalContinuation.evidence",
					status: "fail",
					detail: `required approval-continuation evidence is missing: ${options.missingPath ?? DEFAULT_APPROVAL_CONTINUATION_EVIDENCE_PATH}`,
				},
			],
		};
	}

	const parsed = ApprovalContinuationEvidenceSchema.safeParse(evidence);
	if (!parsed.success) {
		return {
			schemaVersion: "telclaude.hermes.approval-continuation-report.v1",
			status: "input_error",
			mode: "blocked",
			hermes: null,
			productionEnable: false,
			gates: [
				{
					name: "approvalContinuation.evidence",
					status: "fail",
					detail: parsed.error.issues
						.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
						.join("; "),
				},
			],
		};
	}

	const input = parsed.data;
	const nativeFailures = collectNativeFailures(input.native);
	const fallbackFailures = collectFallbackFailures(input.fallback);
	const nativeGate: ApprovalContinuationGate = {
		name: "approvalContinuation.native",
		status: nativeFailures.length === 0 ? "pass" : "fail",
		detail:
			nativeFailures.length === 0
				? "Hermes approval wait/resume is proven for the pinned artifact"
				: nativeFailures.join("; "),
	};
	const fallbackGate: ApprovalContinuationGate = {
		name: "approvalContinuation.crossTurnFallback",
		status: fallbackFailures.length === 0 ? "pass" : "fail",
		detail:
			fallbackFailures.length === 0
				? "Cross-turn prepare/approve/execute fallback fixtures passed"
				: fallbackFailures.join("; "),
	};
	const mode =
		nativeGate.status === "pass"
			? "native"
			: fallbackGate.status === "pass"
				? "cross_turn_fallback"
				: "blocked";

	return {
		schemaVersion: "telclaude.hermes.approval-continuation-report.v1",
		status: mode === "blocked" ? "fail" : "pass",
		mode,
		hermes: input.hermes,
		productionEnable: mode !== "blocked",
		gates: [nativeGate, fallbackGate],
	};
}

function collectNativeFailures(native: ApprovalContinuationEvidence["native"]): string[] {
	const failures: string[] = [];
	if (!native.events_wait) failures.push("events_wait is unavailable");
	if (!native.permissions_list_open) failures.push("permissions_list_open is unavailable");
	if (!native.permissions_respond) failures.push("permissions_respond is unavailable");
	if (!native.responds_to_blocked_run) {
		failures.push("permissions_respond is not proven to resume the blocked Hermes run");
	}
	if (native.wrong_actor_denied !== true) failures.push("wrong actor denial is unproven");
	if (native.stale_request_denied !== true) failures.push("stale request denial is unproven");
	if (native.replay_denied !== true) failures.push("approval replay denial is unproven");
	if (native.mutated_decision_denied !== true) {
		failures.push("mutated decision denial is unproven");
	}
	return failures;
}

function collectFallbackFailures(fallback: ApprovalContinuationEvidence["fallback"]): string[] {
	if (!fallback) {
		return ["cross-turn fallback evidence is missing"];
	}
	const fixtureById = new Map(fallback.fixtures.map((fixture) => [fixture.id, fixture]));
	return REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS.flatMap((id) => {
		const fixture = fixtureById.get(id);
		if (!fixture) return [`missing fallback fixture ${id}`];
		if (fixture.status !== "pass") return [`fallback fixture ${id} status is ${fixture.status}`];
		return [];
	});
}
