import { describe, expect, it } from "vitest";
import {
	evaluateApprovalContinuationEvidence,
	REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS,
} from "../../src/hermes/approval-continuation.js";

const hermes = { version: "0.15.1" };

describe("Hermes approval-continuation evidence", () => {
	it("fails closed when evidence is missing or malformed", () => {
		expect(evaluateApprovalContinuationEvidence(undefined).status).toBe("input_error");

		const malformed = evaluateApprovalContinuationEvidence({
			schemaVersion: 1,
			hermes,
			native: {},
		});

		expect(malformed.status).toBe("input_error");
		expect(malformed.productionEnable).toBe(false);
		expect(malformed.gates[0]?.detail).toContain("events_wait");
	});

	it("does not treat visible MCP permission tools as proof of continuation", () => {
		const report = evaluateApprovalContinuationEvidence({
			schemaVersion: 1,
			hermes,
			native: {
				events_wait: true,
				permissions_list_open: true,
				permissions_respond: true,
				responds_to_blocked_run: false,
			},
		});

		expect(report).toMatchObject({
			status: "fail",
			mode: "blocked",
			productionEnable: false,
		});
		expect(
			report.gates.find((gate) => gate.name === "approvalContinuation.native")?.detail,
		).toContain("not proven to resume");
	});

	it("passes native mode only with resume and negative proof", () => {
		const report = evaluateApprovalContinuationEvidence({
			schemaVersion: 1,
			hermes,
			native: {
				events_wait: true,
				permissions_list_open: true,
				permissions_respond: true,
				responds_to_blocked_run: true,
				wrong_actor_denied: true,
				stale_request_denied: true,
				replay_denied: true,
				mutated_decision_denied: true,
			},
		});

		expect(report).toMatchObject({
			status: "pass",
			mode: "native",
			productionEnable: true,
		});
	});

	it("accepts the explicit cross-turn prepare/approve/execute fallback", () => {
		const report = evaluateApprovalContinuationEvidence({
			schemaVersion: 1,
			hermes,
			native: {
				events_wait: true,
				permissions_list_open: true,
				permissions_respond: true,
				responds_to_blocked_run: false,
				wrong_actor_denied: true,
				stale_request_denied: true,
				replay_denied: true,
				mutated_decision_denied: true,
			},
			fallback: {
				strategy: "cross_turn_prepare_approve_execute",
				fixtures: REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS.map((id) => ({
					id,
					status: "pass",
					evidence_path: `artifacts/hermes/approval/${id}.json`,
				})),
			},
		});

		expect(report).toMatchObject({
			status: "pass",
			mode: "cross_turn_fallback",
			productionEnable: true,
		});
		expect(
			report.gates.find((gate) => gate.name === "approvalContinuation.crossTurnFallback")?.status,
		).toBe("pass");
	});

	it("blocks fallback production enablement when replay defenses are unproven", () => {
		const report = evaluateApprovalContinuationEvidence({
			schemaVersion: 1,
			hermes,
			native: {
				events_wait: false,
				permissions_list_open: false,
				permissions_respond: false,
				responds_to_blocked_run: false,
				wrong_actor_denied: true,
				stale_request_denied: true,
				replay_denied: false,
				mutated_decision_denied: true,
			},
			fallback: {
				strategy: "cross_turn_prepare_approve_execute",
				fixtures: REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS.map((id) => ({
					id,
					status: "pass",
					evidence_path: `artifacts/hermes/approval/${id}.json`,
				})),
			},
		});

		expect(report).toMatchObject({
			status: "fail",
			mode: "blocked",
			productionEnable: false,
		});
		expect(
			report.gates.find((gate) => gate.name === "approvalContinuation.crossTurnFallback")?.status,
		).toBe("pass");
		expect(
			report.gates.find((gate) => gate.name === "approvalContinuation.replayDefenses")?.detail,
		).toContain("approval replay denial is unproven");
	});

	it("keeps fallback blocked until every required workflow fixture passes", () => {
		const [firstFixture] = REQUIRED_APPROVAL_FALLBACK_FIXTURE_IDS;
		const report = evaluateApprovalContinuationEvidence({
			schemaVersion: 1,
			hermes,
			native: {
				events_wait: true,
				permissions_list_open: true,
				permissions_respond: true,
				responds_to_blocked_run: false,
				wrong_actor_denied: true,
				stale_request_denied: true,
				replay_denied: true,
				mutated_decision_denied: true,
			},
			fallback: {
				strategy: "cross_turn_prepare_approve_execute",
				fixtures: [
					{
						id: firstFixture,
						status: "fail",
						evidence_path: "artifacts/hermes/approval/failing.json",
					},
				],
			},
		});

		expect(report.status).toBe("fail");
		expect(report.productionEnable).toBe(false);
		expect(
			report.gates.find((gate) => gate.name === "approvalContinuation.crossTurnFallback")?.detail,
		).toContain(`fallback fixture ${firstFixture} status is fail`);
	});
});
