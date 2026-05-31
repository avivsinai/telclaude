import { describe, expect, it } from "vitest";
import {
	createHermesWorkflowRunLedger,
	HERMES_WORKFLOW_RUN_LEDGER_SCHEMA_VERSION,
} from "../../src/hermes/workflow-run-ledger.js";

describe("Hermes workflow run ledger", () => {
	it("records required authority, scope, budget, freshness, approval, and side-effect fields", () => {
		const ledger = createLedger();
		const started = ledger.start(baseStartInput());

		expect(started).toMatchObject({ ok: true, duplicate: false });
		if (!started.ok) throw new Error("expected start success");
		expect(started.record).toMatchObject({
			schemaVersion: HERMES_WORKFLOW_RUN_LEDGER_SCHEMA_VERSION,
			workflowRunId: "run-1",
			workflowId: "cron.private.daily_brief",
			initiatingActor: "actor:family-member",
			authorityActor: "actor:aviv",
			authorityActorSource: "server-derived",
			profileId: "tc-private-default",
			domain: "private",
			scope: ["calendar.read", "gmail.read"],
			capabilities: ["memory.search", "provider.google.read"],
			queuedCapabilities: ["provider.google.write"],
			budget: { maxRuntimeMs: 120_000, maxToolCalls: 12, maxCostUsd: 1 },
			freshnessDeadlineMs: 15_000,
			idempotencyKey: "daily-brief:2026-05-31",
			approvalPolicy: { mode: "per_side_effect", approverActorId: "actor:aviv", ttlMs: 300_000 },
			sideEffectLedgerRefs: [],
			status: "running",
			attempt: 1,
		});
	});

	it("rejects non-server-derived authority before creating a run", () => {
		const ledger = createLedger();

		const result = ledger.start({
			...baseStartInput(),
			authorityActor: "actor:family-member",
			authorityActorSource: "initiating-actor" as never,
		});

		expect(result).toMatchObject({
			ok: false,
			code: "authority_not_server_derived",
			retryable: false,
		});
		expect(ledger.getByIdempotencyKey("daily-brief:2026-05-31")).toBeUndefined();
	});

	it("deduplicates retries by idempotency key", () => {
		const ledger = createLedger();
		const first = ledger.start(baseStartInput());
		const duplicate = ledger.start(baseStartInput());

		expect(first).toMatchObject({ ok: true, duplicate: false });
		expect(duplicate).toMatchObject({ ok: true, duplicate: true });
		if (!first.ok || !duplicate.ok) throw new Error("expected start success");
		expect(duplicate.record.workflowRunId).toBe(first.record.workflowRunId);
		expect(ledger.getByIdempotencyKey("daily-brief:2026-05-31")?.workflowRunId).toBe("run-1");
	});

	it("binds approval waiters to the server-derived authority actor", () => {
		const ledger = createLedger();
		const started = ledger.start(baseStartInput());
		if (!started.ok) throw new Error("expected start success");

		expect(
			ledger.waitForApproval(started.record.workflowRunId, {
				approvalRequestId: "approval-wrong",
				authorityActor: "actor:family-member",
				sideEffectLedgerRef: "effect-1",
				expiresAtMs: 10_000,
			}),
		).toMatchObject({
			ok: false,
			code: "authority_mismatch",
		});

		const waiting = ledger.waitForApproval(started.record.workflowRunId, {
			approvalRequestId: "approval-1",
			authorityActor: "actor:aviv",
			sideEffectLedgerRef: "effect-1",
			expiresAtMs: 10_000,
		});

		expect(waiting).toMatchObject({ ok: true });
		if (!waiting.ok) throw new Error("expected wait success");
		expect(waiting.record.status).toBe("waiting_approval");
		expect(waiting.record.sideEffectLedgerRefs).toEqual(["effect-1"]);
		expect(waiting.record.approvalWaiters).toEqual([
			expect.objectContaining({
				approvalRequestId: "approval-1",
				authorityActor: "actor:aviv",
				sideEffectLedgerRef: "effect-1",
				status: "open",
			}),
		]);

		const resumed = ledger.resume(started.record.workflowRunId);
		expect(resumed).toMatchObject({ ok: true });
		if (!resumed.ok) throw new Error("expected resume success");
		expect(resumed.record.status).toBe("running");
		expect(resumed.record.approvalWaiters[0]?.status).toBe("resolved");
	});

	it("records retry/backoff for retryable outages without creating a new run", () => {
		const ledger = createLedger();
		const started = ledger.start(baseStartInput());
		if (!started.ok) throw new Error("expected start success");

		const retry = ledger.scheduleRetry(started.record.workflowRunId, {
			reason: "provider outage",
			retryAfterMs: 20_000,
			backoffMs: 5_000,
		});

		expect(retry).toMatchObject({ ok: true });
		if (!retry.ok) throw new Error("expected retry success");
		expect(retry.record).toMatchObject({
			workflowRunId: "run-1",
			status: "retry_scheduled",
			attempt: 2,
			retry: {
				reason: "provider outage",
				retryAfterMs: 20_000,
				backoffMs: 5_000,
				attempt: 2,
			},
		});
	});

	it("rejects stale data before start and before resume", () => {
		const ledger = createLedger({ nowMs: () => 20_000 });
		expect(ledger.start(baseStartInput())).toMatchObject({
			ok: false,
			code: "freshness_deadline_expired",
		});

		let nowMs = 1_000;
		const liveLedger = createLedger({ nowMs: () => nowMs });
		const started = liveLedger.start(baseStartInput({ freshnessDeadlineMs: 2_000 }));
		if (!started.ok) throw new Error("expected start success");
		nowMs = 3_000;

		const resumed = liveLedger.resume(started.record.workflowRunId);
		expect(resumed).toMatchObject({
			ok: false,
			code: "freshness_deadline_expired",
			record: expect.objectContaining({
				status: "failed",
				failure: expect.objectContaining({
					reason: "workflow freshness deadline expired before resume",
					retryable: false,
				}),
			}),
		});
	});

	it("invalidates open approval waiters and queued capabilities when authority is revoked", () => {
		let revoked = false;
		const ledger = createLedger({ isAuthorityRevoked: () => revoked });
		const started = ledger.start(baseStartInput());
		if (!started.ok) throw new Error("expected start success");
		const waiting = ledger.waitForApproval(started.record.workflowRunId, {
			approvalRequestId: "approval-1",
			authorityActor: "actor:aviv",
			sideEffectLedgerRef: "effect-1",
			expiresAtMs: 10_000,
		});
		if (!waiting.ok) throw new Error("expected wait success");

		revoked = true;
		const resumed = ledger.resume(started.record.workflowRunId);

		expect(resumed).toMatchObject({
			ok: false,
			code: "authority_revoked",
			record: expect.objectContaining({
				status: "failed",
				queuedCapabilities: [],
				approvalWaiters: [
					expect.objectContaining({
						approvalRequestId: "approval-1",
						status: "invalidated",
					}),
				],
			}),
		});
	});

	it("prevents checkpoints after cancellation", () => {
		const ledger = createLedger();
		const started = ledger.start(baseStartInput());
		if (!started.ok) throw new Error("expected start success");

		const cancelled = ledger.cancel(started.record.workflowRunId, {
			cancelledBy: "actor:aviv",
			reason: "operator stopped the run",
		});
		expect(cancelled).toMatchObject({ ok: true });

		expect(
			ledger.checkpoint(started.record.workflowRunId, {
				checkpointId: "after-cancel",
				summary: "should not persist",
			}),
		).toMatchObject({
			ok: false,
			code: "run_terminal",
			retryable: false,
		});
	});
});

function createLedger(
	overrides: Partial<Parameters<typeof createHermesWorkflowRunLedger>[0]> = {},
) {
	let sequence = 0;
	return createHermesWorkflowRunLedger({
		nowMs: () => 1_000,
		makeWorkflowRunId: () => `run-${++sequence}`,
		...overrides,
	});
}

function baseStartInput(
	overrides: Partial<Parameters<ReturnType<typeof createLedger>["start"]>[0]> = {},
) {
	return {
		workflowId: "cron.private.daily_brief",
		initiatingActor: "actor:family-member",
		authorityActor: "actor:aviv",
		authorityActorSource: "server-derived" as const,
		profileId: "tc-private-default",
		domain: "private",
		scope: ["calendar.read", "gmail.read"],
		capabilities: ["memory.search", "provider.google.read"],
		queuedCapabilities: ["provider.google.write"],
		budget: { maxRuntimeMs: 120_000, maxToolCalls: 12, maxCostUsd: 1 },
		freshnessDeadlineMs: 15_000,
		idempotencyKey: "daily-brief:2026-05-31",
		approvalPolicy: {
			mode: "per_side_effect" as const,
			approverActorId: "actor:aviv",
			ttlMs: 300_000,
		},
		...overrides,
	};
}
