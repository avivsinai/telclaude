export const HERMES_WORKFLOW_RUN_LEDGER_SCHEMA_VERSION = "telclaude.hermes.workflow-run-ledger.v1";

export type HermesWorkflowRunStatus =
	| "running"
	| "waiting_approval"
	| "retry_scheduled"
	| "completed"
	| "failed"
	| "cancelled"
	| "human_takeover"
	| "compensating";

export type HermesWorkflowRunBudget = {
	maxRuntimeMs?: number;
	maxToolCalls?: number;
	maxCostUsd?: number;
};

export type HermesWorkflowApprovalPolicy = {
	mode: "none" | "required" | "per_side_effect";
	approverActorId?: string;
	ttlMs?: number;
};

export type HermesWorkflowRunRecord = {
	schemaVersion: typeof HERMES_WORKFLOW_RUN_LEDGER_SCHEMA_VERSION;
	workflowRunId: string;
	workflowId: string;
	initiatingActor: string;
	authorityActor: string;
	authorityActorSource: "server-derived";
	profileId: string;
	domain: string;
	scope: string[];
	capabilities: string[];
	queuedCapabilities: string[];
	budget: HermesWorkflowRunBudget;
	freshnessDeadlineMs: number;
	idempotencyKey: string;
	approvalPolicy: HermesWorkflowApprovalPolicy;
	sideEffectLedgerRefs: string[];
	status: HermesWorkflowRunStatus;
	attempt: number;
	createdAtMs: number;
	updatedAtMs: number;
	checkpoints: HermesWorkflowCheckpoint[];
	approvalWaiters: HermesWorkflowApprovalWaiter[];
	retry?: HermesWorkflowRetry;
	cancellation?: HermesWorkflowCancellation;
	humanTakeover?: HermesWorkflowHumanTakeover;
	compensation?: HermesWorkflowCompensation;
	failure?: HermesWorkflowFailure;
	completedAtMs?: number;
};

export type HermesWorkflowCheckpoint = {
	checkpointId: string;
	createdAtMs: number;
	summary: string;
	stateRef?: string;
};

export type HermesWorkflowApprovalWaiter = {
	approvalRequestId: string;
	authorityActor: string;
	sideEffectLedgerRef: string;
	waitStartedAtMs: number;
	expiresAtMs: number;
	status: "open" | "resolved" | "expired" | "invalidated";
};

export type HermesWorkflowRetry = {
	reason: string;
	retryAfterMs: number;
	backoffMs: number;
	attempt: number;
};

export type HermesWorkflowCancellation = {
	cancelledAtMs: number;
	cancelledBy: string;
	reason: string;
};

export type HermesWorkflowHumanTakeover = {
	takenOverAtMs: number;
	operatorActor: string;
	reason: string;
};

export type HermesWorkflowCompensation = {
	startedAtMs: number;
	reason: string;
	steps: string[];
};

export type HermesWorkflowFailure = {
	failedAtMs: number;
	reason: string;
	retryable: boolean;
};

export type HermesWorkflowStartInput = {
	workflowId: string;
	initiatingActor: string;
	authorityActor: string;
	authorityActorSource: "server-derived";
	profileId: string;
	domain: string;
	scope: string[];
	capabilities: string[];
	queuedCapabilities?: string[];
	budget: HermesWorkflowRunBudget;
	freshnessDeadlineMs: number;
	idempotencyKey: string;
	approvalPolicy: HermesWorkflowApprovalPolicy;
	sideEffectLedgerRefs?: string[];
};

export type HermesWorkflowRunFailureCode =
	| "freshness_deadline_expired"
	| "authority_not_server_derived"
	| "authority_revoked"
	| "authority_mismatch"
	| "run_not_found"
	| "run_terminal";

export type HermesWorkflowRunResult =
	| { ok: true; record: HermesWorkflowRunRecord; duplicate: boolean }
	| {
			ok: false;
			code: HermesWorkflowRunFailureCode;
			reason: string;
			retryable: boolean;
			record?: HermesWorkflowRunRecord;
	  };

export type HermesWorkflowRunLedger = {
	start(input: HermesWorkflowStartInput): HermesWorkflowRunResult;
	get(workflowRunId: string): HermesWorkflowRunRecord | undefined;
	getByIdempotencyKey(idempotencyKey: string): HermesWorkflowRunRecord | undefined;
	checkpoint(
		workflowRunId: string,
		checkpoint: Omit<HermesWorkflowCheckpoint, "createdAtMs">,
	): HermesWorkflowRunResult;
	waitForApproval(
		workflowRunId: string,
		waiter: Omit<HermesWorkflowApprovalWaiter, "waitStartedAtMs" | "status">,
	): HermesWorkflowRunResult;
	scheduleRetry(
		workflowRunId: string,
		retry: Omit<HermesWorkflowRetry, "attempt">,
	): HermesWorkflowRunResult;
	resume(workflowRunId: string): HermesWorkflowRunResult;
	complete(workflowRunId: string): HermesWorkflowRunResult;
	fail(
		workflowRunId: string,
		failure: Omit<HermesWorkflowFailure, "failedAtMs">,
	): HermesWorkflowRunResult;
	cancel(
		workflowRunId: string,
		cancellation: Omit<HermesWorkflowCancellation, "cancelledAtMs">,
	): HermesWorkflowRunResult;
	takeOver(
		workflowRunId: string,
		takeover: Omit<HermesWorkflowHumanTakeover, "takenOverAtMs">,
	): HermesWorkflowRunResult;
	startCompensation(
		workflowRunId: string,
		compensation: Omit<HermesWorkflowCompensation, "startedAtMs">,
	): HermesWorkflowRunResult;
};

export function createHermesWorkflowRunLedger(input: {
	nowMs: () => number;
	makeWorkflowRunId: () => string;
	isAuthorityRevoked?: (record: HermesWorkflowRunRecord) => boolean;
}): HermesWorkflowRunLedger {
	const records = new Map<string, HermesWorkflowRunRecord>();
	const idempotencyIndex = new Map<string, string>();

	function update(
		workflowRunId: string,
		mutator: (record: HermesWorkflowRunRecord, nowMs: number) => HermesWorkflowRunRecord,
	): HermesWorkflowRunResult {
		const record = records.get(workflowRunId);
		if (!record) return runNotFound();
		if (isTerminal(record.status)) return runTerminal(record);
		const authorityFailure = failIfAuthorityRevoked(record);
		if (authorityFailure) return authorityFailure;
		const nowMs = input.nowMs();
		const updated = mutator(record, nowMs);
		records.set(workflowRunId, updated);
		return { ok: true, record: updated, duplicate: false };
	}

	function failIfAuthorityRevoked(record: HermesWorkflowRunRecord): HermesWorkflowRunResult | null {
		if (input.isAuthorityRevoked?.(record) !== true) return null;
		const failed = invalidateAuthority(record, input.nowMs(), "workflow authority was revoked");
		records.set(record.workflowRunId, failed);
		return {
			ok: false,
			code: "authority_revoked",
			reason: "workflow authority was revoked",
			retryable: false,
			record: failed,
		};
	}

	return {
		start(startInput) {
			const existingId = idempotencyIndex.get(startInput.idempotencyKey);
			if (existingId) {
				const existing = records.get(existingId);
				if (existing) return { ok: true, record: existing, duplicate: true };
			}
			if (startInput.authorityActorSource !== "server-derived") {
				return {
					ok: false,
					code: "authority_not_server_derived",
					reason: "workflow authorityActor must be server-derived",
					retryable: false,
				};
			}
			const nowMs = input.nowMs();
			if (startInput.freshnessDeadlineMs <= nowMs) {
				return {
					ok: false,
					code: "freshness_deadline_expired",
					reason: "workflow freshness deadline expired before start",
					retryable: false,
				};
			}
			const workflowRunId = input.makeWorkflowRunId();
			const record: HermesWorkflowRunRecord = {
				schemaVersion: HERMES_WORKFLOW_RUN_LEDGER_SCHEMA_VERSION,
				workflowRunId,
				workflowId: startInput.workflowId,
				initiatingActor: startInput.initiatingActor,
				authorityActor: startInput.authorityActor,
				authorityActorSource: startInput.authorityActorSource,
				profileId: startInput.profileId,
				domain: startInput.domain,
				scope: [...startInput.scope],
				capabilities: [...startInput.capabilities],
				queuedCapabilities: [...(startInput.queuedCapabilities ?? [])],
				budget: { ...startInput.budget },
				freshnessDeadlineMs: startInput.freshnessDeadlineMs,
				idempotencyKey: startInput.idempotencyKey,
				approvalPolicy: { ...startInput.approvalPolicy },
				sideEffectLedgerRefs: [...(startInput.sideEffectLedgerRefs ?? [])],
				status: "running",
				attempt: 1,
				createdAtMs: nowMs,
				updatedAtMs: nowMs,
				checkpoints: [],
				approvalWaiters: [],
			};
			if (input.isAuthorityRevoked?.(record) === true) {
				return {
					ok: false,
					code: "authority_revoked",
					reason: "workflow authority was revoked before start",
					retryable: false,
					record: invalidateAuthority(record, nowMs, "workflow authority was revoked before start"),
				};
			}
			records.set(workflowRunId, record);
			idempotencyIndex.set(startInput.idempotencyKey, workflowRunId);
			return { ok: true, record, duplicate: false };
		},
		get(workflowRunId) {
			return records.get(workflowRunId);
		},
		getByIdempotencyKey(idempotencyKey) {
			const workflowRunId = idempotencyIndex.get(idempotencyKey);
			return workflowRunId ? records.get(workflowRunId) : undefined;
		},
		checkpoint(workflowRunId, checkpoint) {
			return update(workflowRunId, (record, nowMs) => ({
				...record,
				status: "running",
				updatedAtMs: nowMs,
				checkpoints: [...record.checkpoints, { ...checkpoint, createdAtMs: nowMs }],
			}));
		},
		waitForApproval(workflowRunId, waiter) {
			const record = records.get(workflowRunId);
			if (!record) return runNotFound();
			if (waiter.authorityActor !== record.authorityActor) {
				return {
					ok: false,
					code: "authority_mismatch",
					reason: "approval waiter authorityActor does not match workflow authorityActor",
					retryable: false,
					record,
				};
			}
			return update(workflowRunId, (current, nowMs) => ({
				...current,
				status: "waiting_approval",
				updatedAtMs: nowMs,
				sideEffectLedgerRefs: appendUnique(
					current.sideEffectLedgerRefs,
					waiter.sideEffectLedgerRef,
				),
				approvalWaiters: [
					...current.approvalWaiters,
					{ ...waiter, waitStartedAtMs: nowMs, status: "open" },
				],
			}));
		},
		scheduleRetry(workflowRunId, retry) {
			return update(workflowRunId, (record, nowMs) => ({
				...record,
				status: "retry_scheduled",
				attempt: record.attempt + 1,
				updatedAtMs: nowMs,
				retry: { ...retry, attempt: record.attempt + 1 },
			}));
		},
		resume(workflowRunId) {
			const record = records.get(workflowRunId);
			if (!record) return runNotFound();
			if (isTerminal(record.status)) return runTerminal(record);
			const nowMs = input.nowMs();
			if (record.freshnessDeadlineMs <= nowMs) {
				const failed = failRecord(
					record,
					nowMs,
					"workflow freshness deadline expired before resume",
					false,
				);
				records.set(workflowRunId, failed);
				return {
					ok: false,
					code: "freshness_deadline_expired",
					reason: "workflow freshness deadline expired before resume",
					retryable: false,
					record: failed,
				};
			}
			const authorityFailure = failIfAuthorityRevoked(record);
			if (authorityFailure) return authorityFailure;
			const updated: HermesWorkflowRunRecord = {
				...record,
				status: "running",
				updatedAtMs: nowMs,
				approvalWaiters: record.approvalWaiters.map((waiter) =>
					waiter.status === "open" ? { ...waiter, status: "resolved" } : waiter,
				),
				retry: undefined,
			};
			records.set(workflowRunId, updated);
			return { ok: true, record: updated, duplicate: false };
		},
		complete(workflowRunId) {
			return update(workflowRunId, (record, nowMs) => ({
				...record,
				status: "completed",
				updatedAtMs: nowMs,
				completedAtMs: nowMs,
			}));
		},
		fail(workflowRunId, failure) {
			return update(workflowRunId, (record, nowMs) =>
				failRecord(record, nowMs, failure.reason, failure.retryable),
			);
		},
		cancel(workflowRunId, cancellation) {
			return update(workflowRunId, (record, nowMs) => ({
				...record,
				status: "cancelled",
				updatedAtMs: nowMs,
				cancellation: { ...cancellation, cancelledAtMs: nowMs },
			}));
		},
		takeOver(workflowRunId, takeover) {
			return update(workflowRunId, (record, nowMs) => ({
				...record,
				status: "human_takeover",
				updatedAtMs: nowMs,
				humanTakeover: { ...takeover, takenOverAtMs: nowMs },
			}));
		},
		startCompensation(workflowRunId, compensation) {
			return update(workflowRunId, (record, nowMs) => ({
				...record,
				status: "compensating",
				updatedAtMs: nowMs,
				compensation: { ...compensation, startedAtMs: nowMs },
			}));
		},
	};
}

function runNotFound(): HermesWorkflowRunResult {
	return {
		ok: false,
		code: "run_not_found",
		reason: "workflow run was not found",
		retryable: false,
	};
}

function runTerminal(record: HermesWorkflowRunRecord): HermesWorkflowRunResult {
	return {
		ok: false,
		code: "run_terminal",
		reason: `workflow run is already ${record.status}`,
		retryable: false,
		record,
	};
}

function failRecord(
	record: HermesWorkflowRunRecord,
	nowMs: number,
	reason: string,
	retryable: boolean,
): HermesWorkflowRunRecord {
	return {
		...record,
		status: "failed",
		updatedAtMs: nowMs,
		failure: { failedAtMs: nowMs, reason, retryable },
	};
}

function invalidateAuthority(
	record: HermesWorkflowRunRecord,
	nowMs: number,
	reason: string,
): HermesWorkflowRunRecord {
	return {
		...failRecord(record, nowMs, reason, false),
		queuedCapabilities: [],
		approvalWaiters: record.approvalWaiters.map((waiter) =>
			waiter.status === "open" ? { ...waiter, status: "invalidated" } : waiter,
		),
	};
}

function isTerminal(status: HermesWorkflowRunStatus): boolean {
	return status === "completed" || status === "failed" || status === "cancelled";
}

function appendUnique(values: string[], next: string): string[] {
	return values.includes(next) ? values : [...values, next];
}
