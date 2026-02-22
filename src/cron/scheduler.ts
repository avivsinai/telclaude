import { getChildLogger } from "../logging.js";
import {
	claimCronJobById,
	claimDueCronJobs,
	completeClaimedCronJob,
	resetRunningCronJobs,
} from "./store.js";
import type { CronActionResult, CronJob } from "./types.js";

const logger = getChildLogger({ module: "cron-scheduler" });

export type CronScheduler = {
	stop: () => void;
};

/**
 * Cron executor receives an AbortSignal that fires on timeout.
 * Pass this signal down to HTTP requests so they actually get cancelled.
 */
export type CronExecutor = (job: CronJob, signal: AbortSignal) => Promise<CronActionResult>;

/**
 * Run a promise with a proper AbortController-based timeout.
 * Unlike the old Promise.race approach, this actually aborts the executor
 * when the timeout fires, freeing resources.
 */
/** Grace period after abort signal before we forcefully reject (10s). */
const ABORT_GRACE_MS = 10_000;

async function runWithTimeout(
	executor: CronExecutor,
	job: CronJob,
	timeoutMs: number,
): Promise<CronActionResult> {
	if (timeoutMs <= 0) {
		return executor(job, new AbortController().signal);
	}

	const controller = new AbortController();

	// Hard-timeout fallback: even if executor ignores the signal, we reject
	// after timeoutMs + ABORT_GRACE_MS. This prevents stuck jobs from hanging forever.
	const executorPromise = executor(job, controller.signal);
	const hardDeadlineMs = timeoutMs + ABORT_GRACE_MS;

	let softTimer: ReturnType<typeof setTimeout> | undefined;
	let hardTimer: ReturnType<typeof setTimeout> | undefined;

	const hardTimeoutPromise = new Promise<never>((_resolve, reject) => {
		softTimer = setTimeout(() => {
			controller.abort(new Error(`cron job timed out after ${timeoutMs}ms`));
		}, timeoutMs);
		hardTimer = setTimeout(() => {
			reject(new Error(`cron job timed out after ${timeoutMs}ms (executor did not honor abort)`));
		}, hardDeadlineMs);

		if (typeof softTimer === "object" && "unref" in softTimer) softTimer.unref();
		if (typeof hardTimer === "object" && "unref" in hardTimer) hardTimer.unref();
	});

	try {
		return await Promise.race([executorPromise, hardTimeoutPromise]);
	} catch (err) {
		if (controller.signal.aborted && String(err).includes("timed out")) {
			throw new Error(`cron job timed out after ${timeoutMs}ms`);
		}
		throw err;
	} finally {
		if (softTimer) clearTimeout(softTimer);
		if (hardTimer) clearTimeout(hardTimer);
	}
}

async function executeClaimedJob(
	job: CronJob,
	executor: CronExecutor,
	timeoutMs: number,
): Promise<CronActionResult> {
	const startedAtMs = Date.now();
	try {
		const result = await runWithTimeout(executor, job, timeoutMs);
		completeClaimedCronJob({
			job,
			startedAtMs,
			status: result.ok ? "success" : "error",
			message: result.message,
		});
		if (!result.ok) {
			logger.warn(
				{ jobId: job.id, message: result.message },
				"cron job finished with error status",
			);
		}
		return result;
	} catch (err) {
		const message = String(err);
		completeClaimedCronJob({
			job,
			startedAtMs,
			status: "error",
			message,
		});
		logger.error({ error: message, jobId: job.id }, "cron job execution failed");
		return {
			ok: false,
			message,
		};
	}
}

export async function runCronJobNow(params: {
	jobId: string;
	executor: CronExecutor;
	timeoutMs: number;
}): Promise<CronActionResult> {
	const claimed = claimCronJobById(params.jobId);
	if (!claimed) {
		return {
			ok: false,
			message: `job '${params.jobId}' not found or already running`,
		};
	}
	return await executeClaimedJob(claimed, params.executor, params.timeoutMs);
}

export function startCronScheduler(options: {
	pollIntervalMs: number;
	executor: CronExecutor;
	timeoutMs: number;
	maxJobsPerTick?: number;
}): CronScheduler {
	const pollIntervalMs = Math.max(5_000, options.pollIntervalMs);
	const maxJobsPerTick = Math.max(1, options.maxJobsPerTick ?? 10);
	let running = false;

	const tick = async () => {
		if (running) {
			return;
		}
		running = true;
		try {
			const dueJobs = claimDueCronJobs(Date.now(), maxJobsPerTick);
			for (const job of dueJobs) {
				await executeClaimedJob(job, options.executor, options.timeoutMs);
			}
		} finally {
			running = false;
		}
	};

	const resetCount = resetRunningCronJobs();
	if (resetCount > 0) {
		logger.warn({ resetCount }, "reset stale running cron jobs on scheduler start");
	}

	const timer = setInterval(() => {
		void tick();
	}, pollIntervalMs);
	timer.unref();

	void tick();

	return {
		stop: () => {
			clearInterval(timer);
		},
	};
}
