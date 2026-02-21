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

export type CronExecutor = (job: CronJob) => Promise<CronActionResult>;

async function runWithTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
	if (timeoutMs <= 0) {
		return promise;
	}
	return await Promise.race([
		promise,
		new Promise<T>((_resolve, reject) => {
			const t = setTimeout(() => {
				reject(new Error(`cron job timed out after ${timeoutMs}ms`));
			}, timeoutMs);
			t.unref();
		}),
	]);
}

async function executeClaimedJob(
	job: CronJob,
	executor: CronExecutor,
	timeoutMs: number,
): Promise<CronActionResult> {
	const startedAtMs = Date.now();
	try {
		const result = await runWithTimeout(executor(job), timeoutMs);
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
