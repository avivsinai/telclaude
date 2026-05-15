import { loadConfig } from "../config/config.js";
import { executeCronAction } from "../cron/actions.js";
import { runCronJobNow } from "../cron/scheduler.js";
import { getCronJob } from "../cron/store.js";
import { getWebhookCronTargetRejection } from "../webhooks/policy.js";
import type { BackgroundExecutorResult } from "./runner.js";
import type { BackgroundJob } from "./types.js";

function combineAbortSignals(a: AbortSignal, b: AbortSignal): AbortSignal {
	if (a.aborted) return a;
	if (b.aborted) return b;
	const controller = new AbortController();
	const abort = () => controller.abort();
	a.addEventListener("abort", abort, { once: true });
	b.addEventListener("abort", abort, { once: true });
	return controller.signal;
}

export async function cronRunExecutor(
	job: BackgroundJob,
	signal: AbortSignal,
): Promise<BackgroundExecutorResult> {
	if (job.payload.kind !== "cron-run") {
		return { ok: false, error: `Unsupported payload kind: ${job.payload.kind}` };
	}

	if (signal.aborted) {
		return { ok: false, error: "Aborted" };
	}

	const existing = getCronJob(job.payload.jobId);
	if (!existing) {
		return { ok: false, error: `cron job '${job.payload.jobId}' not found` };
	}
	if (!existing.enabled) {
		return { ok: false, error: `cron job '${job.payload.jobId}' is disabled` };
	}
	const targetRejection = getWebhookCronTargetRejection(existing);
	if (targetRejection) {
		return {
			ok: false,
			error: `cron job '${job.payload.jobId}' is not an allowed webhook target: ${targetRejection}`,
		};
	}

	const cfg = loadConfig();
	const result = await runCronJobNow({
		jobId: job.payload.jobId,
		timeoutMs: cfg.cron.timeoutSeconds * 1000,
		executor: (cronJob, cronSignal) =>
			executeCronAction(cronJob, cfg, combineAbortSignals(signal, cronSignal)),
	});

	return {
		ok: result.ok,
		result: {
			message: result.message,
		},
		...(result.ok ? {} : { error: result.message }),
	};
}
