/**
 * Background runner host — wires the runner to the Telegram bot Api when it
 * becomes available so completion cards land in the originating chat.
 *
 * The relay calls `handleStartupInterruptions` synchronously at startup to
 * flip any `running` jobs left over from a previous relay process into
 * `interrupted`. The bot bootstrap (`auto-reply.ts`) then calls
 * `startBackgroundRunnerWithApi` once the `Api` is alive, producing a runner
 * whose `onCompleted` hook emits `BackgroundJobCard` instances via `grammy`.
 *
 * Keeping this module thin means the rest of the codebase can stub the Api
 * for tests without touching the schema/runner primitives.
 */

import type { Api } from "grammy";
import { getChildLogger } from "../logging.js";
import {
	emitCompletionNotification,
	markInterruptedOnStartup,
	startBackgroundRunner,
} from "./index.js";
import type { BackgroundRunnerHandle, RunnerOptions } from "./runner.js";
import type { BackgroundJob } from "./types.js";

const logger = getChildLogger({ module: "background-host" });

/**
 * Mark any `running` jobs as `interrupted` and fire a best-effort completion
 * notification for each. Called exactly once at relay startup, before the
 * runner is launched, so we don't race with fresh `running` transitions.
 *
 * The Api may not yet be available (auto-reply boots after the relay initial
 * setup); if so, the notifier falls back to a direct Telegram HTTP call.
 */
export async function handleStartupInterruptions(api?: Api): Promise<BackgroundJob[]> {
	const interrupted = markInterruptedOnStartup();
	if (interrupted.length === 0) return [];

	logger.warn(
		{ count: interrupted.length, shortIds: interrupted.map((j) => j.shortId) },
		"marked background jobs as interrupted on startup",
	);

	// Fire notifications sequentially so we don't blast the operator with a
	// burst of simultaneous edits if several jobs were interrupted together.
	for (const job of interrupted) {
		try {
			await emitCompletionNotification(job, api ? { api } : {});
		} catch (err) {
			logger.error(
				{ jobId: job.id, error: String(err) },
				"failed to emit startup-interruption notification",
			);
		}
	}

	return interrupted;
}

export type HostedRunnerOptions = Omit<RunnerOptions, "onCompleted"> & {
	api?: Api;
	/** Extra consumer hook (e.g. W10 system card); runs after the notifier. */
	onCompleted?: RunnerOptions["onCompleted"];
};

/**
 * Start the background runner with a completion hook that renders a
 * `BackgroundJobCard` in the originating chat. Returns the handle so the
 * relay can call `.stop()` during graceful shutdown.
 */
export function startHostedBackgroundRunner(
	options: HostedRunnerOptions = {},
): BackgroundRunnerHandle {
	const { api, onCompleted: extraHook, ...runnerOpts } = options;
	return startBackgroundRunner({
		...runnerOpts,
		onCompleted: async ({ job, outcome }) => {
			try {
				await emitCompletionNotification(job, api ? { api } : {});
			} catch (err) {
				logger.error(
					{ jobId: job.id, error: String(err) },
					"failed to emit completion notification",
				);
			}
			if (extraHook) {
				await extraHook({ job, outcome });
			}
		},
	});
}
