/**
 * Background job runner — polls SQLite for queued jobs, executes them, and
 * fires a completion hook when they finish.
 *
 * The runner is deliberately simple: no in-memory queue, no worker pool. Each
 * tick claims up to `maxJobsPerTick` queued jobs via `claimQueuedJobs` (which
 * atomically transitions them to `running`) and dispatches them concurrently.
 *
 * A job executor receives:
 *   - the job record
 *   - an AbortSignal that fires on external cancellation OR soft timeout
 *
 * Executors SHOULD honour the signal; if they don't, the runner enforces a
 * hard timeout ~10s past the soft timeout to prevent leaks.
 *
 * Cancellation coherency:
 *   - `cancelJob()` flips the status to `cancelled` immediately, but cannot
 *     forcibly stop a running executor. The runner checks the job status right
 *     before completion and discards the terminal transition if the job was
 *     cancelled meanwhile (see `completeJob` — it only transitions from
 *     `running`, so cancellation "wins").
 */

import { spawn } from "node:child_process";
import { getChildLogger } from "../logging.js";
import { claimQueuedJobs, completeJob, getJob } from "./jobs.js";
import type { BackgroundJob, BackgroundJobPayload, BackgroundJobResult } from "./types.js";

const logger = getChildLogger({ module: "background-runner" });

export type BackgroundRunnerHandle = {
	stop: () => void;
	/** Run a tick immediately; mostly useful for tests. */
	tick: () => Promise<void>;
};

export type BackgroundExecutorResult = {
	ok: boolean;
	result?: BackgroundJobResult;
	error?: string;
};

/**
 * Executors can be registered per payload kind. `noop` is built in for tests;
 * consumers plug in a real `command` executor at startup. Keeping executors
 * pluggable lets us swap the shell path for Docker `exec`, wrap in a sandbox,
 * or mock for tests without poking at the runner internals.
 */
export type BackgroundExecutor = (
	job: BackgroundJob,
	signal: AbortSignal,
) => Promise<BackgroundExecutorResult>;

const GRACE_MS = 10_000;
const DEFAULT_COMMAND_TIMEOUT_MS = 30 * 60 * 1000; // 30 min — matches heartbeat ceiling.
const MAX_OUTPUT_CHARS = 8_000;

export function truncateOutput(value: string, limit = MAX_OUTPUT_CHARS): string {
	if (value.length <= limit) return value;
	const head = value.slice(0, limit);
	return `${head}\n\n…[truncated ${value.length - limit} chars]`;
}

/**
 * Default command executor — runs the payload command under /bin/sh -c.
 *
 * Exit code 0 is treated as success; anything else as failure. stderr is
 * always captured, and both streams are truncated to keep the completion
 * card within Telegram's message-size budget.
 */
export async function defaultCommandExecutor(
	job: BackgroundJob,
	signal: AbortSignal,
): Promise<BackgroundExecutorResult> {
	if (job.payload.kind !== "command") {
		return { ok: false, error: `Unsupported payload kind: ${job.payload.kind}` };
	}
	const payload = job.payload;
	const cwd = payload.cwd ?? process.cwd();
	const timeoutMs = payload.timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;

	let child: ReturnType<typeof spawn>;
	try {
		child = spawn("/bin/sh", ["-c", payload.command], {
			cwd,
			env: process.env,
			stdio: ["ignore", "pipe", "pipe"],
		});
	} catch (err) {
		return { ok: false, error: `Failed to spawn: ${String(err)}` };
	}

	const stdoutChunks: Buffer[] = [];
	const stderrChunks: Buffer[] = [];
	let stdoutBytes = 0;
	let stderrBytes = 0;
	const MAX_BUFFER_BYTES = 1_000_000; // 1 MB cap to prevent runaway jobs.

	child.stdout?.on("data", (buf: Buffer) => {
		if (stdoutBytes < MAX_BUFFER_BYTES) {
			stdoutChunks.push(buf);
			stdoutBytes += buf.length;
		}
	});
	child.stderr?.on("data", (buf: Buffer) => {
		if (stderrBytes < MAX_BUFFER_BYTES) {
			stderrChunks.push(buf);
			stderrBytes += buf.length;
		}
	});

	const onAbort = (): void => {
		try {
			if (!child.killed) {
				child.kill("SIGTERM");
				// Hard kill after grace.
				setTimeout(() => {
					if (!child.killed) {
						try {
							child.kill("SIGKILL");
						} catch {}
					}
				}, 5_000).unref();
			}
		} catch (err) {
			logger.warn({ jobId: job.id, error: String(err) }, "failed to kill background process");
		}
	};
	if (signal.aborted) {
		onAbort();
	} else {
		signal.addEventListener("abort", onAbort, { once: true });
	}

	const timer = setTimeout(() => {
		onAbort();
	}, timeoutMs);
	timer.unref?.();

	const exit: Promise<{ code: number | null; signalName: NodeJS.Signals | null }> = new Promise(
		(resolve) => {
			child.on("exit", (code, signalName) => resolve({ code, signalName }));
		},
	);

	const { code, signalName } = await exit;
	clearTimeout(timer);
	signal.removeEventListener?.("abort", onAbort);

	const stdout = truncateOutput(Buffer.concat(stdoutChunks).toString("utf8"));
	const stderr = truncateOutput(Buffer.concat(stderrChunks).toString("utf8"));
	const exitCode = code ?? -1;
	const success = code === 0;

	const message = success
		? `Exit 0${stdout ? ` — ${stdout.split(/\n/)[0].slice(0, 160)}` : ""}`
		: signalName
			? `Killed by ${signalName} (exit ${exitCode})`
			: `Exited with code ${exitCode}`;

	return {
		ok: success,
		result: {
			message,
			stdout: stdout || undefined,
			stderr: stderr || undefined,
			exitCode,
		},
		...(success ? {} : { error: message }),
	};
}

/**
 * Built-in noop executor for tests. Resolves after `payload.delayMs` and
 * optionally fails when `payload.fail === true`.
 */
export async function noopExecutor(
	job: BackgroundJob,
	signal: AbortSignal,
): Promise<BackgroundExecutorResult> {
	if (job.payload.kind !== "noop") {
		return { ok: false, error: `Unsupported payload kind: ${job.payload.kind}` };
	}
	const payload = job.payload;
	if (payload.delayMs && payload.delayMs > 0) {
		await new Promise<void>((resolve) => {
			const timer = setTimeout(resolve, payload.delayMs);
			timer.unref?.();
			if (signal.aborted) {
				clearTimeout(timer);
				resolve();
			} else {
				signal.addEventListener(
					"abort",
					() => {
						clearTimeout(timer);
						resolve();
					},
					{ once: true },
				);
			}
		});
	}
	if (signal.aborted) {
		return { ok: false, error: "Aborted" };
	}
	if (payload.fail) {
		return { ok: false, error: payload.message || "noop failure" };
	}
	return {
		ok: true,
		result: { message: payload.message || "noop ok" },
	};
}

function resolveExecutor(
	payload: BackgroundJobPayload,
	overrides?: Partial<Record<BackgroundJobPayload["kind"], BackgroundExecutor>>,
): BackgroundExecutor {
	const custom = overrides?.[payload.kind];
	if (custom) return custom;
	switch (payload.kind) {
		case "command":
			return defaultCommandExecutor;
		case "noop":
			return noopExecutor;
	}
}

export type CompletionHook = (params: {
	job: BackgroundJob;
	outcome: BackgroundExecutorResult;
}) => void | Promise<void>;

export type RunnerOptions = {
	pollIntervalMs?: number;
	maxJobsPerTick?: number;
	executors?: Partial<Record<BackgroundJobPayload["kind"], BackgroundExecutor>>;
	onCompleted?: CompletionHook;
	/** Default per-job soft timeout if the payload omits one. */
	defaultTimeoutMs?: number;
};

async function runSingleJob(
	job: BackgroundJob,
	options: RunnerOptions,
	inFlight: Set<string>,
): Promise<void> {
	const executor = resolveExecutor(job.payload, options.executors);
	const controller = new AbortController();
	const softTimeoutMs =
		job.payload.kind === "command" && job.payload.timeoutMs
			? job.payload.timeoutMs
			: (options.defaultTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS);

	let softTimer: ReturnType<typeof setTimeout> | undefined;
	let hardTimer: ReturnType<typeof setTimeout> | undefined;
	let outcome: BackgroundExecutorResult;
	try {
		softTimer = setTimeout(() => {
			controller.abort(new Error("Soft timeout"));
		}, softTimeoutMs);
		softTimer.unref?.();

		const execPromise = executor(job, controller.signal);
		const hardPromise = new Promise<BackgroundExecutorResult>((_, reject) => {
			hardTimer = setTimeout(() => {
				reject(new Error(`Background job timed out after ${softTimeoutMs}ms + grace`));
			}, softTimeoutMs + GRACE_MS);
			hardTimer.unref?.();
		});
		outcome = await Promise.race([execPromise, hardPromise]);
	} catch (err) {
		outcome = { ok: false, error: String(err instanceof Error ? err.message : err) };
	} finally {
		if (softTimer) clearTimeout(softTimer);
		if (hardTimer) clearTimeout(hardTimer);
		inFlight.delete(job.id);
	}

	// Check whether the job was cancelled during execution; if so, don't
	// clobber the `cancelled` status with `completed`/`failed`.
	const current = getJob(job.id);
	if (!current || current.status !== "running") {
		logger.info(
			{ jobId: job.id, currentStatus: current?.status ?? "missing" },
			"background job status changed before completion; skipping terminal write",
		);
		if (current && options.onCompleted) {
			await options.onCompleted({ job: current, outcome });
		}
		return;
	}

	const { job: persisted, transitioned } = completeJob({
		jobId: job.id,
		status: outcome.ok ? "completed" : "failed",
		result: outcome.result,
		error: outcome.error,
	});

	if (!transitioned || !persisted) {
		logger.info({ jobId: job.id }, "completeJob() no-op — job likely cancelled mid-run");
	}

	if (options.onCompleted && persisted) {
		try {
			await options.onCompleted({ job: persisted, outcome });
		} catch (err) {
			logger.error({ jobId: job.id, error: String(err) }, "background completion hook threw");
		}
	}
}

export function startBackgroundRunner(options: RunnerOptions = {}): BackgroundRunnerHandle {
	const pollIntervalMs = Math.max(500, options.pollIntervalMs ?? 2_000);
	const maxJobsPerTick = Math.max(1, options.maxJobsPerTick ?? 4);
	const inFlight = new Set<string>();
	let running = false;
	let stopped = false;

	const tick = async (): Promise<void> => {
		if (running || stopped) return;
		running = true;
		try {
			if (inFlight.size >= maxJobsPerTick) {
				return;
			}
			const capacity = maxJobsPerTick - inFlight.size;
			const claimed = claimQueuedJobs(Date.now(), capacity);
			for (const job of claimed) {
				inFlight.add(job.id);
				// Fire-and-forget; `runSingleJob` manages its own finally.
				void runSingleJob(job, options, inFlight).catch((err) => {
					logger.error({ jobId: job.id, error: String(err) }, "background job dispatch threw");
				});
			}
		} finally {
			running = false;
		}
	};

	const timer = setInterval(() => {
		void tick();
	}, pollIntervalMs);
	timer.unref?.();

	// Fire the first tick immediately so queued jobs created just before start
	// don't wait a full interval.
	void tick();

	return {
		stop: () => {
			stopped = true;
			clearInterval(timer);
		},
		tick,
	};
}
