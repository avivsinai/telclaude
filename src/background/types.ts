/**
 * Background job types.
 *
 * Background jobs are long-running tasks registered by the operator or an agent
 * via `telclaude background spawn`. The runner picks them up from SQLite, executes
 * them asynchronously, and emits a completion card to the originating chat.
 *
 * Jobs are persisted before returning a job id, so crashes/restarts cannot silently
 * drop work; running jobs at restart are marked `interrupted` and reported.
 */

import { z } from "zod";
import type { PermissionTier } from "../config/config.js";

/**
 * Background job lifecycle statuses.
 *
 * - `queued`: created, not yet picked up by the runner.
 * - `running`: claimed by the runner, executor in progress.
 * - `completed`: executor returned `ok: true`.
 * - `failed`: executor threw or returned `ok: false`.
 * - `cancelled`: operator cancelled before or during execution.
 * - `interrupted`: runner crashed or relay restarted while job was running.
 */
export type BackgroundJobStatus =
	| "queued"
	| "running"
	| "completed"
	| "failed"
	| "cancelled"
	| "interrupted";

/**
 * Payload kinds. `command` shells out; `noop` is used for testing so we can
 * exercise the end-to-end flow without spawning subprocesses.
 */
export const BackgroundJobPayloadSchema = z.discriminatedUnion("kind", [
	z.object({
		kind: z.literal("command"),
		/** Shell command executed via /bin/sh -c. */
		command: z.string().min(1),
		/** Working directory (default: process.cwd()). */
		cwd: z.string().optional(),
		/** Max runtime before the executor is aborted (default: 30 min). */
		timeoutMs: z.number().int().positive().optional(),
	}),
	z.object({
		kind: z.literal("noop"),
		/** Message surfaced on the completion card. */
		message: z.string().default("noop"),
		/** Optional delay to simulate work. */
		delayMs: z.number().int().nonnegative().optional(),
		/** Force a failure (for tests). */
		fail: z.boolean().optional(),
	}),
]);

export type BackgroundJobPayload = z.infer<typeof BackgroundJobPayloadSchema>;

export const BackgroundJobResultSchema = z.object({
	message: z.string(),
	stdout: z.string().optional(),
	stderr: z.string().optional(),
	exitCode: z.number().int().optional(),
});

export type BackgroundJobResult = z.infer<typeof BackgroundJobResultSchema>;

export type BackgroundJob = {
	/** Long UUID used by the runner and callback tokens. */
	id: string;
	/** Short public id (8 hex chars) used in Telegram commands. */
	shortId: string;
	/** Linked local user id (for audit). */
	userId: string;
	/** Originating Telegram chat where the completion notification will land. */
	chatId: number | null;
	/** Optional forum thread. */
	threadId: number | null;
	/** Tier that spawned the job — used to gate cancellation + control. */
	tier: PermissionTier;
	/** Human-readable label. */
	title: string;
	/** Longer description (optional). */
	description: string | null;
	/** Current lifecycle state. */
	status: BackgroundJobStatus;
	/** Typed payload describing what to run. */
	payload: BackgroundJobPayload;
	/** Structured result once terminal. */
	result: BackgroundJobResult | null;
	/** Error message for `failed` / `interrupted`. */
	error: string | null;
	createdAtMs: number;
	startedAtMs: number | null;
	completedAtMs: number | null;
	cancelledAtMs: number | null;
};

export type BackgroundJobCreateInput = {
	title: string;
	description?: string;
	userId: string;
	chatId?: number | null;
	threadId?: number | null;
	tier: PermissionTier;
	payload: BackgroundJobPayload;
};

export type BackgroundJobTerminalStatus = "completed" | "failed" | "cancelled" | "interrupted";

export function isTerminalStatus(
	status: BackgroundJobStatus,
): status is BackgroundJobTerminalStatus {
	return (
		status === "completed" ||
		status === "failed" ||
		status === "cancelled" ||
		status === "interrupted"
	);
}
