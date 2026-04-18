/**
 * Completion notification routing for background jobs.
 *
 * When a job transitions to a terminal status, we render a `BackgroundJobCard`
 * in the originating chat (or fall back to an admin alert). The runner hands
 * us a `grammy` Api when available; when the bot isn't running we fall back
 * to direct Telegram HTTP (same pattern as `admin-alert.ts`).
 */

import type { Api } from "grammy";
import { loadConfig } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { sendBackgroundJobCard } from "../telegram/cards/create-helpers.js";
import type { BackgroundJobCardState, CardActorScope } from "../telegram/cards/types.js";
import { CardKind } from "../telegram/cards/types.js";
import { truncateOutput } from "./runner.js";
import type { BackgroundJob } from "./types.js";

const logger = getChildLogger({ module: "background-notifier" });

export type NotifierDeps = {
	/** Optional grammy Api handle — preferred routing path. */
	api?: Api;
	/** Optional explicit override for completion destinations. */
	homeChat?: { chatId: number; threadId?: number };
};

function buildCardState(job: BackgroundJob): BackgroundJobCardState {
	const stdout = job.result?.stdout;
	const stderr = job.result?.stderr;
	const preview = [stdout, stderr].filter(Boolean).join("\n---\n");

	return {
		kind: CardKind.BackgroundJob,
		title: `${job.status === "completed" ? "Background job finished" : "Background job update"}: ${job.title}`,
		description: job.description ?? undefined,
		shortId: job.shortId,
		payloadKind: job.payload.kind,
		status: job.status as BackgroundJobCardState["status"],
		resultSummary: job.result?.message,
		outputPreview: preview ? truncateOutput(preview, 1_500) : undefined,
		errorMessage: job.error ?? undefined,
		createdAtMs: job.createdAtMs,
		startedAtMs: job.startedAtMs ?? undefined,
		completedAtMs: job.completedAtMs ?? undefined,
	};
}

function resolveDestination(
	job: BackgroundJob,
	deps: NotifierDeps,
): { chatId: number; threadId?: number } | null {
	// 1. Originating chat wins when present.
	if (job.chatId !== null && job.chatId !== undefined) {
		return {
			chatId: job.chatId,
			threadId: job.threadId ?? undefined,
		};
	}

	// 2. Explicit home chat override from the caller (e.g. W3 integration).
	if (deps.homeChat) {
		return deps.homeChat;
	}

	// 3. Fall back to admin claim chat IDs via the shared helper.
	// Imported lazily to avoid a circular module dep when Telegram is unused
	// in unit tests (e.g. `jobs.test.ts` only imports the store).
	return null;
}

/**
 * Emit a Telegram completion notification for a terminal-state job.
 *
 * Intentionally best-effort: logs and swallows errors so a failed delivery
 * cannot block the runner or get the job itself stuck.
 */
export async function emitCompletionNotification(
	job: BackgroundJob,
	deps: NotifierDeps = {},
): Promise<void> {
	const state = buildCardState(job);

	const dest = resolveDestination(job, deps);
	const actorScope: CardActorScope = dest ? (`chat:${dest.chatId}` as CardActorScope) : "admin";

	// Direct card path when we have both a destination and a grammy Api.
	if (dest && deps.api) {
		try {
			await sendBackgroundJobCard(deps.api, dest.chatId, {
				state,
				actorScope,
				threadId: dest.threadId,
			});
			logger.info(
				{ jobId: job.id, shortId: job.shortId, chatId: dest.chatId, status: job.status },
				"background job completion card sent",
			);
			return;
		} catch (err) {
			logger.warn(
				{ jobId: job.id, error: String(err) },
				"failed to send completion card, falling back to admin alert",
			);
		}
	}

	// Text fallback when no grammy Api is wired up or card send failed.
	const cfg = loadConfig();
	const botToken = cfg.telegram?.botToken ?? process.env.TELEGRAM_BOT_TOKEN;
	if (!botToken) {
		logger.warn({ jobId: job.id }, "no bot token configured, cannot send completion notification");
		return;
	}

	const resolvedDest = dest ?? (await resolveAdminFallback());
	if (!resolvedDest) {
		logger.warn(
			{ jobId: job.id, shortId: job.shortId },
			"no destination available, dropping completion notification",
		);
		return;
	}

	const summary = job.result?.message ?? job.error ?? job.status;
	const body = [
		`Background job: ${job.title}`,
		`ID: ${job.shortId}`,
		`Status: ${job.status}`,
		summary,
	]
		.filter(Boolean)
		.join("\n");

	try {
		await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				chat_id: resolvedDest.chatId,
				text: body,
				...(resolvedDest.threadId ? { message_thread_id: resolvedDest.threadId } : {}),
			}),
		});
		logger.info(
			{ jobId: job.id, chatId: resolvedDest.chatId },
			"background job completion text notification sent",
		);
	} catch (err) {
		logger.warn(
			{ jobId: job.id, error: String(err) },
			"failed to send completion text notification",
		);
	}
}

async function resolveAdminFallback(): Promise<{ chatId: number; threadId?: number } | null> {
	try {
		const { getDb } = await import("../storage/db.js");
		const row = (
			getDb()
				.prepare("SELECT chat_id FROM identity_links WHERE local_user_id = 'admin' LIMIT 1")
				.get() as { chat_id: number } | undefined
		)?.chat_id;
		if (typeof row === "number") {
			return { chatId: row };
		}
	} catch (err) {
		logger.warn({ error: String(err) }, "failed to resolve admin fallback chat");
	}
	return null;
}
