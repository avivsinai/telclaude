import { cancelJob, getJobByShortId } from "../../../background/index.js";
import { getChildLogger } from "../../../logging.js";
import type {
	BackgroundJobCardAction,
	BackgroundJobCardState,
	BackgroundJobListCardAction,
	BackgroundJobListCardState,
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
} from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

const logger = getChildLogger({ module: "background-job-card" });

type K = typeof CardKind.BackgroundJob;

function statusIcon(status: BackgroundJobCardState["status"]): string {
	switch (status) {
		case "queued":
			return "\u23F3"; // hourglass
		case "running":
			return "\u2699\uFE0F"; // gear
		case "completed":
			return "\u2705"; // check
		case "failed":
			return "\u274C"; // cross
		case "cancelled":
			return "\uD83D\uDEAB"; // prohibited
		case "interrupted":
			return "\u26A0\uFE0F"; // warning
		default:
			return "\u2753"; // question mark
	}
}

function isTerminalState(status: BackgroundJobCardState["status"]): boolean {
	return (
		status === "completed" ||
		status === "failed" ||
		status === "cancelled" ||
		status === "interrupted"
	);
}

export const backgroundJobRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal && !isTerminalState(s.status)) {
			return terminal;
		}

		const icon = statusIcon(s.status);
		let text = `${icon} *${esc(s.title)}*`;

		text += `\n\n*Status:* ${esc(s.status)}`;
		text += `\n*Job:* \`${esc(s.shortId)}\` \\(${esc(s.payloadKind)}\\)`;

		if (s.description) {
			text += `\n\n${esc(s.description)}`;
		}

		if (s.status === "running" && s.startedAtMs) {
			text += `\n\n_Running since ${esc(formatAge(s.startedAtMs))}_`;
		} else if (s.status === "queued") {
			text += `\n\n_Queued ${esc(formatAge(s.createdAtMs))}_`;
		}

		if (isTerminalState(s.status)) {
			if (s.resultSummary) {
				text += `\n\n${esc(s.resultSummary)}`;
			}
			if (s.errorMessage) {
				text += `\n\n*Error:* ${esc(s.errorMessage)}`;
			}
			if (s.outputPreview) {
				// Output preview already sanitized on server side; render as code fence.
				const sanitized = s.outputPreview.slice(0, 1_500);
				text += `\n\n\`\`\`\n${esc(sanitized)}\n\`\`\``;
			}
			if (s.completedAtMs) {
				text += `\n\n_Finished ${esc(formatAge(s.completedAtMs))}_`;
			}
		}

		const kb = keyboard();
		if (!isTerminalState(s.status)) {
			kb.text("\uD83D\uDEAB Cancel", btn(card, "cancel-background-job"));
		}
		kb.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, _action: BackgroundJobCardAction): BackgroundJobCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "cancel-background-job": {
				const { job, transitioned } = cancelJob(
					// entityRef is "bg:<shortId>" — fetch the concrete job for its id.
					(getJobByShortId(card.state.shortId) ?? { id: "" }).id,
				);
				if (!job) {
					return {
						callbackText: "Job not found",
						callbackAlert: true,
					};
				}
				if (!transitioned) {
					return {
						state: {
							...card.state,
							status: job.status as BackgroundJobCardState["status"],
							resultSummary: job.result?.message ?? card.state.resultSummary,
							errorMessage: job.error ?? undefined,
							completedAtMs: job.completedAtMs ?? card.state.completedAtMs,
							lastRefreshedAtMs: Date.now(),
						},
						status: isTerminalState(job.status as BackgroundJobCardState["status"])
							? "consumed"
							: undefined,
						callbackText: `Already ${job.status}`,
						rerender: true,
					};
				}
				logger.info({ jobId: job.id }, "background job cancelled via card");
				return {
					state: {
						...card.state,
						status: "cancelled",
						resultSummary: "Cancelled by operator",
						completedAtMs: job.completedAtMs ?? Date.now(),
						lastRefreshedAtMs: Date.now(),
					},
					status: "consumed",
					callbackText: "Cancelled",
					rerender: true,
				};
			}
			case "refresh": {
				const latest = getJobByShortId(card.state.shortId);
				if (!latest) {
					return {
						state: { ...card.state, lastRefreshedAtMs: Date.now() },
						callbackText: "Job missing",
						rerender: true,
					};
				}
				const nextState: BackgroundJobCardState = {
					...card.state,
					status: latest.status as BackgroundJobCardState["status"],
					resultSummary: latest.result?.message,
					errorMessage: latest.error ?? undefined,
					outputPreview:
						[latest.result?.stdout, latest.result?.stderr].filter(Boolean).join("\n---\n") ||
						undefined,
					startedAtMs: latest.startedAtMs ?? undefined,
					completedAtMs: latest.completedAtMs ?? undefined,
					lastRefreshedAtMs: Date.now(),
				};
				return {
					state: nextState,
					status: isTerminalState(nextState.status) ? "consumed" : undefined,
					callbackText: `Status: ${latest.status}`,
					rerender: true,
				};
			}
			default: {
				const _exhaustive: never = action;
				return { callbackText: `Unknown action: ${String(_exhaustive)}`, callbackAlert: true };
			}
		}
	},
};

type LK = typeof CardKind.BackgroundJobList;

export const backgroundJobListRenderer: CardRenderer<LK> = {
	render(card: CardInstance<LK>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		let text = `\uD83D\uDCC3 *${esc(s.title)}*\n`;

		if (s.entries.length === 0) {
			text += "\n_No background jobs in the last 7 days_";
		} else {
			for (const entry of s.entries.slice(0, 10)) {
				text += `\n${statusIcon(entry.status)} \`${esc(entry.shortId)}\` — ${esc(entry.label)}`;
				text += `\n  _${esc(entry.status)} · ${esc(formatAge(entry.createdAtMs))}_`;
			}
		}

		if (s.lastRefreshedAtMs) {
			text += `\n\n_Last refreshed ${esc(formatAge(s.lastRefreshedAtMs))}_`;
		}

		text +=
			"\n\n_Tap `/background show <id>` for full status or `/background cancel <id>` to abort._";

		const kb = keyboard().text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<LK>, _action: BackgroundJobListCardAction): BackgroundJobListCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<LK>): Promise<CardExecutionResult<LK>> {
		const { card } = context;
		// Refresh is the only action; fetch fresh list at the call site (action.type === "refresh").
		const { listJobs } = await import("../../../background/index.js");
		const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
		const jobs = listJobs({ sinceMs: sevenDaysAgo, limit: 25 });
		return {
			state: {
				...card.state,
				entries: jobs.map((job) => ({
					shortId: job.shortId,
					label: job.title,
					status: job.status as BackgroundJobCardState["status"],
					createdAtMs: job.createdAtMs,
				})),
				lastRefreshedAtMs: Date.now(),
			},
			callbackText: "Refreshed",
			rerender: true,
		};
	},
};
