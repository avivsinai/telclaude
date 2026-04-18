/**
 * W10 — SystemHealthCard renderer.
 *
 * Two views:
 *  - "list": one line per health item with a status icon; up to
 *    `SYSTEM_HEALTH_MAX_FIX_BUTTONS` inline "Fix" buttons (one per degraded
 *    item, indexed).
 *  - "remediation": detail of one item + the central remediation command
 *    sourced from `remediation-commands.ts` (never hardcoded in this file).
 *
 * The reducer resolves `fix-N` back to the Nth item in `state.items` at the
 * time the button was rendered — callback-token revision bumps invalidate
 * stale buttons if the item list changes.
 */

import {
	getRemediation,
	type RemediationEntry,
	type RemediationKey,
} from "../../remediation-commands.js";
import { collectSystemHealth } from "../../status-overview.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SystemHealthCardAction,
	SystemHealthCardItem,
	SystemHealthCardState,
	SystemHealthStatus,
} from "../types.js";
import { SYSTEM_HEALTH_MAX_FIX_BUTTONS } from "../types.js";
import { btn, esc, formatAge, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.SystemHealth;

const STATUS_ICON: Record<SystemHealthStatus, string> = {
	ok: "\uD83D\uDFE2", // green circle
	degraded: "\uD83D\uDFE1", // yellow circle
	auth_expired: "\uD83D\uDD34", // red circle
	unreachable: "\u274C", // cross mark
	unknown: "\u26AA", // white circle
};

const STATUS_LABEL: Record<SystemHealthStatus, string> = {
	ok: "ok",
	degraded: "degraded",
	auth_expired: "auth expired",
	unreachable: "unreachable",
	unknown: "unknown",
};

function headerText(state: SystemHealthCardState): string {
	const icon = STATUS_ICON[state.overallStatus];
	const label = STATUS_LABEL[state.overallStatus];
	const title = `${icon} *${esc("System Health")}* — ${esc(label)}`;
	const sub =
		state.issueCount === 0
			? esc("all green")
			: esc(state.issueCount === 1 ? "1 issue" : `${state.issueCount} issues`);
	return `${title}\n${sub}`;
}

function indexOfNthIssue(state: SystemHealthCardState, n: number): number {
	let count = 0;
	for (let i = 0; i < state.items.length; i += 1) {
		const item = state.items[i];
		if (item.status === "ok" || item.status === "unknown") continue;
		if (count === n) return i;
		count += 1;
	}
	return -1;
}

function renderList(card: CardInstance<K>, state: SystemHealthCardState): CardRenderResult {
	let text = headerText(state);
	text += "\n";
	for (const item of state.items) {
		const icon = STATUS_ICON[item.status];
		const detail = item.detail ? ` \u2014 ${esc(item.detail)}` : "";
		text += `\n${icon} *${esc(item.label)}*${detail}`;
	}
	text += `\n\n_Updated ${esc(formatAge(state.collectedAtMs))}_`;

	const kb = keyboard();
	let issueIndex = 0;
	for (const item of state.items) {
		if (item.status === "ok" || item.status === "unknown") continue;
		if (issueIndex >= SYSTEM_HEALTH_MAX_FIX_BUTTONS) break;
		if (issueIndex > 0 && issueIndex % 2 === 0) {
			kb.row();
		}
		kb.text(`\uD83D\uDEE0 ${item.label}`, btn(card, `fix-${issueIndex}`));
		issueIndex += 1;
	}
	if (issueIndex > 0) kb.row();
	kb.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

function renderRemediation(card: CardInstance<K>, state: SystemHealthCardState): CardRenderResult {
	const item = state.items.find((it) => it.id === state.selectedItemId);
	const remediation: RemediationEntry | undefined = item?.remediationKey
		? getRemediation(item.remediationKey as RemediationKey)
		: undefined;

	const title = item ? item.label : "System Health";
	const icon = item ? STATUS_ICON[item.status] : STATUS_ICON.unknown;
	let text = `${icon} *${esc(title)}*`;
	if (item?.detail) {
		text += `\n${esc(item.detail)}`;
	}
	if (remediation) {
		text += `\n\n*${esc(remediation.title)}*\n${esc(remediation.explanation)}`;
		text += `\n\n\u0060${esc(remediation.command)}\u0060`;
		if (remediation.docsPath) {
			text += `\n\n_See ${esc(remediation.docsPath)}_`;
		}
	} else {
		text += `\n\n${esc("No remediation available — see docs for this signal.")}`;
	}
	text += `\n\n_Updated ${esc(formatAge(state.collectedAtMs))}_`;

	const kb = keyboard()
		.text("\u25C0 Back", btn(card, "view-list"))
		.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));
	return { text, parseMode: "MarkdownV2", keyboard: kb };
}

function buildRefreshedState(base: SystemHealthCardState): SystemHealthCardState {
	// Pure reducer — the actual refresh happens in execute(). This keeps
	// render() deterministic when called without an async probe (tests).
	return { ...base };
}

export const systemHealthRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const terminal = renderTerminalState(card, card.state.title);
		if (terminal) return terminal;

		return card.state.view === "remediation"
			? renderRemediation(card, card.state)
			: renderList(card, card.state);
	},

	reduce(card: CardInstance<K>, action: SystemHealthCardAction): SystemHealthCardState {
		const state = card.state;
		switch (action.type) {
			case "refresh":
				return buildRefreshedState(state);
			case "view-list":
				return { ...state, view: "list", selectedItemId: undefined };
			default: {
				const n = Number.parseInt(action.type.slice(4), 10);
				if (!Number.isFinite(n)) return state;
				const idx = indexOfNthIssue(state, n);
				if (idx < 0) return state;
				const item = state.items[idx] as SystemHealthCardItem;
				return {
					...state,
					view: "remediation",
					selectedItemId: item.id,
				};
			}
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		if (action.type === "refresh") {
			const snapshot = await collectSystemHealth().catch(() => null);
			if (!snapshot) {
				return {
					callbackText: "Health probe failed — see logs",
					callbackAlert: true,
					rerender: false,
				};
			}
			const nextState: SystemHealthCardState = {
				...card.state,
				view: card.state.view ?? "list",
				overallStatus: snapshot.overallStatus as SystemHealthStatus,
				items: snapshot.items.map((item) => ({
					id: item.id,
					label: item.label,
					status: item.status as SystemHealthStatus,
					detail: item.detail,
					remediationKey: item.remediation,
					observedAtMs: item.observedAtMs,
				})),
				issueCount: snapshot.issueCount,
				collectedAtMs: snapshot.collectedAtMs,
				selectedItemId:
					card.state.view === "remediation" && card.state.selectedItemId
						? snapshot.items.some((i) => i.id === card.state.selectedItemId)
							? card.state.selectedItemId
							: undefined
						: undefined,
			};
			const callbackText =
				snapshot.issueCount === 0
					? "All systems nominal"
					: `${snapshot.issueCount} issue${snapshot.issueCount === 1 ? "" : "s"}`;
			return {
				state: nextState,
				callbackText,
				rerender: true,
			};
		}

		if (action.type === "view-list") {
			return {
				state: { ...card.state, view: "list", selectedItemId: undefined },
				callbackText: "Back to list",
				rerender: true,
			};
		}

		// fix-N path — resolve the Nth issue and switch to remediation view.
		const n = Number.parseInt(action.type.slice(4), 10);
		if (!Number.isFinite(n)) {
			return { callbackText: "Unknown action", callbackAlert: true, rerender: false };
		}
		const idx = indexOfNthIssue(card.state, n);
		if (idx < 0) {
			return { callbackText: "Issue no longer present", callbackAlert: true, rerender: false };
		}
		const item = card.state.items[idx] as SystemHealthCardItem;
		const nextState: SystemHealthCardState = {
			...card.state,
			view: "remediation",
			selectedItemId: item.id,
		};
		const remediation = item.remediationKey
			? getRemediation(item.remediationKey as RemediationKey)
			: undefined;
		const callbackText = remediation ? `Fix: ${remediation.title}` : `Showing ${item.label}`;
		return { state: nextState, callbackText, rerender: true };
	},
};

/**
 * Guard helper surfaced for tests — resolves the item index for the Nth
 * issue in the state's items array. Mirrors the internal reducer logic.
 */
export function resolveNthIssueIndex(state: SystemHealthCardState, n: number): number {
	return indexOfNthIssue(state, n);
}
