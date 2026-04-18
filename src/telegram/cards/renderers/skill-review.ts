/**
 * W9 — Skill draft-review card.
 *
 * Shown before `promoteSkill()` runs so the operator sees:
 *   - Scanner findings aggregated by severity, plus the top few messages.
 *   - Signature state (trusted / community / unknown) with a short digest.
 *   - Auto-install patterns the importer flagged.
 *   - Optional diff summary vs. the prior active version.
 *
 * Buttons: Promote | Reject | Refresh. Promote is disabled when the
 * scanner has blocked the skill (critical/high) or when admin controls
 * are off. Reject marks the card consumed without touching the draft —
 * rejecting is a UI signal only, so operators can iterate on the draft
 * in-place.
 *
 * Invariants:
 *   - This renderer is the ONLY card path wired to `promoteSkill()` for
 *     review-gated flows. The bare `SkillDraft` card stays on the lighter
 *     one-tap promote for backwards compatibility.
 *   - Unsigned skills are not blocked. The "community" badge is
 *     informational — trust is a separate axis from scanner blocking.
 */

import { promoteSkill } from "../../../commands/skills-promote.js";
import type {
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
	SkillReviewCardAction,
	SkillReviewCardState,
	SkillReviewTrust,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.SkillReview;

const TRUST_BADGE: Record<SkillReviewTrust, string> = {
	trusted: "\uD83D\uDD12 trusted",
	community: "\uD83C\uDF10 community",
	unknown: "\u2753 unknown",
};

const SEVERITY_ICON: Record<string, string> = {
	critical: "\uD83D\uDD34",
	high: "\uD83D\uDFE0",
	medium: "\uD83D\uDFE1",
	info: "\u2139\uFE0F",
};

function formatFindingCounts(summary: SkillReviewCardState["findingSummary"]): string {
	const ordered: Array<"critical" | "high" | "medium" | "info"> = [
		"critical",
		"high",
		"medium",
		"info",
	];
	const parts: string[] = [];
	for (const severity of ordered) {
		const entry = summary.find((s) => s.severity === severity);
		if (!entry) continue;
		parts.push(`${severity}=${entry.count}`);
	}
	return parts.length > 0 ? parts.join(" ") : "none";
}

export const skillReviewRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;
		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		const trustBadge = TRUST_BADGE[s.trust];
		const header = [`\uD83D\uDCDD *${esc(s.title)}*`, `*${esc(s.skillName)}* — ${esc(trustBadge)}`];
		if (s.description) {
			header.push(esc(s.description));
		}

		const lines = [...header, ""];

		lines.push(`*Scanner:* ${esc(formatFindingCounts(s.findingSummary))}`);
		if (s.scannerBlocked) {
			lines.push(`_${esc("Blocked by scanner — Promote disabled.")}_`);
		}
		for (const finding of s.topFindings.slice(0, 4)) {
			const icon = SEVERITY_ICON[finding.severity] ?? "\u25AA";
			const loc = finding.file ? ` \u2014 _${esc(finding.file)}_` : "";
			lines.push(`  ${icon} ${esc(finding.message)}${loc}`);
		}

		lines.push("");
		lines.push(`*Signature:* ${esc(trustBadge)}`);
		if (s.trustDetail) {
			lines.push(`  _${esc(s.trustDetail)}_`);
		}

		if (s.autoInstallPatterns.length > 0) {
			lines.push("");
			lines.push("*Auto-install patterns matched:*");
			for (const pattern of s.autoInstallPatterns.slice(0, 5)) {
				lines.push(`  \u2022 ${esc(pattern)}`);
			}
		}

		if (s.diffSummary) {
			lines.push("");
			lines.push(`*Diff vs active:* ${esc(s.diffSummary)}`);
		}

		if (s.decision === "promoted") {
			lines.push("", `_\u2705 ${esc("Promoted.")}_`);
		} else if (s.decision === "rejected") {
			lines.push("", `_\u274C ${esc("Rejected. Draft left in place.")}_`);
		}
		if (s.decisionError) {
			lines.push("", `_${esc(`Error: ${s.decisionError}`)}_`);
		}

		const kb = keyboard();
		const canPromote = s.adminControlsEnabled && !s.scannerBlocked && !s.decision;
		if (canPromote) {
			kb.text("\u2705 Promote", btn(card, "promote"));
		}
		if (s.adminControlsEnabled && !s.decision) {
			kb.text("\u274C Reject", btn(card, "reject"));
		}
		if (canPromote || (s.adminControlsEnabled && !s.decision)) {
			kb.row();
		}
		kb.text("\uD83D\uDD04 Refresh", btn(card, "refresh"));

		return { text: lines.join("\n"), parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, _action: SkillReviewCardAction): SkillReviewCardState {
		return card.state;
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const s = card.state;

		switch (action.type) {
			case "refresh":
				return {
					callbackText: "Refreshed",
					rerender: true,
				};

			case "reject": {
				if (!s.adminControlsEnabled) {
					return { callbackText: "Only admin can reject drafts.", callbackAlert: true };
				}
				if (s.decision) {
					return { callbackText: "Already decided.", callbackAlert: true };
				}
				return {
					state: { ...s, decision: "rejected" },
					status: "consumed",
					callbackText: `Rejected ${s.skillName}`,
					rerender: true,
				};
			}

			case "promote": {
				if (!s.adminControlsEnabled) {
					return { callbackText: "Only admin can promote.", callbackAlert: true };
				}
				if (s.scannerBlocked) {
					return {
						callbackText: "Scanner blocked this skill.",
						callbackAlert: true,
					};
				}
				if (s.decision) {
					return { callbackText: "Already decided.", callbackAlert: true };
				}
				const result = promoteSkill(s.skillName);
				if (!result.success) {
					return {
						state: { ...s, decisionError: result.error },
						callbackText: result.error ?? "Promotion failed",
						callbackAlert: true,
						rerender: true,
					};
				}
				return {
					state: { ...s, decision: "promoted", decisionError: undefined },
					status: "consumed",
					callbackText: `Promoted ${s.skillName}`,
					rerender: true,
				};
			}
		}
	},
};
