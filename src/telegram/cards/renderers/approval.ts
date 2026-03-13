import type {
	ApprovalCardAction,
	ApprovalCardState,
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Approval;

export const approvalRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) {
			// Add outcome detail for consumed approvals
			if (card.status === "consumed") {
				const outcome = s.approved ? "\u2705 Approved" : s.denied ? "\u274C Denied" : "Processed";
				return {
					text: `\uD83D\uDD10 *${esc(s.title)}*\n\n${esc(s.body)}\n\n_${esc(outcome)}_`,
					parseMode: "MarkdownV2",
					keyboard: null,
				};
			}
			return terminal;
		}

		let text = `\uD83D\uDD10 *${esc(s.title)}*\n\n${esc(s.body)}`;

		if (s.explanation) {
			text += `\n\n\uD83D\uDCA1 _${esc(s.explanation)}_`;
		}

		const kb = keyboard()
			.text("\u2705 Approve", btn(card, "approve"))
			.text("\u274C Deny", btn(card, "deny"))
			.row()
			.text("\uD83D\uDCA1 Explain", btn(card, "explain"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: ApprovalCardAction): ApprovalCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "approve":
				return { ...s, approved: true, denied: false };
			case "deny":
				return { ...s, denied: true, approved: false };
			case "explain":
				return { ...s, explanation: s.explanation ?? "Pending explanation..." };
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "approve":
				// TODO: call existing approval system (approvals.resolveApproval)
				// The entityRef should contain the approval nonce.
				return {
					state: { ...card.state, approved: true, denied: false },
					status: "consumed",
					callbackText: "Approved",
				};

			case "deny":
				// TODO: call existing approval system (approvals.resolveApproval)
				return {
					state: { ...card.state, denied: true, approved: false },
					status: "consumed",
					callbackText: "Denied",
				};

			case "explain":
				// TODO: generate explanation for the approval request
				return {
					state: { ...card.state, explanation: "This action requires elevated permissions." },
					callbackText: "Explanation shown",
				};

			case "refresh":
				return { rerender: true };
		}
	},
};
