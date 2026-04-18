import { getChildLogger } from "../../../logging.js";
import {
	consumeApproval,
	denyApproval,
	grantAllowlist,
	type PendingApproval,
} from "../../../security/approvals.js";
import { type ApprovalScope, scopeAllowedForRisk } from "../../../security/risk-tiers.js";
import type {
	ApprovalScopeCardAction,
	ApprovalScopeCardState,
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

const logger = getChildLogger({ module: "approval-scope-card" });

type K = typeof CardKind.ApprovalScope;

function scopeFromAction(action: ApprovalScopeCardAction): ApprovalScope | null {
	switch (action.type) {
		case "approve-once":
			return "once";
		case "approve-session":
			return "session";
		case "approve-always":
			return "always";
		default:
			return null;
	}
}

function humanizeRisk(risk: ApprovalScopeCardState["riskTier"]): string {
	switch (risk) {
		case "low":
			return "Low risk";
		case "medium":
			return "Medium risk";
		case "high":
			return "High risk";
	}
}

export const approvalScopeRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) {
			if (card.status === "consumed") {
				const outcome = s.denied
					? "\u274C Denied"
					: s.scopeChosen === "once"
						? "\u2705 Approved (this request)"
						: s.scopeChosen === "session"
							? "\u2705 Approved (this session)"
							: s.scopeChosen === "always"
								? "\u2705 Approved (always)"
								: "Processed";
				return {
					text: `\uD83D\uDD10 *${esc(s.title)}*\n\n${esc(s.body)}\n\n_${esc(outcome)}_`,
					parseMode: "MarkdownV2",
					keyboard: null,
				};
			}
			return terminal;
		}

		const riskLabel = humanizeRisk(s.riskTier);
		const bodyPreview = s.body.length > 500 ? `${s.body.slice(0, 500)}...` : s.body;

		let text = `\uD83D\uDD10 *${esc(s.title)}*\n\n${esc(bodyPreview)}`;
		text += `\n\n*Risk:* ${esc(riskLabel)}`;
		if (s.toolKey) {
			text += `  \u00b7 *Tool:* \`${esc(s.toolKey)}\``;
		}
		if (s.explanation) {
			text += `\n\n\uD83D\uDCA1 _${esc(s.explanation)}_`;
		}
		if (s.riskTier === "high") {
			text += `\n\n\u26A0\uFE0F _High-risk actions always prompt; "always" is disabled._`;
		}

		const kb = keyboard();
		const enabled = new Set<ApprovalScope>(s.scopesEnabled);
		if (enabled.has("once")) {
			kb.text("\u2705 Once", btn(card, "approve-once"));
		}
		if (enabled.has("session")) {
			kb.text("\uD83D\uDD04 Session", btn(card, "approve-session"));
		}
		if (enabled.has("always")) {
			kb.text("\uD83D\uDCCC Always", btn(card, "approve-always"));
		}
		kb.row();
		kb.text("\u274C Deny", btn(card, "deny"));

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: ApprovalScopeCardAction): ApprovalScopeCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "approve-once":
				return { ...s, scopeChosen: "once", denied: false };
			case "approve-session":
				return { ...s, scopeChosen: "session", denied: false };
			case "approve-always":
				return { ...s, scopeChosen: "always", denied: false };
			case "deny":
				return { ...s, denied: true, scopeChosen: undefined };
			case "refresh":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;
		const actorId = context.ctx.from.id;
		const nonce = card.entityRef.replace(/^approval:/, "");

		if (action.type === "deny") {
			const result = denyApproval(nonce, card.chatId);
			if (!result.success) {
				logger.warn({ nonce, error: result.error }, "approval-scope card: denyApproval failed");
				return {
					callbackText: `Denial failed: ${result.error}`,
					callbackAlert: true,
				};
			}
			return {
				state: { ...card.state, denied: true, scopeChosen: undefined },
				status: "consumed",
				callbackText: "Denied",
			};
		}

		if (action.type === "refresh") {
			return { rerender: true };
		}

		const scope = scopeFromAction(action);
		if (!scope) {
			return { callbackText: "Unknown action", callbackAlert: true };
		}

		// Enforce the tier cap at execute time (defense-in-depth beyond the
		// UI's scopesEnabled list).
		if (!scopeAllowedForRisk(card.state.riskTier, scope)) {
			logger.warn(
				{
					toolKey: card.state.toolKey,
					riskTier: card.state.riskTier,
					attemptedScope: scope,
				},
				"approval-scope card: scope blocked by risk cap",
			);
			return {
				callbackText: `Cannot grant "${scope}" for ${card.state.riskTier}-risk action`,
				callbackAlert: true,
			};
		}

		// Consume the pending approval first so the action actually proceeds.
		const consume = consumeApproval(nonce, card.chatId);
		if (!consume.success) {
			logger.warn({ nonce, error: consume.error }, "approval-scope card: consumeApproval failed");
			return {
				callbackText: `Approval failed: ${consume.error}`,
				callbackAlert: true,
			};
		}

		// Persist the grant (session/always) or a one-shot marker (once).
		try {
			grantAllowlistForApproval(consume.data, scope, actorId);
		} catch (err) {
			logger.error(
				{ err: String(err), toolKey: card.state.toolKey, scope },
				"approval-scope card: grantAllowlist failed",
			);
			return {
				callbackText: "Approved, but allowlist write failed — run will proceed without persistence",
				callbackAlert: true,
			};
		}

		const confirm =
			scope === "once"
				? "Approved (once)"
				: scope === "session"
					? "Approved for this session"
					: "Approved (always)";

		return {
			state: { ...card.state, scopeChosen: scope, denied: false },
			status: "consumed",
			callbackText: confirm,
		};
	},
};

/**
 * Internal: write the grant into the allowlist. Only called when the scope
 * is not "once" (we still record "once" so an immediately-following tool
 * call of the same (user, tool) pair auto-approves).
 */
function grantAllowlistForApproval(
	approval: PendingApproval,
	scope: ApprovalScope,
	actorId: number,
): void {
	const toolKey = approval.toolKey ?? "legacy:unknown";
	const userId = String(actorId);
	grantAllowlist({
		userId,
		tier: approval.tier,
		toolKey,
		scope,
		sessionKey: scope === "session" ? (approval.sessionKey ?? null) : null,
		chatId: approval.chatId,
	});
}
