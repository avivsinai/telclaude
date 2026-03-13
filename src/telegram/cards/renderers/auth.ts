import { getIdentityLink } from "../../../security/linking.js";
import { format2FASetupInstructions, sendPostAuthStatusCard } from "../../onboarding.js";
import type {
	AuthCardAction,
	AuthCardState,
	CardExecutionContext,
	CardExecutionResult,
	CardInstance,
	CardKind,
	CardRenderer,
	CardRenderResult,
} from "../types.js";
import { btn, esc, keyboard, renderTerminalState } from "./helpers.js";

type K = typeof CardKind.Auth;

export const authRenderer: CardRenderer<K> = {
	render(card: CardInstance<K>): CardRenderResult {
		const s = card.state;

		const terminal = renderTerminalState(card, s.title);
		if (terminal) return terminal;

		let text = `\uD83D\uDD10 *${esc(s.title)}*`;

		if (s.summary) {
			text += `\n\n${esc(s.summary)}`;
		}

		const kb = keyboard();

		switch (s.step) {
			case "setup":
				text += "\n\nSet up two\\-factor authentication to secure your account\\.";
				kb.text("\uD83D\uDD11 Setup 2FA", btn(card, "setup-2fa")).text(
					"\u23ED Skip",
					btn(card, "skip"),
				);
				break;

			case "verify":
				text += "\n\nEnter your 6\\-digit TOTP code using `/auth verify <code>`\\.";
				// No buttons for verify step (text-based input)
				break;

			case "complete":
				text += "\n\n\u2705 _Two\\-factor authentication is active\\._";
				// No action buttons for completed state
				break;

			case "skipped":
				text += "\n\n_2FA setup skipped\\._";
				kb.text("\uD83D\uDD11 Setup Later", btn(card, "setup-2fa"));
				break;
		}

		return { text, parseMode: "MarkdownV2", keyboard: kb };
	},

	reduce(card: CardInstance<K>, action: AuthCardAction): AuthCardState {
		const s = { ...card.state };
		switch (action.type) {
			case "setup-2fa":
				return { ...s, step: "setup" };
			case "verify":
				return { ...s, step: "verify" };
			case "skip":
				return { ...s, step: "skipped" };
			case "logout":
				return s;
			case "disable":
				return s;
		}
	},

	async execute(context: CardExecutionContext<K>): Promise<CardExecutionResult<K>> {
		const { action, card } = context;

		switch (action.type) {
			case "setup-2fa": {
				const localUserId = card.state.localUserId ?? getIdentityLink(card.chatId)?.localUserId;
				if (!localUserId) {
					return {
						callbackText: "Link your identity first",
						callbackAlert: true,
					};
				}

				await context.ctx.api.sendMessage(card.chatId, format2FASetupInstructions(localUserId), {
					parse_mode: "Markdown",
					message_thread_id: card.threadId,
				});

				return {
					state: { ...card.state, step: "verify", localUserId },
					callbackText: "Setup instructions sent",
					rerender: true,
				};
			}

			case "skip":
				await sendPostAuthStatusCard(context.ctx.api, card.chatId, {
					localUserId: card.state.localUserId,
					actorScope: card.actorScope,
					threadId: card.threadId,
				});
				return {
					state: { ...card.state, step: "skipped" },
					callbackText: "2FA setup skipped",
					rerender: true,
				};

			case "verify":
				// Verify is text-based (/auth verify <code>) — not a button action
				return {
					callbackText: "Use /auth verify <code> to verify",
					callbackAlert: true,
				};

			case "logout":
				// TODO: clear TOTP session
				return {
					callbackText: "TOTP session cleared",
				};

			case "disable":
				// TODO: disable TOTP entirely
				return {
					callbackText: "Use /auth disable to disable",
					callbackAlert: true,
				};
		}
	},
};
