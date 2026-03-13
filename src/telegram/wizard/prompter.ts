/**
 * Wizard Prompter — composable interactive multi-step flows for Telegram.
 *
 * A lightweight, transient prompt system using Telegram inline keyboards.
 * Each wizard instance manages a single message that is edited through
 * sequential prompt steps, keeping the chat clean.
 *
 * This is intentionally separate from the card system (which is for
 * long-lived, stateful UI elements). Wizards are ephemeral: they live
 * for the duration of a multi-step flow and clean up after themselves.
 *
 * @example
 * ```typescript
 * const wizard = createWizardPrompter({ api: bot.api, chatId: 12345 });
 *
 * const action = await wizard.select({
 *   message: "What would you like to do?",
 *   options: [
 *     { value: 'setup', label: 'Set up 2FA', emoji: '🔐' },
 *     { value: 'skip', label: 'Skip for now', emoji: '⏭' },
 *   ],
 * });
 *
 * if (action === 'setup') {
 *   const confirmed = await wizard.confirm({
 *     message: "This will enable TOTP. Continue?",
 *   });
 *   if (confirmed) {
 *     const secret = await wizard.text({
 *       message: "Enter your TOTP secret:",
 *       validate: (v) => v.length < 6 ? "Too short" : undefined,
 *     });
 *   }
 * }
 *
 * await wizard.dismiss();
 * ```
 */

import crypto from "node:crypto";
import { InlineKeyboard } from "grammy";

import { getChildLogger } from "../../logging.js";
import type {
	WizardConfirmParams,
	WizardContext,
	WizardMultiselectParams,
	WizardPrompter,
	WizardSelectParams,
	WizardTextParams,
} from "./types.js";

const logger = getChildLogger({ module: "telegram-wizard" });

/** Max buttons per row in inline keyboard. */
const BUTTONS_PER_ROW = 2;

/** Max options supported in a single select/multiselect prompt. */
const MAX_OPTIONS = 8;

/** Default timeout for waiting on user response (5 minutes). */
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

// ═══════════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Thrown when a wizard prompt times out waiting for user input.
 */
export class WizardTimeoutError extends Error {
	constructor(promptMessage: string) {
		super(`Wizard timed out waiting for response to: ${promptMessage}`);
		this.name = "WizardTimeoutError";
	}
}

/**
 * Thrown when a wizard prompt is cancelled (e.g., wizard dismissed while waiting).
 */
export class WizardCancelledError extends Error {
	constructor() {
		super("Wizard was cancelled");
		this.name = "WizardCancelledError";
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Callback Routing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Global registry of active wizard callback handlers.
 *
 * When a wizard prompt is active, its handler is registered here keyed by
 * wizard ID. The bot's callback_query handler dispatches to the matching
 * wizard. Handlers are automatically cleaned up on completion or timeout.
 */
const activeWizardHandlers = new Map<string, (data: string) => void>();

/**
 * Route a callback_query to the matching wizard handler.
 *
 * Call this from the bot's callback_query handler for data starting with "w:".
 * Returns true if the callback was handled by a wizard.
 *
 * @example
 * ```typescript
 * bot.callbackQuery(/^w:/, async (ctx) => {
 *   const handled = routeWizardCallback(ctx.callbackQuery.data);
 *   if (handled) {
 *     await ctx.answerCallbackQuery();
 *   }
 * });
 * ```
 */
export function routeWizardCallback(callbackData: string): boolean {
	// Format: w:<wizardId>:<payload>
	const parts = callbackData.split(":");
	if (parts.length < 3 || parts[0] !== "w") {
		return false;
	}
	const wizardId = parts[1];
	const handler = activeWizardHandlers.get(wizardId);
	if (handler) {
		handler(callbackData);
		return true;
	}
	return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Text Message Routing
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Global registry of active wizard text input handlers.
 *
 * When a wizard text() prompt is active, its handler is registered here
 * keyed by `chatId:wizardId`. The relay routes incoming text messages
 * through `routeWizardTextMessage` before normal processing.
 */
const activeTextHandlers = new Map<string, (text: string) => void>();

/**
 * Route an incoming text message to a waiting wizard text() prompt.
 *
 * Returns true if the message was consumed by a wizard. The relay should
 * call this before normal message processing and skip the message if true.
 *
 * @example
 * ```typescript
 * // In the relay's message handler:
 * if (routeWizardTextMessage(chatId, messageText)) {
 *   return; // consumed by wizard
 * }
 * // ...normal processing
 * ```
 */
export function routeWizardTextMessage(chatId: number, text: string): boolean {
	// Check all text handlers for this chat
	for (const [key, handler] of activeTextHandlers) {
		if (key.startsWith(`${chatId}:`)) {
			handler(text);
			return true;
		}
	}
	return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wizard ID Generation
// ═══════════════════════════════════════════════════════════════════════════════

/** Generate a short random ID for scoping wizard callbacks. */
function generateWizardId(): string {
	return crypto.randomBytes(3).toString("hex"); // 6 hex chars
}

// ═══════════════════════════════════════════════════════════════════════════════
// Core Implementation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a wizard prompter for composable interactive Telegram flows.
 *
 * The wizard manages a single message that is edited through sequential
 * prompt steps. Each step presents an inline keyboard or waits for text
 * input, then updates the message to show the result before proceeding
 * to the next step.
 *
 * @param ctx - Wizard context with API handle, chat ID, and optional settings
 * @returns A WizardPrompter instance with select, confirm, text, and multiselect methods
 */
export function createWizardPrompter(ctx: WizardContext): WizardPrompter {
	const wizardId = generateWizardId();
	const timeoutMs = ctx.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	let currentMessageId = ctx.messageId ?? null;
	let dismissed = false;

	/**
	 * Wait for a callback matching this wizard, with timeout.
	 * Registers a temporary handler and races against a timer.
	 */
	function waitForCallback(promptMessage: string): Promise<string> {
		return new Promise<string>((resolve, reject) => {
			let timer: NodeJS.Timeout | null = null;

			const cleanup = () => {
				activeWizardHandlers.delete(wizardId);
				if (timer) {
					clearTimeout(timer);
					timer = null;
				}
			};

			activeWizardHandlers.set(wizardId, (data: string) => {
				cleanup();
				resolve(data);
			});

			timer = setTimeout(() => {
				cleanup();
				reject(new WizardTimeoutError(promptMessage));
			}, timeoutMs);
		});
	}

	/**
	 * Wait for a text message from the same chat, with timeout.
	 */
	function waitForTextMessage(promptMessage: string): Promise<string> {
		const handlerKey = `${ctx.chatId}:${wizardId}`;
		return new Promise<string>((resolve, reject) => {
			let timer: NodeJS.Timeout | null = null;

			const cleanup = () => {
				activeTextHandlers.delete(handlerKey);
				if (timer) {
					clearTimeout(timer);
					timer = null;
				}
			};

			activeTextHandlers.set(handlerKey, (text: string) => {
				cleanup();
				resolve(text);
			});

			timer = setTimeout(() => {
				cleanup();
				reject(new WizardTimeoutError(promptMessage));
			}, timeoutMs);
		});
	}

	/**
	 * Send a new message or edit the existing wizard message.
	 * Returns the message ID (for tracking through steps).
	 */
	async function sendOrEdit(text: string, keyboard?: InlineKeyboard): Promise<number> {
		if (currentMessageId) {
			try {
				await ctx.api.editMessageText(ctx.chatId, currentMessageId, text, {
					reply_markup: keyboard,
				});
				return currentMessageId;
			} catch (err) {
				const errStr = String(err);
				// If edit fails because message is too old or deleted, send new
				if (!errStr.includes("message is not modified")) {
					logger.debug(
						{ wizardId, error: errStr },
						"wizard message edit failed, sending new message",
					);
					currentMessageId = null;
				} else {
					return currentMessageId;
				}
			}
		}

		const msg = await ctx.api.sendMessage(ctx.chatId, text, {
			reply_markup: keyboard,
			message_thread_id: ctx.threadId,
		});
		currentMessageId = msg.message_id;
		return msg.message_id;
	}

	/**
	 * Edit the wizard message to show a completed step.
	 */
	async function showResult(prompt: string, result: string): Promise<void> {
		const text = `${prompt}\n> ${result}`;
		await sendOrEdit(text);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Prompt Methods
	// ─────────────────────────────────────────────────────────────────────────

	const select: WizardPrompter["select"] = async <T>(params: WizardSelectParams<T>): Promise<T> => {
		if (dismissed) throw new WizardCancelledError();

		const options = params.options.slice(0, MAX_OPTIONS);
		const keyboard = new InlineKeyboard();

		for (let i = 0; i < options.length; i++) {
			const opt = options[i];
			const label = opt.emoji ? `${opt.emoji} ${opt.label}` : opt.label;
			keyboard.text(label, `w:${wizardId}:${i}`);
			// New row after every BUTTONS_PER_ROW buttons
			if ((i + 1) % BUTTONS_PER_ROW === 0 && i < options.length - 1) {
				keyboard.row();
			}
		}

		await sendOrEdit(params.message, keyboard);

		// Wait for callback
		let callbackData: string;
		try {
			callbackData = await waitForCallback(params.message);
		} catch (err) {
			// On timeout, update message and re-throw
			if (err instanceof WizardTimeoutError) {
				try {
					await sendOrEdit(`${params.message}\n> _Timed out_`);
				} catch {
					// Best effort
				}
			}
			throw err;
		}

		// Parse: w:<wizardId>:<index>
		const parts = callbackData.split(":");
		const index = Number.parseInt(parts[2], 10);
		const selected = options[index];

		if (!selected) {
			logger.warn({ wizardId, index, optionCount: options.length }, "invalid wizard select index");
			throw new Error(`Invalid selection index: ${index}`);
		}

		await showResult(params.message, selected.label);
		return selected.value;
	};

	const confirm: WizardPrompter["confirm"] = async (
		params: WizardConfirmParams,
	): Promise<boolean> => {
		if (dismissed) throw new WizardCancelledError();

		const confirmLabel = params.confirmLabel ?? "Yes";
		const denyLabel = params.denyLabel ?? "No";

		const keyboard = new InlineKeyboard()
			.text(confirmLabel, `w:${wizardId}:1`)
			.text(denyLabel, `w:${wizardId}:0`);

		await sendOrEdit(params.message, keyboard);

		let callbackData: string;
		try {
			callbackData = await waitForCallback(params.message);
		} catch (err) {
			if (err instanceof WizardTimeoutError) {
				try {
					await sendOrEdit(`${params.message}\n> _Timed out_`);
				} catch {
					// Best effort
				}
			}
			throw err;
		}

		const parts = callbackData.split(":");
		const result = parts[2] === "1";
		await showResult(params.message, result ? confirmLabel : denyLabel);
		return result;
	};

	const text: WizardPrompter["text"] = async (params: WizardTextParams): Promise<string> => {
		if (dismissed) throw new WizardCancelledError();

		const promptText = params.placeholder
			? `${params.message}\n\n_${params.placeholder}_`
			: params.message;

		// Send the prompt with force_reply markup.
		// This tells Telegram to show a reply UI for the user.
		const msg = await ctx.api.sendMessage(ctx.chatId, promptText, {
			reply_markup: { force_reply: true, selective: true },
			message_thread_id: ctx.threadId,
		});
		// Track the prompt message so we can clean up, but keep the wizard
		// message ID for future steps.
		const promptMessageId = msg.message_id;

		const attemptTextInput = async (): Promise<string> => {
			let value: string;
			try {
				value = await waitForTextMessage(params.message);
			} catch (err) {
				if (err instanceof WizardTimeoutError) {
					try {
						await ctx.api.editMessageText(
							ctx.chatId,
							promptMessageId,
							`${params.message}\n> _Timed out_`,
						);
					} catch {
						// Best effort
					}
				}
				throw err;
			}

			// Validate if validator provided
			if (params.validate) {
				const errorMsg = params.validate(value);
				if (errorMsg) {
					// Send error and re-prompt
					await ctx.api.sendMessage(ctx.chatId, `${errorMsg}\n\nPlease try again:`, {
						reply_markup: { force_reply: true, selective: true },
						message_thread_id: ctx.threadId,
					});
					return attemptTextInput();
				}
			}

			return value;
		};

		const result = await attemptTextInput();

		// Update the original prompt to show the result
		try {
			await ctx.api.editMessageText(ctx.chatId, promptMessageId, `${params.message}\n> ${result}`);
		} catch {
			// Best effort — message may have been deleted
		}

		return result;
	};

	const multiselect: WizardPrompter["multiselect"] = async <T>(
		params: WizardMultiselectParams<T>,
	): Promise<T[]> => {
		if (dismissed) throw new WizardCancelledError();

		const options = params.options.slice(0, MAX_OPTIONS);
		const selected = new Set<number>();

		// Initialize with initialValues
		if (params.initialValues) {
			for (let i = 0; i < options.length; i++) {
				if (params.initialValues.includes(options[i].value)) {
					selected.add(i);
				}
			}
		}

		/** Build the keyboard reflecting current selection state. */
		function buildKeyboard(): InlineKeyboard {
			const kb = new InlineKeyboard();
			for (let i = 0; i < options.length; i++) {
				const opt = options[i];
				const check = selected.has(i) ? "\u2611" : "\u2610";
				const label = opt.emoji ? `${check} ${opt.emoji} ${opt.label}` : `${check} ${opt.label}`;
				kb.text(label, `w:${wizardId}:t:${i}`);
				if ((i + 1) % BUTTONS_PER_ROW === 0 && i < options.length - 1) {
					kb.row();
				}
			}
			// Done button on its own row
			kb.row().text("Done", `w:${wizardId}:done`);
			return kb;
		}

		/** Format the prompt message with current selection count. */
		function formatMessage(): string {
			const count = selected.size;
			const min = params.minSelections;
			const max = params.maxSelections;
			let suffix = "";
			if (min !== undefined && max !== undefined) {
				suffix = ` (${count} selected, ${min}-${max} required)`;
			} else if (min !== undefined) {
				suffix = ` (${count} selected, min ${min})`;
			} else if (max !== undefined) {
				suffix = ` (${count} selected, max ${max})`;
			} else if (count > 0) {
				suffix = ` (${count} selected)`;
			}
			return `${params.message}${suffix}`;
		}

		await sendOrEdit(formatMessage(), buildKeyboard());

		// Loop: handle toggle and done callbacks
		for (;;) {
			let callbackData: string;
			try {
				callbackData = await waitForCallback(params.message);
			} catch (err) {
				if (err instanceof WizardTimeoutError) {
					try {
						await sendOrEdit(`${params.message}\n> _Timed out_`);
					} catch {
						// Best effort
					}
				}
				throw err;
			}

			const parts = callbackData.split(":");

			if (parts[2] === "done") {
				// Validate selections
				if (params.minSelections !== undefined && selected.size < params.minSelections) {
					// Re-register handler and re-render with error hint
					await sendOrEdit(
						`${formatMessage()}\n\nPlease select at least ${params.minSelections}.`,
						buildKeyboard(),
					);
					continue;
				}
				if (params.maxSelections !== undefined && selected.size > params.maxSelections) {
					await sendOrEdit(
						`${formatMessage()}\n\nPlease select at most ${params.maxSelections}.`,
						buildKeyboard(),
					);
					continue;
				}

				// Collect selected values
				const result: T[] = [];
				for (const idx of selected) {
					result.push(options[idx].value);
				}

				// Show result
				const labels = [...selected].map((i) => options[i].label).join(", ");
				await showResult(params.message, labels || "None");
				return result;
			}

			if (parts[2] === "t") {
				// Toggle
				const index = Number.parseInt(parts[3], 10);
				if (index >= 0 && index < options.length) {
					if (selected.has(index)) {
						selected.delete(index);
					} else {
						// Check max before adding
						if (params.maxSelections === undefined || selected.size < params.maxSelections) {
							selected.add(index);
						}
					}
				}
				// Re-render with updated checkmarks
				await sendOrEdit(formatMessage(), buildKeyboard());
			}
		}
	};

	const dismiss: WizardPrompter["dismiss"] = async (): Promise<void> => {
		dismissed = true;
		// Clean up any lingering handlers
		activeWizardHandlers.delete(wizardId);
		for (const key of activeTextHandlers.keys()) {
			if (key.startsWith(`${ctx.chatId}:${wizardId}`)) {
				activeTextHandlers.delete(key);
			}
		}
		// Remove keyboard from current message
		if (currentMessageId) {
			try {
				await ctx.api.editMessageReplyMarkup(ctx.chatId, currentMessageId, {
					reply_markup: undefined,
				});
			} catch {
				// Best effort — message may have been deleted or already has no keyboard
			}
		}
		logger.debug({ wizardId, chatId: ctx.chatId }, "wizard dismissed");
	};

	logger.debug({ wizardId, chatId: ctx.chatId }, "wizard created");

	return { select, confirm, text, multiselect, dismiss };
}
