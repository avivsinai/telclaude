/**
 * Debounced Typing Indicator Controller
 *
 * Prevents typing indicator flicker on fast responses by debouncing
 * the initial sendChatAction call. Once the debounce fires, typing
 * repeats every 4s (Telegram typing expires after 5s) until stop().
 *
 * Usage:
 *   const typing = createTypingController(api, chatId);
 *   typing.start();
 *   // ... process message ...
 *   typing.stop();
 *
 * If the response completes within the debounce window (200ms default),
 * no typing indicator is ever sent — eliminating flicker.
 */

import type { Api } from "grammy";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "telegram-typing" });

export interface TypingController {
	/** Start typing with debounce — cancelled if stop() called before debounce fires. */
	start(): void;
	/** Stop typing — cancel pending debounce and repeat timers. Idempotent. */
	stop(): void;
	/** Change the action type mid-stream (e.g., "upload_document", "record_voice"). */
	setAction(action: string): void;
}

export interface TypingControllerOptions {
	/** Delay before the first sendChatAction fires. Default: 200ms. */
	debounceMs?: number;
	/** Interval between repeated sendChatAction calls. Default: 4000ms. */
	repeatIntervalMs?: number;
	/** Forum topic thread ID. */
	messageThreadId?: number;
}

const DEFAULT_DEBOUNCE_MS = 200;
const DEFAULT_REPEAT_INTERVAL_MS = 4000;

/**
 * Create a typing controller backed by the grammy Api.
 * Supports setAction() for switching between "typing", "upload_document", etc.
 */
export function createTypingController(
	api: Api,
	chatId: number,
	opts?: TypingControllerOptions,
): TypingController {
	const messageThreadId = opts?.messageThreadId;
	let action = "typing";

	return createTypingControllerFromCallback(
		() => {
			api
				.sendChatAction(chatId, action as Parameters<Api["sendChatAction"]>[1], {
					message_thread_id: messageThreadId,
				})
				.catch((err) => {
					logger.debug({ chatId, error: String(err) }, "typing indicator send failed");
				});
		},
		opts,
		(newAction) => {
			action = newAction;
		},
	);
}

/**
 * Create a typing controller backed by a generic callback.
 * Useful when the caller already has a sendComposing() wrapper.
 */
export function createTypingControllerFromCallback(
	sendFn: () => void,
	opts?: Pick<TypingControllerOptions, "debounceMs" | "repeatIntervalMs">,
	onSetAction?: (action: string) => void,
): TypingController {
	const debounceMs = opts?.debounceMs ?? DEFAULT_DEBOUNCE_MS;
	const repeatIntervalMs = opts?.repeatIntervalMs ?? DEFAULT_REPEAT_INTERVAL_MS;

	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	let repeatTimer: ReturnType<typeof setInterval> | null = null;
	let stopped = false;

	function startRepeat(): void {
		if (stopped) return;
		// Send immediately on debounce fire, then repeat
		sendFn();
		repeatTimer = setInterval(() => {
			if (!stopped) {
				sendFn();
			}
		}, repeatIntervalMs);
	}

	function cleanup(): void {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
		if (repeatTimer) {
			clearInterval(repeatTimer);
			repeatTimer = null;
		}
	}

	return {
		start(): void {
			if (stopped) return;
			// Cancel any existing timers (idempotent restart)
			cleanup();
			debounceTimer = setTimeout(startRepeat, debounceMs);
		},

		stop(): void {
			stopped = true;
			cleanup();
		},

		setAction(newAction: string): void {
			onSetAction?.(newAction);
		},
	};
}
