/**
 * Status Reaction Controller
 *
 * Sets emoji reactions on the bot's own reply message to indicate execution
 * progress. Reactions evolve through stages as the agent processes a request.
 *
 * Integration contract (for streaming.ts / session handler):
 * 1. Create controller when bot sends its first reply message:
 *      const reactions = createStatusReactionController(bot.api, chatId, messageId);
 * 2. Call setQueued() immediately after message creation.
 * 3. Call setThinking() when agent starts processing.
 * 4. Call setTool(toolName) on each tool use event — maps tool names to stages.
 * 5. Call setDone() when streaming completes successfully.
 * 6. Call setError() on error.
 *
 * Telegram constraints:
 * - Only a fixed set of emoji are allowed as reactions (ReactionTypeEmoji).
 * - Bots can only react to messages in chats where they have permission.
 * - All API errors are caught and logged silently — never crash the stream.
 */

import type { Api } from "grammy";
import type { ReactionTypeEmoji } from "grammy/types";

import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "status-reactions" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Reaction stages representing agent execution progress.
 */
export type ReactionStage =
	| "queued" // Message received, waiting to process
	| "thinking" // Agent is reasoning
	| "coding" // Agent is writing/editing code
	| "searching" // Agent is searching/reading files
	| "web" // Agent is doing web fetch/search
	| "done" // Completed successfully
	| "error"; // Error occurred

/**
 * Public interface for controlling status reactions.
 */
export interface StatusReactionController {
	/** Set queued stage (message received, waiting to process). */
	setQueued(): void;
	/** Set thinking stage (agent is reasoning). */
	setThinking(): void;
	/** Map a tool name to the appropriate stage and set it. */
	setTool(toolName?: string): void;
	/** Set coding stage explicitly. */
	setCoding(): void;
	/** Set searching stage explicitly. */
	setSearching(): void;
	/** Set web stage explicitly. */
	setWeb(): void;
	/** Set done stage. Auto-clears after a delay. */
	setDone(): Promise<void>;
	/** Set error stage. Persists (no auto-clear). */
	setError(): Promise<void>;
	/** Remove all reactions. */
	clear(): Promise<void>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Emoji mapping
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Map from reaction stage to Telegram-allowed emoji.
 *
 * Telegram restricts bot reactions to a fixed set (ReactionTypeEmoji["emoji"]).
 * Some intuitive emoji (🔍, ✅, ❌) are not in the allowed set, so we use
 * the closest permitted alternatives.
 */
const STAGE_EMOJI: Record<ReactionStage, ReactionTypeEmoji["emoji"]> = {
	queued: "👀",
	thinking: "🤔",
	coding: "👨‍💻",
	searching: "🤓",
	web: "⚡",
	done: "👍",
	error: "💔",
};

/** Stages that are terminal (done, error). */
const TERMINAL_STAGES: ReadonlySet<ReactionStage> = new Set(["done", "error"]);

// ═══════════════════════════════════════════════════════════════════════════════
// Tool name → stage mapping
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Map tool names to reaction stages.
 *
 * Unrecognised tools default to 'thinking'.
 */
function toolNameToStage(toolName?: string): ReactionStage {
	if (!toolName) return "thinking";

	switch (toolName) {
		// Coding / editing tools
		case "Write":
		case "Edit":
		case "NotebookEdit":
			return "coding";

		// File search / reading tools
		case "Read":
		case "Glob":
		case "Grep":
			return "searching";

		// Web tools
		case "WebFetch":
		case "WebSearch":
			return "web";

		// Bash defaults to coding (most common use case)
		case "Bash":
			return "coding";

		default:
			return "thinking";
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Controller options
// ═══════════════════════════════════════════════════════════════════════════════

export interface StatusReactionOptions {
	/** Debounce interval for non-terminal state changes. Default: 300ms. */
	debounceMs?: number;
	/** Stall warning threshold. Logs a warning if no state change. Default: 10000ms. */
	stallWarnMs?: number;
	/** Hard stall threshold. Logs an error if no state change. Default: 30000ms. */
	stallHardMs?: number;
	/** Delay before auto-clearing the done reaction. Default: 5000ms. */
	doneClearDelayMs?: number;
}

const DEFAULT_OPTIONS = {
	debounceMs: 300,
	stallWarnMs: 10_000,
	stallHardMs: 30_000,
	doneClearDelayMs: 5_000,
} as const;

// ═══════════════════════════════════════════════════════════════════════════════
// Implementation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a status reaction controller for a specific bot message.
 *
 * @param api - grammy Api instance (typically bot.api)
 * @param chatId - Chat containing the message
 * @param messageId - The bot's reply message to set reactions on
 * @param options - Timing configuration
 */
export function createStatusReactionController(
	api: Api,
	chatId: number,
	messageId: number,
	options?: StatusReactionOptions,
): StatusReactionController {
	const opts = { ...DEFAULT_OPTIONS, ...options };

	// Current state
	let currentStage: ReactionStage | null = null;
	let disposed = false;

	// Promise serialisation queue — all reaction updates run sequentially.
	let queue: Promise<void> = Promise.resolve();

	// Debounce timer for non-terminal state changes.
	let debounceTimer: NodeJS.Timeout | null = null;

	// Stall detection timers.
	let stallWarnTimer: NodeJS.Timeout | null = null;
	let stallHardTimer: NodeJS.Timeout | null = null;

	// Auto-clear timer for done state.
	let doneClearTimer: NodeJS.Timeout | null = null;

	// ─── Helpers ────────────────────────────────────────────────────────

	function enqueue(fn: () => Promise<void>): void {
		queue = queue.then(fn).catch((err) => {
			logger.debug({ error: String(err), chatId, messageId }, "reaction queue error (suppressed)");
		});
	}

	async function applyReaction(emoji: ReactionTypeEmoji["emoji"]): Promise<void> {
		if (disposed) return;
		try {
			await api.setMessageReaction(chatId, messageId, [{ type: "emoji", emoji }]);
		} catch (err) {
			// Silently catch — message may be deleted, bot may lack permission, etc.
			logger.debug(
				{ error: String(err), chatId, messageId, emoji },
				"failed to set reaction (non-fatal)",
			);
		}
	}

	async function clearReaction(): Promise<void> {
		if (disposed) return;
		try {
			await api.setMessageReaction(chatId, messageId, []);
		} catch (err) {
			logger.debug(
				{ error: String(err), chatId, messageId },
				"failed to clear reaction (non-fatal)",
			);
		}
	}

	function resetStallTimers(): void {
		if (stallWarnTimer) {
			clearTimeout(stallWarnTimer);
			stallWarnTimer = null;
		}
		if (stallHardTimer) {
			clearTimeout(stallHardTimer);
			stallHardTimer = null;
		}
	}

	function startStallTimers(stage: ReactionStage): void {
		resetStallTimers();

		stallWarnTimer = setTimeout(() => {
			logger.warn(
				{ chatId, messageId, stage, stallMs: opts.stallWarnMs },
				"status reaction stalled (warn threshold)",
			);
		}, opts.stallWarnMs);

		stallHardTimer = setTimeout(() => {
			logger.error(
				{ chatId, messageId, stage, stallMs: opts.stallHardMs },
				"status reaction stalled (hard threshold)",
			);
		}, opts.stallHardMs);
	}

	function cancelDebounce(): void {
		if (debounceTimer) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
	}

	function cancelDoneClear(): void {
		if (doneClearTimer) {
			clearTimeout(doneClearTimer);
			doneClearTimer = null;
		}
	}

	function cleanup(): void {
		disposed = true;
		cancelDebounce();
		resetStallTimers();
		cancelDoneClear();
	}

	// ─── Stage transitions ──────────────────────────────────────────────

	/**
	 * Transition to a non-terminal stage with debouncing.
	 *
	 * If a new stage arrives before the debounce timer fires, the previous
	 * pending update is cancelled and the new stage is scheduled instead.
	 */
	function setNonTerminalStage(stage: ReactionStage): void {
		if (disposed) return;

		// Skip if already in this stage.
		if (currentStage === stage) return;

		// Don't regress from a terminal stage.
		if (currentStage && TERMINAL_STAGES.has(currentStage)) return;

		cancelDebounce();

		debounceTimer = setTimeout(() => {
			debounceTimer = null;
			currentStage = stage;
			startStallTimers(stage);
			enqueue(() => applyReaction(STAGE_EMOJI[stage]));
		}, opts.debounceMs);
	}

	/**
	 * Transition to a terminal stage immediately, flushing any pending debounce.
	 * Returns true if the terminal stage was applied, false if already terminal.
	 */
	function setTerminalStage(stage: ReactionStage): Promise<boolean> {
		if (disposed) return Promise.resolve(false);

		// Don't double-fire terminal stages — but cancel pending timers to avoid
		// cross-contamination (e.g. setDone auto-clear after setError).
		if (currentStage && TERMINAL_STAGES.has(currentStage)) {
			cancelDoneClear();
			cancelDebounce();
			return Promise.resolve(false);
		}

		// Flush pending debounce — terminal stages fire immediately.
		cancelDebounce();
		resetStallTimers();

		// Drain the promise queue — discard any pending non-terminal writes that
		// could run after the terminal reaction under auto-retry.
		queue = Promise.resolve();

		currentStage = stage;
		enqueue(() => applyReaction(STAGE_EMOJI[stage]));

		// Return a promise that resolves when the queue catches up.
		return new Promise<boolean>((resolve) => {
			enqueue(async () => {
				resolve(true);
			});
		});
	}

	// ─── Public API ─────────────────────────────────────────────────────

	return {
		setQueued(): void {
			setNonTerminalStage("queued");
		},

		setThinking(): void {
			setNonTerminalStage("thinking");
		},

		setTool(toolName?: string): void {
			const stage = toolNameToStage(toolName);
			setNonTerminalStage(stage);
		},

		setCoding(): void {
			setNonTerminalStage("coding");
		},

		setSearching(): void {
			setNonTerminalStage("searching");
		},

		setWeb(): void {
			setNonTerminalStage("web");
		},

		async setDone(): Promise<void> {
			const applied = await setTerminalStage("done");

			// Only schedule auto-clear if we actually transitioned to done.
			// If setTerminalStage bailed (already terminal), skip — otherwise
			// we'd clear a persistent error reaction.
			if (!applied) return;

			cancelDoneClear();
			doneClearTimer = setTimeout(() => {
				doneClearTimer = null;
				enqueue(() => clearReaction());
				// Schedule cleanup after the clear completes.
				enqueue(async () => {
					cleanup();
				});
			}, opts.doneClearDelayMs);
		},

		async setError(): Promise<void> {
			const applied = await setTerminalStage("error");
			if (!applied) return;
			// Error persists — no auto-clear. But do clean up timers.
			resetStallTimers();
			cancelDoneClear();
		},

		async clear(): Promise<void> {
			cancelDebounce();
			resetStallTimers();
			cancelDoneClear();
			enqueue(() => clearReaction());
			// Wait for the clear to complete.
			return new Promise<void>((resolve) => {
				enqueue(async () => {
					cleanup();
					resolve();
				});
			});
		},
	};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exports for testing
// ═══════════════════════════════════════════════════════════════════════════════

export const __test = {
	toolNameToStage,
	STAGE_EMOJI,
	TERMINAL_STAGES,
};
