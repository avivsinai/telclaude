/**
 * Card System Initialization
 *
 * Called once at relay startup to bootstrap the card subsystem:
 * 1. Ensures the card_instances table exists (handled by db.ts schema).
 * 2. Registers all card renderers into the global registry.
 * 3. Starts a periodic expiry sweep to garbage-collect stale cards.
 */

import type { Api } from "grammy";
import { getChildLogger } from "../../logging.js";
import { rerenderTerminalCard } from "./create-helpers.js";
import { sweepExpiredCards } from "./lifecycle.js";
import { registerAllCardRenderers } from "./renderers/index.js";

const logger = getChildLogger({ module: "telegram-card-init" });

/** Sweep interval: check for expired cards every 60 seconds. */
const SWEEP_INTERVAL_MS = 60_000;

let sweepTimer: NodeJS.Timeout | null = null;

/**
 * Initialize the card system.
 *
 * The card_instances table is created by the main schema in `src/storage/db.ts`,
 * so we don't need to create it here. This function:
 * 1. Registers all 9 card renderers.
 * 2. Starts the background expiry sweep (re-renders expired cards to remove stale buttons).
 */
export function initCardSystem(): void {
	registerAllCardRenderers();
	logger.info("card renderers registered");
}

/**
 * Start the expiry sweep with bot API access for re-rendering expired cards.
 * Call after the bot connects. Safe to call multiple times (restarts the timer).
 */
export function startCardSweep(api: Api): void {
	if (sweepTimer) {
		clearInterval(sweepTimer);
	}
	sweepTimer = setInterval(() => {
		try {
			const { count, cards } = sweepExpiredCards();
			if (count > 0) {
				logger.debug({ expired: count }, "card expiry sweep completed");
				for (const card of cards) {
					if (card.messageId > 0) {
						rerenderTerminalCard(api, card).catch((err) => {
							logger.debug(
								{ cardId: card.cardId, error: String(err) },
								"failed to re-render expired card",
							);
						});
					}
				}
			}
		} catch (err) {
			logger.error({ error: String(err) }, "card expiry sweep failed");
		}
	}, SWEEP_INTERVAL_MS);
	sweepTimer.unref();
	logger.debug("card expiry sweep started with API access");
}

/**
 * Stop the card expiry sweep. Call during graceful shutdown.
 */
export function stopCardSystem(): void {
	if (sweepTimer) {
		clearInterval(sweepTimer);
		sweepTimer = null;
		logger.debug("card expiry sweep stopped");
	}
}
