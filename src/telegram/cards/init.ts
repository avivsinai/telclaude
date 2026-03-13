/**
 * Card System Initialization
 *
 * Called once at relay startup to bootstrap the card subsystem:
 * 1. Ensures the card_instances table exists (handled by db.ts schema).
 * 2. Registers all card renderers into the global registry.
 * 3. Starts a periodic expiry sweep to garbage-collect stale cards.
 */

import { getChildLogger } from "../../logging.js";
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
 * 1. Registers all 7 card renderers.
 * 2. Starts the background expiry sweep.
 */
export function initCardSystem(): void {
	// 1. Register all card renderers
	registerAllCardRenderers();
	logger.info("card renderers registered");

	// 2. Start the expiry sweep interval
	if (sweepTimer) {
		clearInterval(sweepTimer);
	}
	sweepTimer = setInterval(() => {
		try {
			const expired = sweepExpiredCards();
			if (expired > 0) {
				logger.debug({ expired }, "card expiry sweep completed");
			}
		} catch (err) {
			logger.error({ error: String(err) }, "card expiry sweep failed");
		}
	}, SWEEP_INTERVAL_MS);

	// Ensure the timer does not prevent process exit
	sweepTimer.unref();

	logger.info("card system initialized");
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
