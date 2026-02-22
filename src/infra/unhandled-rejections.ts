/**
 * Process-level unhandled rejection handler.
 *
 * Classifies unhandled rejections and decides whether to exit or continue:
 * - Fatal / config errors → exit(1)
 * - Transient network errors → warn + continue
 * - AbortError → suppress (expected during shutdown)
 */

import { getChildLogger } from "../logging.js";
import { formatErrorSafe, isAbortError, isTransientNetworkError } from "./network-errors.js";

const logger = getChildLogger({ module: "unhandled-rejections" });

export type RejectionCategory = "fatal" | "config" | "transient" | "abort" | "unknown";

export function categorize(err: unknown): RejectionCategory {
	if (isAbortError(err)) return "abort";
	if (isTransientNetworkError(err)) return "transient";

	const message = formatErrorSafe(err, 1000);
	const lower = message.toLowerCase();

	// Config errors — missing env vars, invalid settings
	if (
		lower.includes("is not configured") ||
		lower.includes("missing required") ||
		lower.includes("invalid configuration") ||
		lower.includes("enoent") ||
		lower.includes("cannot find module")
	) {
		return "config";
	}

	// Known fatal patterns — out of memory, assertion failures
	if (
		lower.includes("out of memory") ||
		lower.includes("heap out of memory") ||
		lower.includes("assertion") ||
		lower.includes("invariant") ||
		lower.includes("maximum call stack")
	) {
		return "fatal";
	}

	return "unknown";
}

/**
 * Install the unhandled rejection handler.
 * Call once at process startup (relay or agent entry point).
 *
 * @param processLabel - "relay" or "agent" for log context
 */
export function installUnhandledRejectionHandler(processLabel: string): void {
	process.on("unhandledRejection", (reason: unknown) => {
		const category = categorize(reason);
		const formatted = formatErrorSafe(reason);

		switch (category) {
			case "abort":
				// Expected during shutdown — suppress
				logger.debug({ process: processLabel }, `suppressed abort rejection: ${formatted}`);
				break;

			case "transient":
				// Network hiccup — warn but don't crash
				logger.warn(
					{ process: processLabel, category },
					`transient unhandled rejection (continuing): ${formatted}`,
				);
				break;

			case "config":
				// Config error — fatal, exit
				logger.fatal({ process: processLabel, category }, `config error (exiting): ${formatted}`);
				process.exit(1);
				break;

			case "fatal":
				// Fatal error — exit immediately
				logger.fatal(
					{ process: processLabel, category },
					`fatal unhandled rejection (exiting): ${formatted}`,
				);
				process.exit(1);
				break;

			default:
				// Unknown — log at error level but don't crash.
				// In production, crashing on every unknown rejection is worse than
				// logging and continuing, since many are non-fatal race conditions.
				logger.error({ process: processLabel, category }, `unhandled rejection: ${formatted}`);
				break;
		}
	});

	logger.debug({ process: processLabel }, "unhandled rejection handler installed");
}
