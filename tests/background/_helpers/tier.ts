/**
 * Mirror of the `ensureCanSpawn` check in `src/commands/background.ts`.
 *
 * The shipping path wraps this behind commander's `.action()` callback, so we
 * re-expose the pure function here for the runner test. If the gate ever
 * diverges, tests + CLI should be kept in sync deliberately.
 */

import type { PermissionTier } from "../../../src/config/config.js";

export function ensureCanSpawn(tier: PermissionTier): void {
	if (tier === "READ_ONLY") {
		throw new Error(
			"READ_ONLY tier cannot spawn background jobs. Ask an operator to raise your tier first.",
		);
	}
}
