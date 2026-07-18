import type {
	AttachmentQuarantineStore,
	AttachmentQuarantineSweepResult,
} from "./attachment-quarantine-store.js";

export const DEFAULT_ATTACHMENT_QUARANTINE_SWEEP_INTERVAL_MS = 60 * 1000;

export interface AttachmentQuarantineSweeperHandle {
	readonly startup: AttachmentQuarantineSweepResult;
	stop(): void;
}

/** Run once at startup, then enforce the hard deadline on a bounded interval. */
export function startAttachmentQuarantineSweeper(options: {
	readonly store: AttachmentQuarantineStore;
	readonly intervalMs?: number;
	readonly onSweep?: (result: AttachmentQuarantineSweepResult) => void;
}): AttachmentQuarantineSweeperHandle {
	const intervalMs = options.intervalMs ?? DEFAULT_ATTACHMENT_QUARANTINE_SWEEP_INTERVAL_MS;
	if (!Number.isSafeInteger(intervalMs) || intervalMs < 1) {
		throw new Error("attachment quarantine sweep interval must be a positive integer");
	}
	const run = () => {
		const result = options.store.sweepExpired();
		options.onSweep?.(result);
		return result;
	};
	const startup = run();
	const timer = setInterval(run, intervalMs);
	timer.unref();
	return {
		startup,
		stop: () => clearInterval(timer),
	};
}
