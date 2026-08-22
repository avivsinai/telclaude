export type WhatsAppAuthWriteSnapshot = {
	readonly authWriteInFlight: boolean;
	readonly authWritePendingCount: number;
	readonly authWriteSuccessCount: number;
	readonly authWriteFailureCount: number;
	readonly lastAuthWriteAtMs?: number;
	readonly lastAuthWriteFailureAtMs?: number;
};

export type WhatsAppAuthWriteTracker = {
	readonly enqueue: (write: () => Promise<void>) => Promise<void>;
	readonly drain: () => Promise<void>;
	readonly snapshot: () => WhatsAppAuthWriteSnapshot;
};

/**
 * Serializes Baileys auth writes so shutdown can wait for a stable on-disk
 * snapshot without exposing credential content in status or logs.
 */
export function createWhatsAppAuthWriteTracker(
	now: () => number = Date.now,
): WhatsAppAuthWriteTracker {
	let tail = Promise.resolve();
	let pendingCount = 0;
	let successCount = 0;
	let failureCount = 0;
	let lastWriteAtMs: number | undefined;
	let lastWriteFailureAtMs: number | undefined;

	const enqueue = (write: () => Promise<void>): Promise<void> => {
		pendingCount += 1;
		const operation = tail.then(async () => {
			try {
				await write();
				successCount += 1;
				lastWriteAtMs = now();
			} catch (error) {
				failureCount += 1;
				lastWriteFailureAtMs = now();
				throw error;
			} finally {
				pendingCount -= 1;
			}
		});
		tail = operation.then(
			() => undefined,
			() => undefined,
		);
		return operation;
	};

	return {
		enqueue,
		drain: () => tail,
		snapshot: () => ({
			authWriteInFlight: pendingCount > 0,
			authWritePendingCount: pendingCount,
			authWriteSuccessCount: successCount,
			authWriteFailureCount: failureCount,
			...(lastWriteAtMs === undefined ? {} : { lastAuthWriteAtMs: lastWriteAtMs }),
			...(lastWriteFailureAtMs === undefined
				? {}
				: { lastAuthWriteFailureAtMs: lastWriteFailureAtMs }),
		}),
	};
}
