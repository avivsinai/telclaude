import { describe, expect, it } from "vitest";
import { createWhatsAppAuthWriteTracker } from "../../src/whatsapp-bridge/auth-observe.js";

function deferred(): { promise: Promise<void>; resolve: () => void } {
	let resolve!: () => void;
	const promise = new Promise<void>((res) => {
		resolve = res;
	});
	return { promise, resolve };
}

describe("WhatsApp auth-write observation", () => {
	it("serializes writes and exposes only content-free progress", async () => {
		let now = 100;
		const tracker = createWhatsAppAuthWriteTracker(() => now);
		const first = deferred();
		const calls: string[] = [];

		const firstWrite = tracker.enqueue(async () => {
			calls.push("first-start");
			await first.promise;
			calls.push("first-end");
		});
		const secondWrite = tracker.enqueue(async () => {
			calls.push("second");
		});

		expect(tracker.snapshot()).toMatchObject({
			authWriteInFlight: true,
			authWritePendingCount: 2,
			authWriteSuccessCount: 0,
			authWriteFailureCount: 0,
		});
		const drained = tracker.drain();
		let drainSettled = false;
		void drained.then(() => {
			drainSettled = true;
		});
		await Promise.resolve();
		expect(calls).toEqual(["first-start"]);
		expect(drainSettled).toBe(false);

		first.resolve();
		now = 200;
		await Promise.all([firstWrite, secondWrite, drained]);

		expect(calls).toEqual(["first-start", "first-end", "second"]);
		expect(tracker.snapshot()).toEqual({
			authWriteInFlight: false,
			authWritePendingCount: 0,
			authWriteSuccessCount: 2,
			authWriteFailureCount: 0,
			lastAuthWriteAtMs: 200,
		});
	});

	it("records a failed write without blocking later writes", async () => {
		let now = 300;
		const tracker = createWhatsAppAuthWriteTracker(() => now);
		const failure = tracker.enqueue(async () => {
			throw new Error("credential contents must not be retained");
		});
		await expect(failure).rejects.toThrow("credential contents must not be retained");

		now = 400;
		await tracker.enqueue(async () => undefined);

		expect(tracker.snapshot()).toEqual({
			authWriteInFlight: false,
			authWritePendingCount: 0,
			authWriteSuccessCount: 1,
			authWriteFailureCount: 1,
			lastAuthWriteAtMs: 400,
			lastAuthWriteFailureAtMs: 300,
		});
	});
});
