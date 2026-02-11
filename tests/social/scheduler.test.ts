import { afterEach, describe, expect, it, vi } from "vitest";

import { startSocialScheduler } from "../../src/social/scheduler.js";

describe("social scheduler", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("runs immediately and on interval", async () => {
		vi.useFakeTimers();
		const onHeartbeat = vi.fn().mockResolvedValue(undefined);

		startSocialScheduler({ intervalMs: 60000, onHeartbeat });

		await vi.runAllTicks();
		expect(onHeartbeat).toHaveBeenCalledTimes(1);

		await vi.advanceTimersByTimeAsync(60000);
		expect(onHeartbeat).toHaveBeenCalledTimes(2);
	});

	it("prevents overlap while a heartbeat is running", async () => {
		vi.useFakeTimers();
		let resolveHeartbeat: (() => void) | null = null;
		const onHeartbeat = vi.fn(
			() =>
				new Promise<void>((resolve) => {
					resolveHeartbeat = resolve;
				}),
		);

		startSocialScheduler({ intervalMs: 60000, onHeartbeat });
		await vi.runAllTicks();
		expect(onHeartbeat).toHaveBeenCalledTimes(1);

		await vi.advanceTimersByTimeAsync(60000);
		expect(onHeartbeat).toHaveBeenCalledTimes(1);

		resolveHeartbeat?.();
		await vi.runAllTicks();

		await vi.advanceTimersByTimeAsync(60000);
		expect(onHeartbeat).toHaveBeenCalledTimes(2);
	});

	it("stop cancels future heartbeats", async () => {
		vi.useFakeTimers();
		const onHeartbeat = vi.fn().mockResolvedValue(undefined);

		const scheduler = startSocialScheduler({ intervalMs: 60000, onHeartbeat });
		await vi.runAllTicks();
		expect(onHeartbeat).toHaveBeenCalledTimes(1);

		scheduler.stop();
		await vi.advanceTimersByTimeAsync(120000);
		expect(onHeartbeat).toHaveBeenCalledTimes(1);
	});
});
