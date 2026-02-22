import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/utils.js", () => ({
	sleep: vi.fn().mockResolvedValue(undefined),
}));

import { sleep } from "../../src/utils.js";
import {
	computeRetryDelay,
	resolveRetryConfig,
	retryAsync,
	type RetryInfo,
} from "../../src/infra/retry.js";

describe("infra/retry", () => {
	const mockSleep = vi.mocked(sleep);

	beforeEach(() => {
		mockSleep.mockClear();
		vi.restoreAllMocks();
	});

	it("clamps retry config to safe bounds", () => {
		const resolved = resolveRetryConfig({
			maxAttempts: 0,
			baseDelayMs: -10,
			maxDelayMs: -1,
			factor: 0,
			jitter: 2,
		});

		expect(resolved).toEqual({
			maxAttempts: 1,
			baseDelayMs: 0,
			maxDelayMs: 0,
			factor: 1,
			jitter: 1,
		});
	});

	it("computes delay with cap and deterministic jitter", () => {
		const config = resolveRetryConfig({
			baseDelayMs: 100,
			factor: 2,
			maxDelayMs: 500,
			jitter: 0,
		});

		vi.spyOn(Math, "random").mockReturnValue(0.5);
		expect(computeRetryDelay(config, 1)).toBe(100);
		expect(computeRetryDelay(config, 2)).toBe(200);
		expect(computeRetryDelay(config, 4)).toBe(500);
	});

	it("retries and succeeds with exponential delays", async () => {
		let attempts = 0;
		const onRetry = vi.fn();
		const op = vi.fn(async () => {
			attempts++;
			if (attempts < 3) {
				throw new Error("transient");
			}
			return "ok";
		});

		const result = await retryAsync(op, {
			maxAttempts: 4,
			baseDelayMs: 10,
			factor: 2,
			jitter: 0,
			onRetry,
		});

		expect(result).toBe("ok");
		expect(op).toHaveBeenCalledTimes(3);
		expect(mockSleep).toHaveBeenNthCalledWith(1, 10);
		expect(mockSleep).toHaveBeenNthCalledWith(2, 20);
		expect(onRetry).toHaveBeenCalledTimes(2);
	});

	it("stops immediately when shouldRetry returns false", async () => {
		const err = new Error("not retryable");
		const shouldRetry = vi.fn((_error: unknown, _info: RetryInfo) => false);

		await expect(
			retryAsync(
				async () => {
					throw err;
				},
				{
					maxAttempts: 5,
					baseDelayMs: 10,
					shouldRetry,
				},
			),
		).rejects.toBe(err);

		expect(shouldRetry).toHaveBeenCalledTimes(1);
		expect(mockSleep).not.toHaveBeenCalled();
	});

	it("uses retryAfter delay and caps to maxDelayMs", async () => {
		const retryAfterMs = vi.fn(() => 500);
		const onRetry = vi.fn();
		let callCount = 0;

		const result = await retryAsync(
			async () => {
				callCount++;
				if (callCount === 1) {
					throw new Error("rate limited");
				}
				return "done";
			},
			{
				maxAttempts: 2,
				baseDelayMs: 10,
				maxDelayMs: 120,
				jitter: 0,
				retryAfterMs,
				onRetry,
			},
		);

		expect(result).toBe("done");
		expect(retryAfterMs).toHaveBeenCalledTimes(1);
		expect(mockSleep).toHaveBeenCalledWith(120);
		expect(onRetry).toHaveBeenCalledWith(
			expect.any(Error),
			expect.objectContaining({ delayMs: 120 }),
		);
	});

	it("throws the last error after exhausting attempts", async () => {
		const err = new Error("still failing");
		const op = vi.fn(async () => {
			throw err;
		});

		await expect(
			retryAsync(op, {
				maxAttempts: 3,
				baseDelayMs: 1,
				jitter: 0,
				label: "agent-fetch",
			}),
		).rejects.toBe(err);

		expect(op).toHaveBeenCalledTimes(3);
		expect(mockSleep).toHaveBeenCalledTimes(2);
	});
});
