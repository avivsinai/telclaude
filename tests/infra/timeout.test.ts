import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchWithTimeout, TimeoutError, withTimeout } from "../../src/infra/timeout.js";

describe("infra/timeout", () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it("withTimeout resolves when promise completes in time", async () => {
		await expect(withTimeout(Promise.resolve("ok"), 100, "quick-op")).resolves.toBe("ok");
	});

	it("withTimeout rejects with TimeoutError when deadline is exceeded", async () => {
		vi.useFakeTimers();

		const never = new Promise<string>(() => {
			// intentionally pending
		});
		const wrapped = withTimeout(never, 50, "stream-read");

		// Attach catch handler BEFORE advancing timers to prevent unhandled rejection
		const result = wrapped.catch((err: unknown) => err);

		await vi.advanceTimersByTimeAsync(50);

		const err = await result;
		expect(err).toMatchObject({
			name: "TimeoutError",
			message: "stream-read timed out after 50ms",
			timeoutMs: 50,
		});
	});

	it("withTimeout returns original promise when timeout is not positive", async () => {
		const base = Promise.resolve("value");
		const wrapped = withTimeout(base, 0, "ignored");
		expect(wrapped).toBe(base);
		await expect(wrapped).resolves.toBe("value");
	});

	it("fetchWithTimeout passes through when timeout is disabled", async () => {
		const response = new Response("ok", { status: 200 });
		const fetchMock = vi.fn(async () => response);
		vi.stubGlobal("fetch", fetchMock);

		const result = await fetchWithTimeout("https://example.test", { method: "POST" }, 0);
		expect(result).toBe(response);
		expect(fetchMock).toHaveBeenCalledWith("https://example.test", { method: "POST" });
	});

	it("fetchWithTimeout aborts underlying fetch on timeout", async () => {
		vi.useFakeTimers();

		let capturedSignal: AbortSignal | undefined;
		const fetchMock = vi.fn(
			(_url: string | URL, init?: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					capturedSignal = init?.signal ?? undefined;
					capturedSignal?.addEventListener("abort", () => reject(capturedSignal?.reason), {
						once: true,
					});
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		const promise = fetchWithTimeout("https://example.test", undefined, 25);

		// Attach catch handler BEFORE advancing timers to prevent unhandled rejection
		const result = promise.catch((err: unknown) => err);
		await vi.advanceTimersByTimeAsync(25);

		const err = await result;
		expect(err).toBeInstanceOf(TimeoutError);
		expect(capturedSignal?.aborted).toBe(true);
		expect((capturedSignal?.reason as Error).message).toContain("fetch timed out after 25ms");
	});

	it("fetchWithTimeout relays external abort signal", async () => {
		const external = new AbortController();

		const fetchMock = vi.fn(
			(_url: string | URL, init?: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					const signal = init?.signal;
					signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		const promise = fetchWithTimeout("https://example.test", { signal: external.signal }, 5000);
		external.abort(new Error("upstream-abort"));

		await expect(promise).rejects.toMatchObject({ message: "upstream-abort" });
	});
});
