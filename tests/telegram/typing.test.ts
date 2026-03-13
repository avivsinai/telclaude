import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createTypingControllerFromCallback } from "../../src/telegram/typing.js";

describe("TypingController", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("does not fire typing if stopped before debounce", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, { debounceMs: 200 });

		controller.start();
		// Stop before debounce fires
		controller.stop();

		vi.advanceTimersByTime(500);
		expect(sendFn).not.toHaveBeenCalled();
	});

	it("fires typing after debounce expires", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, { debounceMs: 200 });

		controller.start();
		vi.advanceTimersByTime(200);

		expect(sendFn).toHaveBeenCalledTimes(1);

		controller.stop();
	});

	it("repeats typing at configured interval", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, {
			debounceMs: 100,
			repeatIntervalMs: 4000,
		});

		controller.start();

		// Debounce fires
		vi.advanceTimersByTime(100);
		expect(sendFn).toHaveBeenCalledTimes(1);

		// First repeat
		vi.advanceTimersByTime(4000);
		expect(sendFn).toHaveBeenCalledTimes(2);

		// Second repeat
		vi.advanceTimersByTime(4000);
		expect(sendFn).toHaveBeenCalledTimes(3);

		controller.stop();

		// No more calls after stop
		vi.advanceTimersByTime(4000);
		expect(sendFn).toHaveBeenCalledTimes(3);
	});

	it("stop is idempotent", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, { debounceMs: 200 });

		controller.start();
		controller.stop();
		controller.stop(); // Second call should not throw

		vi.advanceTimersByTime(500);
		expect(sendFn).not.toHaveBeenCalled();
	});

	it("start is no-op after stop", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, { debounceMs: 200 });

		controller.stop();
		controller.start(); // Should not schedule anything

		vi.advanceTimersByTime(500);
		expect(sendFn).not.toHaveBeenCalled();
	});

	it("uses default debounce of 200ms", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn);

		controller.start();

		// Before default debounce
		vi.advanceTimersByTime(199);
		expect(sendFn).not.toHaveBeenCalled();

		// At default debounce
		vi.advanceTimersByTime(1);
		expect(sendFn).toHaveBeenCalledTimes(1);

		controller.stop();
	});

	it("uses default repeat interval of 4000ms", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, { debounceMs: 0 });

		controller.start();

		// Immediate fire (0ms debounce)
		vi.advanceTimersByTime(0);
		expect(sendFn).toHaveBeenCalledTimes(1);

		// Before default repeat interval
		vi.advanceTimersByTime(3999);
		expect(sendFn).toHaveBeenCalledTimes(1);

		// At default repeat interval
		vi.advanceTimersByTime(1);
		expect(sendFn).toHaveBeenCalledTimes(2);

		controller.stop();
	});

	it("cleans up repeat timer when stopped mid-repeat", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, {
			debounceMs: 100,
			repeatIntervalMs: 1000,
		});

		controller.start();

		// Let debounce fire and one repeat
		vi.advanceTimersByTime(100); // debounce
		vi.advanceTimersByTime(1000); // first repeat
		expect(sendFn).toHaveBeenCalledTimes(2);

		controller.stop();

		// Should not fire again
		vi.advanceTimersByTime(5000);
		expect(sendFn).toHaveBeenCalledTimes(2);
	});

	it("setAction calls the onSetAction callback", () => {
		const sendFn = vi.fn();
		const onSetAction = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, {}, onSetAction);

		controller.setAction("upload_document");
		expect(onSetAction).toHaveBeenCalledWith("upload_document");
	});

	it("setAction is safe without onSetAction callback", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn);

		// Should not throw
		controller.setAction("upload_voice");
	});

	it("restart resets debounce", () => {
		const sendFn = vi.fn();
		const controller = createTypingControllerFromCallback(sendFn, { debounceMs: 200 });

		controller.start();
		vi.advanceTimersByTime(150);
		expect(sendFn).not.toHaveBeenCalled();

		// Restart resets the debounce
		controller.start();
		vi.advanceTimersByTime(150);
		expect(sendFn).not.toHaveBeenCalled();

		// Now at 200ms from the restart
		vi.advanceTimersByTime(50);
		expect(sendFn).toHaveBeenCalledTimes(1);

		controller.stop();
	});
});
