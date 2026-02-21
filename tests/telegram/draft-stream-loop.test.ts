import { afterEach, describe, expect, it, vi } from "vitest";
import { createDraftStreamLoop } from "../../src/telegram/draft-stream-loop.js";

describe("createDraftStreamLoop", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("debounces updates and sends only the latest pending text", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date(0));
		const sent: string[] = [];
		const loop = createDraftStreamLoop({
			throttleMs: 100,
			isStopped: () => false,
			sendOrEditStreamMessage: async (text) => {
				sent.push(text);
			},
		});

		loop.update("a");
		loop.update("ab");
		await vi.advanceTimersByTimeAsync(100);

		expect(sent).toEqual(["ab"]);
	});

	it("flush waits for in-flight send completion", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date(0));
		let resolveSend: (() => void) | null = null;
		const sent: string[] = [];
		const loop = createDraftStreamLoop({
			throttleMs: 200,
			isStopped: () => false,
			sendOrEditStreamMessage: async (text) => {
				sent.push(text);
				await new Promise<void>((resolve) => {
					resolveSend = resolve;
				});
			},
		});

		loop.update("first");
		const flushPromise = loop.flush();
		expect(sent).toEqual(["first"]);
		resolveSend?.();
		await flushPromise;

		expect(sent).toEqual(["first"]);
	});

	it("keeps pending text when sender reports false", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date(0));
		let blocked = true;
		const sent: string[] = [];
		const loop = createDraftStreamLoop({
			throttleMs: 50,
			isStopped: () => false,
			sendOrEditStreamMessage: async (text) => {
				sent.push(text);
				if (blocked) {
					return false;
				}
				return true;
			},
		});

		loop.update("pending");
		await loop.flush();
		expect(sent).toEqual(["pending"]);

		blocked = false;
		loop.update("pending");
		await loop.flush();
		expect(sent).toEqual(["pending", "pending"]);
	});
});
