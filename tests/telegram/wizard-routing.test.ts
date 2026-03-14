import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let createWizardPrompter: typeof import("../../src/telegram/wizard/index.js").createWizardPrompter;
let routeWizardCallback: typeof import("../../src/telegram/wizard/index.js").routeWizardCallback;
let routeWizardTextMessage: typeof import("../../src/telegram/wizard/index.js").routeWizardTextMessage;

function makeApi() {
	return {
		sendMessage: vi.fn(async () => ({ message_id: 1 })),
		editMessageText: vi.fn(async () => {}),
	};
}

describe("wizard routing", () => {
	beforeEach(async () => {
		vi.resetModules();
		({ createWizardPrompter, routeWizardCallback, routeWizardTextMessage } = await import(
			"../../src/telegram/wizard/index.js"
		));
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("scopes wizard callbacks and text replies to the initiating actor and thread", async () => {
		const api = makeApi();
		const wizard = createWizardPrompter({
			api: api as any,
			actorId: 101,
			chatId: 777,
			threadId: 9,
		});

		const selectPromise = wizard.select({
			message: "Choose a social persona:",
			options: [{ value: "xtwitter", label: "xtwitter" }],
		});

		await Promise.resolve();
		await Promise.resolve();
		const callbackData =
			api.sendMessage.mock.calls[0]?.[2]?.reply_markup?.inline_keyboard?.[0]?.[0]?.callback_data;
		expect(typeof callbackData).toBe("string");

		expect(
			routeWizardCallback(callbackData, {
				actorId: 202,
				chatId: 777,
				threadId: 9,
			}),
		).toBe("forbidden");
		expect(
			routeWizardCallback(callbackData, {
				actorId: 101,
				chatId: 777,
				threadId: 8,
			}),
		).toBe("forbidden");
		expect(
			routeWizardCallback(callbackData, {
				actorId: 101,
				chatId: 777,
				threadId: 9,
			}),
		).toBe("handled");
		await expect(selectPromise).resolves.toBe("xtwitter");

		const textPromise = wizard.text({
			message: "Send the question:",
		});

		await Promise.resolve();
		await Promise.resolve();
		expect(
			routeWizardTextMessage(777, "wrong actor", {
				actorId: 202,
				threadId: 9,
			}),
		).toBe(false);
		expect(
			routeWizardTextMessage(777, "wrong thread", {
				actorId: 101,
				threadId: 8,
			}),
		).toBe(false);
		expect(
			routeWizardTextMessage(777, "hello from the right actor", {
				actorId: 101,
				threadId: 9,
			}),
		).toBe(true);
		await expect(textPromise).resolves.toBe("hello from the right actor");

		await wizard.dismiss();
	});
});
