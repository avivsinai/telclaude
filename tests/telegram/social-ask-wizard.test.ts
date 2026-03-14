import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let startSocialAskWizard: typeof import("../../src/telegram/control-command-actions.js").startSocialAskWizard;
let hasActiveSocialAskWizard: typeof import("../../src/telegram/control-command-actions.js").hasActiveSocialAskWizard;
let routeWizardTextMessage: typeof import("../../src/telegram/wizard/index.js").routeWizardTextMessage;

function makeApi() {
	return {
		sendMessage: vi.fn(async () => ({ message_id: 1 })),
		editMessageText: vi.fn(async () => {}),
		editMessageReplyMarkup: vi.fn(async () => {}),
		sendChatAction: vi.fn(async () => {}),
	};
}

async function waitFor(condition: () => boolean): Promise<void> {
	for (let attempt = 0; attempt < 20; attempt += 1) {
		if (condition()) {
			return;
		}
		await Promise.resolve();
	}
}

describe("social ask wizard", () => {
	beforeEach(async () => {
		vi.useFakeTimers();
		vi.resetModules();
		vi.doMock("../../src/security/linking.js", () => ({
			isAdmin: vi.fn(() => true),
		}));
		vi.doMock("../../src/social/handler.js", () => ({
			queryPublicPersona: vi.fn(async () => "public reply"),
		}));

		({ startSocialAskWizard, hasActiveSocialAskWizard } = await import(
			"../../src/telegram/control-command-actions.js"
		));
		({ routeWizardTextMessage } = await import("../../src/telegram/wizard/index.js"));
	});

	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it("allows only one active ask flow per actor and thread", async () => {
		const api = makeApi();
		const cfg = {
			socialServices: [{ id: "xtwitter", enabled: true }],
		} as any;

		const first = startSocialAskWizard(api as any, {
			actorId: 101,
			chatId: 777,
			threadId: 9,
			cfg,
		});
		expect(first.callbackText).toBe("Reply with a question for xtwitter");
		expect(hasActiveSocialAskWizard({ actorId: 101, chatId: 777, threadId: 9 })).toBe(true);
		await Promise.resolve();
		await Promise.resolve();

		const second = startSocialAskWizard(api as any, {
			actorId: 101,
			chatId: 777,
			threadId: 9,
			cfg,
		});
		expect(second.callbackAlert).toBe(true);
		expect(second.callbackText).toBe("Already waiting for your question.");

		expect(
			routeWizardTextMessage(777, "What did you post today?", {
				actorId: 101,
				threadId: 9,
			}),
		).toBe(true);

		await waitFor(() => !hasActiveSocialAskWizard({ actorId: 101, chatId: 777, threadId: 9 }));
		expect(hasActiveSocialAskWizard({ actorId: 101, chatId: 777, threadId: 9 })).toBe(false);

		const third = startSocialAskWizard(api as any, {
			actorId: 101,
			chatId: 777,
			threadId: 9,
			cfg,
		});
		expect(third.callbackAlert).toBeUndefined();
		expect(third.callbackText).toBe("Reply with a question for xtwitter");
		await Promise.resolve();
		await Promise.resolve();

		expect(
			routeWizardTextMessage(777, "One more question", {
				actorId: 101,
				threadId: 9,
			}),
		).toBe(true);
		await waitFor(() => !hasActiveSocialAskWizard({ actorId: 101, chatId: 777, threadId: 9 }));
	});
});
