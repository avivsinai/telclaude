import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let startProviderAddWizard: typeof import("../../src/telegram/control-command-actions.js").startProviderAddWizard;
let hasActiveProviderWizard: typeof import("../../src/telegram/control-command-actions.js").hasActiveProviderWizard;
let routeWizardTextMessage: typeof import("../../src/telegram/wizard/index.js").routeWizardTextMessage;
let addConfiguredProviderMock: ReturnType<typeof vi.fn>;
let sendProviderListCardMock: ReturnType<typeof vi.fn>;

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

async function deliverWizardText(
	chatId: number,
	text: string,
	scope: { actorId: number; threadId?: number },
): Promise<void> {
	for (let attempt = 0; attempt < 20; attempt += 1) {
		if (routeWizardTextMessage(chatId, text, scope)) {
			return;
		}
		await Promise.resolve();
	}
	throw new Error(`Wizard was not ready to accept "${text}"`);
}

describe("provider add wizard", () => {
	beforeEach(async () => {
		vi.useFakeTimers();
		vi.resetModules();

		addConfiguredProviderMock = vi.fn(async (providerId: string, input: any) => ({
			provider: {
				id: providerId,
				baseUrl: input.baseUrl,
				services: input.services,
				description: input.description,
			},
			providers: [
				{
					id: providerId,
					baseUrl: input.baseUrl,
					services: input.services,
					description: input.description,
				},
			],
			refresh: { providerCount: 1, cleared: false },
			doctorResults: [
				{
					providerId,
					baseUrl: input.baseUrl,
					checks: [{ name: "health", status: "pass", detail: "ok" }],
				},
			],
		}));
		sendProviderListCardMock = vi.fn(async () => ({}));

		vi.doMock("../../src/security/linking.js", () => ({
			isAdmin: vi.fn(() => true),
		}));
		vi.doMock("../../src/config/config.js", () => ({
			loadConfig: vi.fn(() => ({
				providers: [
					{
						id: "google",
						baseUrl: "http://google-services:3001",
						services: ["gmail", "calendar"],
						description: "Google Services sidecar",
					},
				],
				security: {},
			})),
		}));
		vi.doMock("../../src/commands/providers.js", () => ({
			addConfiguredProvider: addConfiguredProviderMock,
			editConfiguredProvider: vi.fn(),
			removeConfiguredProviderById: vi.fn(),
			validateProviderId: (value: string) => {
				const trimmed = value.trim();
				if (!/^[a-z0-9][a-z0-9-]*$/.test(trimmed)) {
					throw new Error("Provider id must use lowercase letters, digits, and hyphens only.");
				}
				return trimmed;
			},
		}));
		vi.doMock("../../src/providers/catalog.js", () => ({
			getCatalogOAuthService: vi.fn(() => undefined),
			getProviderCatalogEntry: vi.fn(() => undefined),
			listCatalogOAuthServices: vi.fn(() => []),
			listProviderCatalogEntries: vi.fn(() => []),
		}));
		vi.doMock("../../src/providers/provider-health.js", () => ({
			checkProviderHealth: vi.fn(async () => ({ reachable: true, response: {} })),
		}));
		vi.doMock("../../src/telegram/cards/create-helpers.js", () => ({
			sendBackgroundJobCard: vi.fn(),
			sendBackgroundJobListCard: vi.fn(),
			sendModelPickerCard: vi.fn(),
			sendPendingQueueCard: vi.fn(),
			sendProviderListCard: sendProviderListCardMock,
			sendSkillDraftCard: vi.fn(),
			sendSkillPickerCard: vi.fn(),
			sendSystemHealthCard: vi.fn(),
		}));

		({ startProviderAddWizard, hasActiveProviderWizard } = await import(
			"../../src/telegram/control-command-actions.js"
		));
		({ routeWizardTextMessage } = await import("../../src/telegram/wizard/index.js"));
	});

	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it("collects provider fields and reopens the provider list after a successful add", async () => {
		const api = makeApi();

		const first = startProviderAddWizard(api as any, {
			actorId: 101,
			chatId: 777,
			threadId: 9,
		});
		expect(first.callbackText).toBe("Answer the prompts to add a provider.");
		expect(hasActiveProviderWizard({ actorId: 101, chatId: 777, threadId: 9 })).toBe(true);
		await Promise.resolve();
		await Promise.resolve();

		const second = startProviderAddWizard(api as any, {
			actorId: 101,
			chatId: 777,
			threadId: 9,
		});
		expect(second.callbackAlert).toBe(true);
		expect(second.callbackText).toBe("Already running a provider wizard in this chat.");

		await deliverWizardText(777, "israel-services", {
			actorId: 101,
			threadId: 9,
		});
		await waitFor(() => api.editMessageText.mock.calls.length >= 1);
		await deliverWizardText(777, "https://israel-services.internal", {
			actorId: 101,
			threadId: 9,
		});
		await waitFor(() => api.editMessageText.mock.calls.length >= 2);
		await deliverWizardText(777, "gov-api, health-api", {
			actorId: 101,
			threadId: 9,
		});
		await waitFor(() => api.editMessageText.mock.calls.length >= 3);
		await deliverWizardText(777, "-", {
			actorId: 101,
			threadId: 9,
		});

		await waitFor(() => !hasActiveProviderWizard({ actorId: 101, chatId: 777, threadId: 9 }));

		expect(addConfiguredProviderMock).toHaveBeenCalledWith("israel-services", {
			baseUrl: "https://israel-services.internal",
			services: ["gov-api", "health-api"],
			description: undefined,
		});
		expect(sendProviderListCardMock).toHaveBeenCalledOnce();
		expect(sendProviderListCardMock.mock.calls[0]?.[2]?.state?.providers).toEqual([
			expect.objectContaining({
				id: "israel-services",
				baseUrl: "https://israel-services.internal",
			}),
		]);
		expect(api.sendMessage).toHaveBeenCalledWith(
			777,
			expect.stringContaining("Configured provider 'israel-services'"),
			expect.objectContaining({ message_thread_id: 9 }),
		);
	});
});
