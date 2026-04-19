import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let buildCallbackToken: typeof import("../../../src/telegram/cards/callback-tokens.js").buildCallbackToken;
let CardRegistry: typeof import("../../../src/telegram/cards/registry.js").CardRegistry;
let createCard: typeof import("../../../src/telegram/cards/store.js").createCard;
let createApproval: typeof import("../../../src/security/approvals.js").createApproval;
let denyApproval: typeof import("../../../src/security/approvals.js").denyApproval;
let getCard: typeof import("../../../src/telegram/cards/store.js").getCard;
let getPendingApprovalsForChat: typeof import("../../../src/security/approvals.js").getPendingApprovalsForChat;
let handleCallback: typeof import("../../../src/telegram/cards/callback-controller.js").handleCallback;
let registerAllCardRenderers: typeof import("../../../src/telegram/cards/renderers/index.js").registerAllCardRenderers;
let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;
let sendApprovalScopeCard: typeof import("../../../src/telegram/cards/create-helpers.js").sendApprovalScopeCard;
let CardKind: typeof import("../../../src/telegram/cards/types.js").CardKind;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

type InlineKeyboardButton = { text: string; callback_data?: string };

function findButton(replyMarkup: unknown, labelFragment: string): InlineKeyboardButton | null {
	if (!replyMarkup || typeof replyMarkup !== "object") return null;
	const keyboard = (replyMarkup as { inline_keyboard?: InlineKeyboardButton[][] }).inline_keyboard;
	for (const row of keyboard ?? []) {
		for (const button of row) {
			if (button.text.toLowerCase().includes(labelFragment.toLowerCase())) {
				return button;
			}
		}
	}
	return null;
}

function makeCallbackContext(options: {
	card: {
		shortId: string;
		revision: number;
		messageId: number;
		chatId: number;
	};
	actorId: number;
	action: string;
	api?: Record<string, unknown>;
}) {
	const answerCallbackQuery = vi.fn(async () => {});
	const editMessageText = vi.fn(async () => ({}));
	return {
		ctx: {
			callbackQuery: {
				data: buildCallbackToken({
					shortId: options.card.shortId,
					action: options.action,
					revision: options.card.revision,
				}),
				message: { message_id: options.card.messageId },
			},
			chat: { id: options.card.chatId },
			from: { id: options.actorId, username: `user${options.actorId}` },
			api: {
				editMessageText,
				...(options.api ?? {}),
			},
			answerCallbackQuery,
		} as any,
		answerCallbackQuery,
		editMessageText,
	};
}

describe("card hardening", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-card-hardening-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.useRealTimers();
		vi.resetModules();
		({ resetDatabase } = await import("../../../src/storage/db.js"));
		resetDatabase();
		({ buildCallbackToken } = await import("../../../src/telegram/cards/callback-tokens.js"));
		({ CardRegistry } = await import("../../../src/telegram/cards/registry.js"));
		({ createCard, getCard } = await import("../../../src/telegram/cards/store.js"));
		({ createApproval, denyApproval, getPendingApprovalsForChat } = await import(
			"../../../src/security/approvals.js"
		));
		({ handleCallback } = await import("../../../src/telegram/cards/callback-controller.js"));
		({ registerAllCardRenderers } = await import("../../../src/telegram/cards/renderers/index.js"));
		({ sendApprovalScopeCard } = await import("../../../src/telegram/cards/create-helpers.js"));
		({ CardKind } = await import("../../../src/telegram/cards/types.js"));
		registerAllCardRenderers();
	});

	afterEach(() => {
		vi.useRealTimers();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("keeps current buttons valid when refresh produces no visible card change", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-04-19T06:00:00.000Z"));

		const now = Date.now();
		const card = createCard({
			kind: CardKind.ProviderList,
			chatId: 777,
			messageId: 55,
			actorScope: "user:101",
			entityRef: "provider-list",
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				view: "list",
				page: 0,
				canMutate: false,
				providers: [
					{
						id: "anthropic",
						label: "Anthropic",
						health: "ok",
					},
				],
				lastRefreshedAtMs: now,
			},
			expiresAt: now + 60_000,
		});

		const refresh = makeCallbackContext({
			card,
			actorId: 101,
			action: "refresh",
			api: {
				editMessageText: vi.fn(async () => {
					throw new Error("400 Bad Request: message is not modified");
				}),
			},
		});

		await handleCallback(refresh.ctx);

		expect(refresh.answerCallbackQuery).toHaveBeenCalledWith({
			text: "Refreshed",
			show_alert: false,
		});
		expect(getCard(card.cardId)?.revision).toBe(1);
		expect(getCard(card.cardId)?.state).toEqual(
			expect.objectContaining({
				view: "list",
			}),
		);

		const afterRefresh = getCard(card.cardId);
		expect(afterRefresh).not.toBeNull();
		const select = makeCallbackContext({
			card: afterRefresh as NonNullable<typeof afterRefresh>,
			actorId: 101,
			action: "select-0",
		});

		await handleCallback(select.ctx);

		expect(select.answerCallbackQuery).toHaveBeenCalledWith({
			text: "Anthropic",
			show_alert: false,
		});
		expect(getCard(card.cardId)).toEqual(
			expect.objectContaining({
				revision: 2,
				state: expect.objectContaining({
					view: "detail",
					selectedProviderId: "anthropic",
				}),
			}),
		);
	});

	it("answers slow callbacks before the handler completes", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-04-19T06:00:00.000Z"));

		const card = createCard({
			kind: CardKind.Status,
			chatId: 777,
			messageId: 77,
			actorScope: "user:101",
			entityRef: "status",
			state: {
				kind: CardKind.Status,
				title: "Status",
				summary: "healthy",
			},
			expiresAt: Date.now() + 60_000,
		});
		const registry = new CardRegistry();
		registry.register(CardKind.Status, {
			render: () => ({
				text: "Status",
				parseMode: "MarkdownV2",
				keyboard: null,
			}),
			reduce: (current) => current.state,
			execute: async () => {
				await new Promise((resolve) => setTimeout(resolve, 2_000));
				return { callbackText: "Done", rerender: false };
			},
		});

		const { ctx, answerCallbackQuery } = makeCallbackContext({
			card,
			actorId: 101,
			action: "refresh",
		});

		const pending = handleCallback(ctx, { registry });
		expect(answerCallbackQuery).not.toHaveBeenCalled();

		await vi.advanceTimersByTimeAsync(1_600);
		expect(answerCallbackQuery).toHaveBeenCalledTimes(1);

		await vi.advanceTimersByTimeAsync(500);
		await pending;
		expect(answerCallbackQuery).toHaveBeenCalledTimes(1);
	});

	it("rejects a tap that expires before execution can commit", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-04-19T06:00:00.000Z"));

		const card = createCard({
			kind: CardKind.Status,
			chatId: 777,
			messageId: 78,
			actorScope: "user:101",
			entityRef: "status",
			state: {
				kind: CardKind.Status,
				title: "Status",
				summary: "healthy",
			},
			expiresAt: Date.now() + 100,
		});
		const registry = new CardRegistry();
		registry.register(CardKind.Status, {
			render: (current) => ({
				text: current.state.summary,
				parseMode: "MarkdownV2",
				keyboard: null,
			}),
			reduce: (current) => current.state,
			execute: async () => {
				await new Promise((resolve) => setTimeout(resolve, 200));
				return {
					state: {
						kind: CardKind.Status,
						title: "Status",
						summary: "updated",
					},
					callbackText: "Updated",
					rerender: false,
				};
			},
		});

		const { ctx, answerCallbackQuery } = makeCallbackContext({
			card,
			actorId: 101,
			action: "refresh",
		});

		const pending = handleCallback(ctx, { registry });
		await vi.advanceTimersByTimeAsync(250);
		await pending;

		expect(answerCallbackQuery).toHaveBeenCalledWith({
			text: "Card expired",
			show_alert: true,
		});
		expect(getCard(card.cardId)).toEqual(
			expect.objectContaining({
				status: "expired",
			}),
		);
	});

	it("treats double taps as idempotent", async () => {
		const card = createCard({
			kind: CardKind.ProviderList,
			chatId: 777,
			messageId: 56,
			actorScope: "user:101",
			entityRef: "provider-list",
			state: {
				kind: CardKind.ProviderList,
				title: "Providers",
				view: "list",
				page: 0,
				canMutate: false,
				providers: Array.from({ length: 10 }, (_, index) => ({
					id: `provider-${index}`,
					label: `Provider ${index}`,
					health: "ok" as const,
				})),
			},
			expiresAt: Date.now() + 60_000,
		});

		const first = makeCallbackContext({ card, actorId: 101, action: "page-next" });
		const second = makeCallbackContext({ card, actorId: 101, action: "page-next" });

		await Promise.all([handleCallback(first.ctx), handleCallback(second.ctx)]);

		expect(getCard(card.cardId)).toEqual(
			expect.objectContaining({
				revision: 2,
				state: expect.objectContaining({ page: 1 }),
			}),
		);
		expect(
			[first.answerCallbackQuery, second.answerCallbackQuery].some((mock) =>
				mock.mock.calls.some(
					(args) => args[0]?.text === "Card outdated" && args[0]?.show_alert === true,
				),
			),
		).toBe(true);
	});

	it("fails closed when an approval card outlives the in-memory waiter after restart", async () => {
		const chatId = 141;
		const actorId = 141;
		const { nonce } = createApproval({
			requestId: "restart-test",
			chatId,
			tier: "WRITE_LOCAL",
			body: "Claude wants to edit README.md",
			from: `tg:${chatId}`,
			to: "tool-approval",
			messageId: "restart-test",
			observerClassification: "ALLOW",
			observerConfidence: 1,
			riskTier: "medium",
			toolKey: "Edit",
			sessionKey: `tg:${chatId}`,
		});

		const sendMessage = vi.fn(async () => ({ message_id: 79 }));
		const card = await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Edit",
			body: "Edit README.md",
			nonce,
			toolKey: "Edit",
			riskTier: "medium",
			actorScope: `user:${actorId}`,
		});
		const alwaysButton = findButton(sendMessage.mock.calls[0]?.[2]?.reply_markup, "Always");
		expect(alwaysButton?.callback_data).toBeDefined();

		vi.resetModules();
		({ getCard } = await import("../../../src/telegram/cards/store.js"));
		({ getPendingApprovalsForChat } = await import("../../../src/security/approvals.js"));
		({ handleCallback } = await import("../../../src/telegram/cards/callback-controller.js"));
		({ registerAllCardRenderers } = await import("../../../src/telegram/cards/renderers/index.js"));
		registerAllCardRenderers();

		const answerCallbackQuery = vi.fn(async () => {});
		const editMessageText = vi.fn(async () => {});
		await handleCallback({
			callbackQuery: {
				data: alwaysButton?.callback_data,
				message: { message_id: card.messageId },
			},
			chat: { id: chatId },
			from: { id: actorId, username: "tester" },
			api: { editMessageText },
			answerCallbackQuery,
		} as any);

		expect(answerCallbackQuery).toHaveBeenCalledWith(
			expect.objectContaining({
				show_alert: true,
			}),
		);
		expect(getCard(card.cardId)).toEqual(
			expect.objectContaining({
				status: "consumed",
				state: expect.objectContaining({
					denied: true,
				}),
			}),
		);
		expect(getCard(card.cardId)?.state).not.toHaveProperty("scopeChosen");
		expect(getPendingApprovalsForChat(chatId)).toHaveLength(0);
	});

	it("fails closed on deny after restart when the approval row is already gone", async () => {
		const chatId = 142;
		const actorId = 142;
		const { nonce } = createApproval({
			requestId: "restart-deny-test",
			chatId,
			tier: "WRITE_LOCAL",
			body: "Claude wants to edit README.md",
			from: `tg:${chatId}`,
			to: "tool-approval",
			messageId: "restart-deny-test",
			observerClassification: "ALLOW",
			observerConfidence: 1,
			riskTier: "medium",
			toolKey: "Edit",
			sessionKey: `tg:${chatId}`,
		});

		const sendMessage = vi.fn(async () => ({ message_id: 80 }));
		const card = await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Edit",
			body: "Edit README.md",
			nonce,
			toolKey: "Edit",
			riskTier: "medium",
			actorScope: `user:${actorId}`,
		});
		expect(denyApproval(nonce, chatId).success).toBe(true);

		vi.resetModules();
		({ getCard } = await import("../../../src/telegram/cards/store.js"));
		({ getPendingApprovalsForChat } = await import("../../../src/security/approvals.js"));
		({ handleCallback } = await import("../../../src/telegram/cards/callback-controller.js"));
		({ registerAllCardRenderers } = await import("../../../src/telegram/cards/renderers/index.js"));
		registerAllCardRenderers();

		const denyButton = findButton(sendMessage.mock.calls[0]?.[2]?.reply_markup, "Deny");
		const answerCallbackQuery = vi.fn(async () => {});
		const editMessageText = vi.fn(async () => {});
		await handleCallback({
			callbackQuery: {
				data: denyButton?.callback_data,
				message: { message_id: card.messageId },
			},
			chat: { id: chatId },
			from: { id: actorId, username: "tester" },
			api: { editMessageText },
			answerCallbackQuery,
		} as any);

		expect(answerCallbackQuery).toHaveBeenCalledWith(
			expect.objectContaining({
				show_alert: true,
				text: "Approval session reset. Retry the original action.",
			}),
		);
		expect(getCard(card.cardId)).toEqual(
			expect.objectContaining({
				status: "consumed",
				state: expect.objectContaining({
					denied: true,
				}),
			}),
		);
		expect(getPendingApprovalsForChat(chatId)).toHaveLength(0);
	});

	it("reports touch-path revision conflicts as outdated instead of success", async () => {
		const card = createCard({
			kind: CardKind.Status,
			chatId: 777,
			messageId: 81,
			actorScope: "user:101",
			entityRef: "status",
			state: {
				kind: CardKind.Status,
				title: "Status",
				summary: "healthy",
			},
			expiresAt: Date.now() + 60_000,
		});

		vi.resetModules();
		vi.doMock("../../../src/telegram/cards/store.js", async () => {
			const actual = await vi.importActual<typeof import("../../../src/telegram/cards/store.js")>(
				"../../../src/telegram/cards/store.js",
			);
			return {
				...actual,
				touchCard: vi.fn(() => null),
			};
		});
		({ handleCallback } = await import("../../../src/telegram/cards/callback-controller.js"));

		const registry = new CardRegistry();
		registry.register(CardKind.Status, {
			render: () => ({
				text: "Status",
				parseMode: "MarkdownV2",
				keyboard: null,
			}),
			reduce: (current) => current.state,
			execute: async () => ({
				callbackText: "Done",
				rerender: false,
			}),
		});

		const { ctx, answerCallbackQuery } = makeCallbackContext({
			card,
			actorId: 101,
			action: "refresh",
		});
		await handleCallback(ctx, { registry });

		expect(answerCallbackQuery).toHaveBeenCalledWith({
			text: "Card outdated",
			show_alert: true,
		});
	});
});
