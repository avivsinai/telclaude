import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let getActiveCardsByEntity: typeof import("../../src/telegram/cards/store.js").getActiveCardsByEntity;
let getCard: typeof import("../../src/telegram/cards/store.js").getCard;
let handleCallback: typeof import("../../src/telegram/cards/callback-controller.js").handleCallback;
let registerAllCardRenderers: typeof import("../../src/telegram/cards/renderers/index.js").registerAllCardRenderers;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let sendPendingQueueCard: typeof import("../../src/telegram/cards/create-helpers.js").sendPendingQueueCard;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

function makeEntries(count: number) {
	return Array.from({ length: count }, (_, index) => ({
		id: `entry-${index + 1}`,
		label: `Entry ${index + 1}`,
	}));
}

function findCallbackData(replyMarkup: any, labelIncludes: string): string {
	const button = replyMarkup?.inline_keyboard
		?.flat()
		.find(
			(button: any) =>
				typeof button?.text === "string" &&
				button.text.includes(labelIncludes) &&
				typeof button.callback_data === "string",
		);

	if (!button?.callback_data) {
		throw new Error(`Missing callback button containing ${labelIncludes}`);
	}

	return button.callback_data;
}

describe("card create helpers", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-card-helpers-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ getActiveCardsByEntity, getCard } = await import("../../src/telegram/cards/store.js"));
		({ handleCallback } = await import("../../src/telegram/cards/callback-controller.js"));
		({ registerAllCardRenderers } = await import("../../src/telegram/cards/renderers/index.js"));
		({ sendPendingQueueCard } = await import("../../src/telegram/cards/create-helpers.js"));

		registerAllCardRenderers();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("keeps first-send buttons valid after recording the Telegram message id", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 501 }));
		const card = await sendPendingQueueCard({ sendMessage } as any, 777, {
			entries: makeEntries(5),
			actorScope: "user:101",
		});

		const callbackData = findCallbackData(sendMessage.mock.calls[0]?.[2]?.reply_markup, "Next");
		const answerCallbackQuery = vi.fn(async () => {});
		const editMessageText = vi.fn(async () => {});

		await handleCallback({
			callbackQuery: {
				data: callbackData,
				message: { message_id: card.messageId },
			},
			chat: { id: card.chatId },
			from: { id: 101, username: "user101" },
			api: { editMessageText },
			answerCallbackQuery,
		} as any);

		expect(answerCallbackQuery).toHaveBeenCalledWith({ text: "Page 2", show_alert: false });
		expect(editMessageText).toHaveBeenCalledOnce();
		expect(getCard(card.cardId)).toEqual(
			expect.objectContaining({
				messageId: 501,
				revision: 2,
				state: expect.objectContaining({ page: 1 }),
			}),
		);
	});

	it("updates an existing active card in place instead of orphaning the old message", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 601 }));
		const editMessageText = vi.fn(async () => ({}));
		const api = { sendMessage, editMessageText } as any;

		const first = await sendPendingQueueCard(api, 777, {
			entries: makeEntries(5),
			actorScope: "user:101",
		});
		const updatedEntries = makeEntries(2);
		const second = await sendPendingQueueCard(api, 777, {
			entries: updatedEntries,
			actorScope: "user:101",
		});

		expect(sendMessage).toHaveBeenCalledTimes(1);
		expect(editMessageText).toHaveBeenCalledTimes(1);
		expect(second).toEqual(
			expect.objectContaining({
				cardId: first.cardId,
				messageId: first.messageId,
				revision: first.revision + 1,
			}),
		);
		expect(getActiveCardsByEntity({
			kind: second.kind,
			chatId: second.chatId,
			entityRef: second.entityRef,
		})).toHaveLength(1);
		expect(getCard(second.cardId)).toEqual(
			expect.objectContaining({
				status: "active",
				state: expect.objectContaining({
					entries: updatedEntries,
					total: updatedEntries.length,
				}),
			}),
		);
	});
});
