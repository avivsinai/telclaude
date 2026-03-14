import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let buildCallbackToken: typeof import("../../src/telegram/cards/callback-tokens.js").buildCallbackToken;
let createQuarantinedEntry: typeof import("../../src/memory/store.js").createQuarantinedEntry;
let createEntries: typeof import("../../src/memory/store.js").createEntries;
let createCard: typeof import("../../src/telegram/cards/store.js").createCard;
let getCard: typeof import("../../src/telegram/cards/store.js").getCard;
let getEntries: typeof import("../../src/memory/store.js").getEntries;
let handleCallback: typeof import("../../src/telegram/cards/callback-controller.js").handleCallback;
let CardKind: typeof import("../../src/telegram/cards/types.js").CardKind;
let loadPendingQueueEntries: typeof import("../../src/telegram/cards/renderers/pending-queue.js").loadPendingQueueEntries;
let pendingQueueRenderer: typeof import("../../src/telegram/cards/renderers/pending-queue.js").pendingQueueRenderer;
let registerAllCardRenderers: typeof import("../../src/telegram/cards/renderers/index.js").registerAllCardRenderers;
let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

function makePendingQueueCard(options: {
	chatId?: number;
	actorScope?: string;
	page?: number;
	entries: Array<{ id: string; label: string; summary?: string }>;
}) {
	return createCard({
		kind: CardKind.PendingQueue,
		chatId: options.chatId ?? 777,
		messageId: 55,
		actorScope: options.actorScope ?? "user:101",
		entityRef: "pending-queue",
		state: {
			kind: CardKind.PendingQueue,
			title: "Pending Queue",
			entries: options.entries,
			total: options.entries.length,
			page: options.page ?? 0,
		},
		expiresAt: Date.now() + 60_000,
	});
}

function makeCallbackContext(options: {
	card: ReturnType<typeof makePendingQueueCard>;
	actorId: number;
	action: "promote" | "dismiss";
}) {
	const answerCallbackQuery = vi.fn(async () => {});
	const editMessageText = vi.fn(async () => {});
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
			api: { editMessageText },
			answerCallbackQuery,
		} as any,
		answerCallbackQuery,
		editMessageText,
	};
}

function makePagedEntries() {
	return [
		{ id: "page-5", label: "Entry 5" },
		{ id: "page-4", label: "Entry 4" },
		{ id: "page-3", label: "Entry 3" },
		{ id: "page-2", label: "Entry 2" },
		{ id: "page-1", label: "Entry 1" },
	];
}

describe("pending queue cards", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-pending-queue-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ createEntries, createQuarantinedEntry, getEntries } = await import(
			"../../src/memory/store.js"
		));
		({ createCard, getCard } = await import("../../src/telegram/cards/store.js"));
		({ buildCallbackToken } = await import("../../src/telegram/cards/callback-tokens.js"));
		({ handleCallback } = await import("../../src/telegram/cards/callback-controller.js"));
		({ CardKind } = await import("../../src/telegram/cards/types.js"));
		({ registerAllCardRenderers } = await import("../../src/telegram/cards/renderers/index.js"));
		({ loadPendingQueueEntries, pendingQueueRenderer } = await import(
			"../../src/telegram/cards/renderers/pending-queue.js"
		));

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

	it("allows callbacks from the scoped user in a group chat", async () => {
		createQuarantinedEntry({
			id: "allowed-post",
			category: "posts",
			content: "Allowed post",
			chatId: "777",
		});
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			entries: [{ id: "allowed-post", label: "Allowed post" }],
		});
		const { ctx, answerCallbackQuery, editMessageText } = makeCallbackContext({
			card,
			actorId: 101,
			action: "promote",
		});

		await handleCallback(ctx);

		expect(answerCallbackQuery).toHaveBeenCalledWith({ text: "Promoted", show_alert: false });
		expect(editMessageText).toHaveBeenCalledOnce();
		const promoted = getEntries({ chatId: "777", order: "asc" })[0];
		expect(promoted._provenance.trust).toBe("trusted");
		expect(promoted._provenance.promotedBy).toBe("telegram:777:101");
		expect(getCard(card.cardId)?.state).toEqual(
			expect.objectContaining({ entries: [], total: 0, page: 0 }),
		);
	});

	it("rejects callbacks from a different group member", async () => {
		createQuarantinedEntry({
			id: "blocked-post",
			category: "posts",
			content: "Blocked post",
			chatId: "777",
		});
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			entries: [{ id: "blocked-post", label: "Blocked post" }],
		});
		const { ctx, answerCallbackQuery, editMessageText } = makeCallbackContext({
			card,
			actorId: 202,
			action: "promote",
		});

		await handleCallback(ctx);

		expect(answerCallbackQuery).toHaveBeenCalledWith({
			text: "Not authorized for this card",
			show_alert: true,
		});
		expect(editMessageText).not.toHaveBeenCalled();
		expect(getEntries({ chatId: "777", order: "asc" })[0]._provenance.trust).toBe("quarantined");
		expect(getCard(card.cardId)?.state).toEqual(card.state);
	});

	it("loads pending queue entries with the same filtering and shape as the command path", () => {
		const now = Date.now();
		for (let index = 1; index <= 5; index += 1) {
			createQuarantinedEntry(
				{
					id: `telegram-${index}`,
					category: "posts",
					content: `telegram idea ${index}`,
					chatId: "chat-1",
				},
				now - (5 - index) * 60_000,
			);
		}
		createQuarantinedEntry(
			{
				id: "telegram-other-chat",
				category: "posts",
				content: "should be filtered out",
				chatId: "chat-2",
			},
			now + 60_000,
		);

		for (let index = 1; index <= 18; index += 1) {
			const id = `social-${String(index).padStart(2, "0")}`;
			createEntries(
				[
					{
						id,
						category: "posts",
						content: `social idea ${index}`,
						chatId: "chat-2",
						metadata:
							index === 18
								? {
										action: "quote",
										targetPostId: "tweet-1",
										targetAuthor: "@writer",
										targetExcerpt: "Quoted source text worth keeping around for tests",
									}
								: undefined,
					},
				],
				"social",
				now + index,
			);
		}

		const entries = loadPendingQueueEntries("chat-1");
		const expectedIds = [
			...Array.from({ length: 18 }, (_, offset) => `social-${String(18 - offset).padStart(2, "0")}`),
			"telegram-5",
			"telegram-4",
		];

		expect(entries).toHaveLength(20);
		expect(entries.map((entry) => entry.id)).toEqual(expectedIds);
		expect(entries.some((entry) => entry.id === "telegram-other-chat")).toBe(false);
		expect(entries[0]).toEqual(
			expect.objectContaining({
				id: "social-18",
				label: expect.stringContaining('"social idea 18"'),
				summary: expect.stringContaining("quote @writer"),
			}),
		);
		expect(entries[0]?.summary).toContain("Quoted source text worth keeping around");
		expect(entries.at(-1)).toEqual(
			expect.objectContaining({
				id: "telegram-4",
				label: expect.stringContaining('"telegram idea 4"'),
			}),
		);
	});

	it("clamps to the previous page after promote removes the last item on the final page", async () => {
		for (let index = 1; index <= 5; index += 1) {
			createQuarantinedEntry({
				id: `page-${index}`,
				category: "posts",
				content: `post ${index}`,
				chatId: "777",
			});
		}
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			page: 1,
			entries: makePagedEntries(),
		});

		const result = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "promote" },
		});
		const nextState = result.state;
		expect(nextState).toEqual(
			expect.objectContaining({
				page: 0,
				total: 4,
			}),
		);

		const rendered = pendingQueueRenderer.render({ ...card, state: nextState! });
		expect(rendered.text).toContain("Entry 5");
		expect(rendered.text).toContain("Entry 2");
		expect(rendered.text).not.toContain("Entry 1");
		expect(rendered.text).not.toContain("_No pending entries_");
	});

	it("clamps to the previous page after dismiss removes the last item on the final page", async () => {
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			page: 1,
			entries: makePagedEntries(),
		});

		const result = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "dismiss" },
		});
		const nextState = result.state;
		expect(nextState).toEqual(
			expect.objectContaining({
				page: 0,
				total: 4,
			}),
		);

		const rendered = pendingQueueRenderer.render({ ...card, state: nextState! });
		expect(rendered.text).toContain("Entry 5");
		expect(rendered.text).toContain("Entry 2");
		expect(rendered.text).not.toContain("Entry 1");
		expect(rendered.text).not.toContain("_No pending entries_");
	});
});
