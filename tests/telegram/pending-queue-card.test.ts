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
	entries: Array<Record<string, unknown> & { id: string; label: string; summary?: string }>;
	view?: "list" | "detail";
	selectedEntryId?: string;
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
			view: options.view ?? "list",
			selectedEntryId: options.selectedEntryId,
		},
		expiresAt: Date.now() + 60_000,
	});
}

function makeCallbackContext(options: {
	card: ReturnType<typeof makePendingQueueCard>;
	actorId: number;
	action:
		| "view"
		| "back"
		| "edit"
		| "refine"
		| "promote"
		| "dismiss"
		| "mark-posted"
		| "retry-api";
}) {
	const answerCallbackQuery = vi.fn(async () => {});
	const editMessageText = vi.fn(async () => {});
	const sendMessage = vi.fn(async () => ({ message_id: 99 }));
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
			api: { editMessageText, sendMessage },
			answerCallbackQuery,
		} as any,
		answerCallbackQuery,
		editMessageText,
		sendMessage,
	};
}

function makePagedEntries() {
	for (let index = 1; index <= 5; index += 1) {
		createQuarantinedEntry(
			{
				id: `page-${index}`,
				category: "posts",
				content: `post ${index}`,
				chatId: "777",
			},
			index,
		);
	}
	return loadPendingQueueEntries("777");
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
			entries: loadPendingQueueEntries("777"),
		});
		const { ctx, answerCallbackQuery, editMessageText } = makeCallbackContext({
			card,
			actorId: 101,
			action: "promote",
		});

		await handleCallback(ctx);

		expect(answerCallbackQuery).toHaveBeenCalledWith({ text: "Approved", show_alert: false });
		expect(editMessageText).toHaveBeenCalledOnce();
		const promoted = getEntries({ chatId: "777", order: "asc" })[0];
		expect(promoted._provenance.trust).toBe("trusted");
		expect(promoted._provenance.promotedBy).toBe("telegram:777:101");
		expect(promoted.metadata).toEqual(expect.objectContaining({ draftState: "queued" }));
		expect(getCard(card.cardId)?.state).toEqual(
			expect.objectContaining({
				entries: [expect.objectContaining({ id: "allowed-post", status: "queued" })],
				total: 1,
				page: 0,
			}),
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
		expect(entries[0]?.summary).toContain("Quoted source text worth");
		expect(entries.at(-1)).toEqual(
			expect.objectContaining({
				id: "telegram-4",
				label: expect.stringContaining('"telegram idea 4"'),
			}),
		);
	});

	it("opens a detail view with metadata and copy-ready text", async () => {
		createEntries(
			[
				{
					id: "detail-quote",
					category: "posts",
					content: "Copy ready quote text",
					metadata: {
						action: "quote",
						draftState: "manual_action_needed",
						draftWorkflow: "workbench",
						serviceId: "xtwitter",
						targetPostId: "tweet-9",
						targetAuthor: "@writer",
						targetExcerpt: "Original source text",
						targetUrl: "https://x.example/post/tweet-9",
						manualActionReason: "quote API unavailable",
					},
				},
			],
			"social",
			Date.now(),
		);
		const entries = loadPendingQueueEntries("777");
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			entries,
		});

		const result = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "view" },
		});
		const nextState = result.state;
		expect(nextState).toEqual(
			expect.objectContaining({
				view: "detail",
				selectedEntryId: "detail-quote",
			}),
		);

		const rendered = pendingQueueRenderer.render({ ...card, state: nextState! });
		expect(rendered.text).toContain("Manual action");
		expect(rendered.text).toContain("xtwitter");
		expect(rendered.text).toContain("Copy-ready text");
		expect(rendered.text).toContain("Copy ready quote text");
		expect(JSON.stringify(rendered.keyboard?.inline_keyboard)).toContain("Open target");
	});

	it("queues manual-action drafts for API retry", async () => {
		createEntries(
			[
				{
					id: "manual-retry",
					category: "posts",
					content: "Retry this draft",
					metadata: {
						draftState: "manual_action_needed",
						draftWorkflow: "workbench",
						serviceId: "xtwitter",
						manualActionReason: "API unavailable",
					},
				},
			],
			"social",
			Date.now(),
		);
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			entries: loadPendingQueueEntries("777"),
			view: "detail",
			selectedEntryId: "manual-retry",
		});

		const result = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "retry-api" },
		});

		expect(result.callbackText).toBe("Queued for API retry");
		expect(result.state).toEqual(
			expect.objectContaining({
				entries: [expect.objectContaining({ id: "manual-retry", status: "queued" })],
				selectedEntryId: "manual-retry",
			}),
		);
		const stored = getEntries({ sources: ["social"], order: "asc" })[0];
		expect(stored._provenance.trust).toBe("trusted");
		expect(stored.metadata).toEqual(expect.objectContaining({ draftState: "queued" }));
	});

	it("starts edit and refine flows through deferred card actions", async () => {
		createEntries(
			[
				{
					id: "editable-draft",
					category: "posts",
					content: "Needs polish",
					metadata: {
						draftState: "needs_review",
						draftWorkflow: "workbench",
						serviceId: "moltbook",
					},
				},
			],
			"social",
			Date.now(),
		);
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			entries: loadPendingQueueEntries("777"),
			view: "detail",
			selectedEntryId: "editable-draft",
		});

		const editResult = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "edit" },
		});
		const refineResult = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "refine" },
		});

		expect(editResult.callbackText).toBe("Reply with edited text");
		expect(editResult.afterCommit).toBeTypeOf("function");
		expect(refineResult.callbackText).toBe("Reply with refinement instruction");
		expect(refineResult.afterCommit).toBeTypeOf("function");
	});

	it("clamps to the previous page after mark-posted removes the last item on the final page", async () => {
		const card = makePendingQueueCard({
			chatId: 777,
			actorScope: "user:101",
			page: 1,
			entries: makePagedEntries(),
		});

		const result = await pendingQueueRenderer.execute({
			ctx: { from: { id: 101 } } as any,
			card,
			action: { type: "mark-posted" },
		});
		const nextState = result.state;
		expect(nextState).toEqual(
			expect.objectContaining({
				page: 0,
				total: 4,
			}),
		);

		const posted = getEntries({ posted: true, order: "asc" })[0];
		expect(posted.id).toBe("page-1");
		expect(posted.metadata).toEqual(expect.objectContaining({ draftState: "marked_posted" }));

		const rendered = pendingQueueRenderer.render({ ...card, state: nextState! });
		expect(rendered.text).toContain("post 5");
		expect(rendered.text).toContain("post 2");
		expect(rendered.text).not.toContain("post 1");
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
		expect(rendered.text).toContain("post 5");
		expect(rendered.text).toContain("post 2");
		expect(rendered.text).not.toContain("post 1");
		expect(rendered.text).not.toContain("_No pending entries_");
	});
});
