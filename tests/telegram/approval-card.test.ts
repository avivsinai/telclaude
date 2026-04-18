/**
 * W1 — ApprovalScopeCard renderer tests.
 *
 * Validates:
 * - Four-button keyboard (once / session / always / deny) for non-high risk.
 * - "Approve always" persists an allowlist grant.
 * - High-risk cards hide the "always" button and prevent the scope at execute().
 * - Deny consumes the approval without writing to the allowlist.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let registerAllCardRenderers: typeof import("../../src/telegram/cards/renderers/index.js").registerAllCardRenderers;
let sendApprovalScopeCard: typeof import("../../src/telegram/cards/create-helpers.js").sendApprovalScopeCard;
let handleCallback: typeof import("../../src/telegram/cards/callback-controller.js").handleCallback;
let getCard: typeof import("../../src/telegram/cards/store.js").getCard;
let createApproval: typeof import("../../src/security/approvals.js").createApproval;
let listAllowlist: typeof import("../../src/security/approvals.js").listAllowlist;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

type InlineKeyboardButton = { text: string; callback_data?: string };

function flattenButtons(replyMarkup: unknown): InlineKeyboardButton[] {
	if (!replyMarkup || typeof replyMarkup !== "object") return [];
	const keyboard = (replyMarkup as { inline_keyboard?: InlineKeyboardButton[][] })
		.inline_keyboard;
	if (!keyboard) return [];
	return keyboard.flat();
}

function findButton(replyMarkup: unknown, labelFragment: string): InlineKeyboardButton | null {
	for (const btn of flattenButtons(replyMarkup)) {
		if (typeof btn.text === "string" && btn.text.toLowerCase().includes(labelFragment.toLowerCase())) {
			return btn;
		}
	}
	return null;
}

function seedApproval(options: {
	chatId: number;
	tier: "READ_ONLY" | "WRITE_LOCAL" | "SOCIAL" | "FULL_ACCESS";
	toolKey: string;
	riskTier: "low" | "medium" | "high";
	sessionKey?: string;
}): string {
	const result = createApproval({
		requestId: `req-${Math.random()}`,
		chatId: options.chatId,
		tier: options.tier,
		body: "please run this",
		from: "tg:user",
		to: "bot",
		messageId: "msg-1",
		observerClassification: "ALLOW",
		observerConfidence: 0.9,
		riskTier: options.riskTier,
		toolKey: options.toolKey,
		sessionKey: options.sessionKey ?? null,
	});
	return result.nonce;
}

describe("ApprovalScopeCard (W1)", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-approval-card-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ registerAllCardRenderers } = await import("../../src/telegram/cards/renderers/index.js"));
		({ sendApprovalScopeCard } = await import("../../src/telegram/cards/create-helpers.js"));
		({ handleCallback } = await import("../../src/telegram/cards/callback-controller.js"));
		({ getCard } = await import("../../src/telegram/cards/store.js"));
		({ createApproval, listAllowlist } = await import("../../src/security/approvals.js"));

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

	it("renders four buttons (once / session / always / deny) for medium risk", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 1 }));
		const chatId = 111;
		const nonce = seedApproval({
			chatId,
			tier: "WRITE_LOCAL",
			toolKey: "Write",
			riskTier: "medium",
			sessionKey: `tg:${chatId}`,
		});
		await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Write",
			body: "Write file",
			nonce,
			toolKey: "Write",
			riskTier: "medium",
			actorScope: `user:1001`,
		});

		const replyMarkup = sendMessage.mock.calls[0]?.[2]?.reply_markup;
		expect(findButton(replyMarkup, "Once")).not.toBeNull();
		expect(findButton(replyMarkup, "Session")).not.toBeNull();
		expect(findButton(replyMarkup, "Always")).not.toBeNull();
		expect(findButton(replyMarkup, "Deny")).not.toBeNull();
	});

	it("hides 'Always' for high-risk actions", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 2 }));
		const chatId = 112;
		const nonce = seedApproval({
			chatId,
			tier: "WRITE_LOCAL",
			toolKey: "Bash",
			riskTier: "high",
		});
		await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Bash rm -rf",
			body: "rm -rf build/",
			nonce,
			toolKey: "Bash",
			riskTier: "high",
			actorScope: `user:1002`,
		});

		const replyMarkup = sendMessage.mock.calls[0]?.[2]?.reply_markup;
		expect(findButton(replyMarkup, "Once")).not.toBeNull();
		expect(findButton(replyMarkup, "Session")).toBeNull();
		expect(findButton(replyMarkup, "Always")).toBeNull();
		expect(findButton(replyMarkup, "Deny")).not.toBeNull();
	});

	it("'Approve always' records an allowlist grant and consumes the approval", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 3 }));
		const editMessageText = vi.fn(async () => {});
		const answerCallbackQuery = vi.fn(async () => {});
		const chatId = 113;
		const actorId = 1003;
		const nonce = seedApproval({
			chatId,
			tier: "WRITE_LOCAL",
			toolKey: "Read",
			riskTier: "medium",
		});
		const card = await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Read",
			body: "Read file",
			nonce,
			toolKey: "Read",
			riskTier: "medium",
			actorScope: `user:${actorId}`,
		});

		const callback = findButton(sendMessage.mock.calls[0]?.[2]?.reply_markup, "Always");
		expect(callback?.callback_data).toBeDefined();

		await handleCallback({
			callbackQuery: {
				data: callback?.callback_data,
				message: { message_id: card.messageId },
			},
			chat: { id: card.chatId },
			from: { id: actorId, username: "tester" },
			api: { editMessageText },
			answerCallbackQuery,
		} as any);

		expect(answerCallbackQuery).toHaveBeenCalled();
		const stored = getCard(card.cardId);
		expect(stored?.status).toBe("consumed");

		const grants = listAllowlist({ userId: String(actorId) });
		expect(grants).toHaveLength(1);
		expect(grants[0]?.scope).toBe("always");
		expect(grants[0]?.toolKey).toBe("Read");
	});

	it("deny consumes approval without writing an allowlist row", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 4 }));
		const editMessageText = vi.fn(async () => {});
		const answerCallbackQuery = vi.fn(async () => {});
		const chatId = 114;
		const actorId = 1004;
		const nonce = seedApproval({
			chatId,
			tier: "WRITE_LOCAL",
			toolKey: "Write",
			riskTier: "medium",
		});
		const card = await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Write",
			body: "Write file",
			nonce,
			toolKey: "Write",
			riskTier: "medium",
			actorScope: `user:${actorId}`,
		});

		const denyBtn = findButton(sendMessage.mock.calls[0]?.[2]?.reply_markup, "Deny");
		await handleCallback({
			callbackQuery: {
				data: denyBtn?.callback_data,
				message: { message_id: card.messageId },
			},
			chat: { id: card.chatId },
			from: { id: actorId, username: "tester" },
			api: { editMessageText },
			answerCallbackQuery,
		} as any);

		const stored = getCard(card.cardId);
		expect(stored?.status).toBe("consumed");
		const grants = listAllowlist({ userId: String(actorId) });
		expect(grants).toHaveLength(0);
	});
});
