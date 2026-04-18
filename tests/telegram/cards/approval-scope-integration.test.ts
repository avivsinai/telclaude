import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let resetDatabase: typeof import("../../../src/storage/db.js").resetDatabase;
let registerAllCardRenderers: typeof import("../../../src/telegram/cards/renderers/index.js").registerAllCardRenderers;
let sendApprovalScopeCard: typeof import("../../../src/telegram/cards/create-helpers.js").sendApprovalScopeCard;
let handleCallback: typeof import("../../../src/telegram/cards/callback-controller.js").handleCallback;
let createApproval: typeof import("../../../src/security/approvals.js").createApproval;
let listAllowlist: typeof import("../../../src/security/approvals.js").listAllowlist;
let waitForToolApproval: typeof import("../../../src/security/approval-wait.js").waitForToolApproval;
let generateLinkCode: typeof import("../../../src/security/linking.js").generateLinkCode;
let consumeLinkCode: typeof import("../../../src/security/linking.js").consumeLinkCode;

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

describe("ApprovalScopeCard integration", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-approval-scope-int-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;

		vi.resetModules();
		({ resetDatabase } = await import("../../../src/storage/db.js"));
		resetDatabase();
		({ registerAllCardRenderers } = await import(
			"../../../src/telegram/cards/renderers/index.js"
		));
		({ sendApprovalScopeCard } = await import("../../../src/telegram/cards/create-helpers.js"));
		({ handleCallback } = await import("../../../src/telegram/cards/callback-controller.js"));
		({ createApproval, listAllowlist } = await import("../../../src/security/approvals.js"));
		({ waitForToolApproval } = await import("../../../src/security/approval-wait.js"));
		({ generateLinkCode, consumeLinkCode } = await import("../../../src/security/linking.js"));

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

	it("writes grants under the linked local identity and resolves the waiting tool approval", async () => {
		const chatId = 141;
		const actorId = 141;
		const localUserId = "aviv";
		const linkCode = generateLinkCode(localUserId);
		expect(consumeLinkCode(linkCode, chatId, "cli:test").success).toBe(true);

		const { nonce } = createApproval({
			requestId: "tool-link-test",
			chatId,
			tier: "WRITE_LOCAL",
			body: "Claude wants to edit README.md",
			from: `tg:${chatId}`,
			to: "tool-approval",
			messageId: "tool-link-test",
			observerClassification: "ALLOW",
			observerConfidence: 1,
			riskTier: "medium",
			toolKey: "Edit",
			sessionKey: `tg:${chatId}`,
		});
		const waiting = waitForToolApproval({ nonce, chatId, timeoutMs: 1_000 });

		const sendMessage = vi.fn(async () => ({ message_id: 7 }));
		const editMessageText = vi.fn(async () => {});
		const answerCallbackQuery = vi.fn(async () => {});

		const card = await sendApprovalScopeCard({ sendMessage } as any, chatId, {
			title: "Approve Edit",
			body: "Edit README.md",
			nonce,
			toolKey: "Edit",
			riskTier: "medium",
			actorScope: `user:${actorId}`,
		});
		const alwaysButton = findButton(sendMessage.mock.calls[0]?.[2]?.reply_markup, "Always");

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

		await expect(waiting).resolves.toMatchObject({
			status: "approved",
			scope: "always",
			source: "card",
		});
		expect(listAllowlist({ userId: localUserId })).toHaveLength(1);
		expect(listAllowlist({ userId: String(actorId) })).toHaveLength(0);
	});
});
