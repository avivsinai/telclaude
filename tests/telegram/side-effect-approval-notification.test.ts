import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Api } from "grammy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let resetDatabase: typeof import("../../src/storage/db.js").resetDatabase;
let registerAllCardRenderers: typeof import("../../src/telegram/cards/renderers/index.js").registerAllCardRenderers;
let sendHouseholdProviderApprovalNotificationCard: typeof import("../../src/telegram/side-effect-approval-notification.js").sendHouseholdProviderApprovalNotificationCard;

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("household provider approval notification", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tc-household-approval-card-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		vi.resetModules();
		({ resetDatabase } = await import("../../src/storage/db.js"));
		resetDatabase();
		({ registerAllCardRenderers } = await import("../../src/telegram/cards/renderers/index.js"));
		({ sendHouseholdProviderApprovalNotificationCard } = await import(
			"../../src/telegram/side-effect-approval-notification.js"
		));
		registerAllCardRenderers();
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) delete process.env.TELCLAUDE_DATA_DIR;
		else process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
	});

	it("sends a notification-only card with redacted strings and /approve authority", async () => {
		const sendMessage = vi.fn(async () => ({ message_id: 17 }));
		const syntheticIsraeliId = "123456782";
		const syntheticOtp = "654321";

		await sendHouseholdProviderApprovalNotificationCard({ sendMessage } as unknown as Api, {
			chatId: 111,
			nonce: "abcd1234abcd1234",
			service: `clalit ת.ז ${syntheticIsraeliId}`,
			action: `prescription_renewal code ${syntheticOtp}`,
		});

		const [chatId, text, options] = sendMessage.mock.calls[0] ?? [];
		expect(chatId).toBe(111);
		expect(text).toContain("/approve abcd1234abcd1234");
		expect(text).toContain("REDACTED:israeli\\_id");
		expect(text).toContain("REDACTED:otp\\_code");
		expect(text).not.toContain(syntheticIsraeliId);
		expect(text).not.toContain(syntheticOtp);
		expect(options?.reply_markup?.inline_keyboard ?? []).toEqual([]);
	});
});
