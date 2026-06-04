import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	consumePendingTOTPMessage,
	savePendingTOTPMessage,
} from "../../src/security/totp-auth-gate.js";
import { closeDb, resetDatabase } from "../../src/storage/db.js";

const ORIGINAL_DATA_DIR = process.env.TELCLAUDE_DATA_DIR;

describe("TOTP auth gate pending message replay", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-totp-auth-gate-"));
		process.env.TELCLAUDE_DATA_DIR = tempDir;
		resetDatabase();
	});

	afterEach(() => {
		closeDb();
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_DATA_DIR === undefined) {
			delete process.env.TELCLAUDE_DATA_DIR;
		} else {
			process.env.TELCLAUDE_DATA_DIR = ORIGINAL_DATA_DIR;
		}
	});

	it("preserves the original Telegram sender and thread while awaiting verification", () => {
		savePendingTOTPMessage({
			chatId: 123,
			messageId: "msg-original",
			body: "continue the original request",
			username: "alice",
			senderId: 456,
			messageThreadId: 789,
		});

		const pending = consumePendingTOTPMessage(123);

		expect(pending).toMatchObject({
			chatId: 123,
			messageId: "msg-original",
			body: "continue the original request",
			username: "alice",
			senderId: 456,
			messageThreadId: 789,
		});
		expect(consumePendingTOTPMessage(123)).toBeNull();
	});
});
