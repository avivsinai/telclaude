/**
 * Tests for approval system security-critical behavior.
 *
 * Critical behaviors:
 * - Approvals can only be consumed once (atomic)
 * - Expired approvals cannot be consumed
 * - Approvals are scoped to specific chat
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { consumeApproval, createApproval } from "../../src/security/approvals.js";

// Mock the database module
vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;

	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				// Run minimal schema for approvals table
				mockDb.exec(`
					CREATE TABLE IF NOT EXISTS approvals (
						nonce TEXT PRIMARY KEY,
						request_id TEXT NOT NULL,
						chat_id INTEGER NOT NULL,
						created_at INTEGER NOT NULL,
						expires_at INTEGER NOT NULL,
						tier TEXT NOT NULL,
						body TEXT NOT NULL,
						media_path TEXT,
						media_url TEXT,
						media_type TEXT,
						username TEXT,
						from_user TEXT NOT NULL,
						to_user TEXT NOT NULL,
						message_id TEXT NOT NULL,
						observer_classification TEXT NOT NULL,
						observer_confidence REAL NOT NULL,
						observer_reason TEXT
					);
					CREATE INDEX IF NOT EXISTS idx_approvals_chat_id ON approvals(chat_id);
					CREATE INDEX IF NOT EXISTS idx_approvals_expires_at ON approvals(expires_at);
				`);
			}
			return mockDb;
		},
		closeDb: () => {
			if (mockDb) {
				mockDb.close();
				mockDb = null;
			}
		},
	};
});

// Mock logging
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

describe("Approvals", () => {
	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
	});

	function createTestApproval(chatId: number, ttlMs = 60000): string {
		return createApproval(
			{
				requestId: "test-req-" + Math.random(),
				chatId,
				tier: "WRITE_SAFE",
				body: "Test message",
				from: "user123",
				to: "bot",
				messageId: "msg-123",
				observerClassification: "WARN",
				observerConfidence: 0.8,
				observerReason: "Test warning",
			},
			ttlMs,
		);
	}

	describe("atomic consumption", () => {
		it("returns approval data on first consume", () => {
			const chatId = 123456;
			const nonce = createTestApproval(chatId);

			const result = consumeApproval(nonce, chatId);

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.nonce).toBe(nonce);
				expect(result.data.chatId).toBe(chatId);
			}
		});

		it("fails on second consume attempt (atomic)", () => {
			const chatId = 123456;
			const nonce = createTestApproval(chatId);

			// First consume succeeds
			const first = consumeApproval(nonce, chatId);
			expect(first.success).toBe(true);

			// Second consume fails
			const second = consumeApproval(nonce, chatId);
			expect(second.success).toBe(false);
			if (!second.success) {
				expect(second.error).toContain("No pending approval");
			}
		});

		it("fails for non-existent nonce", () => {
			const result = consumeApproval("non-existent-nonce", 123456);
			expect(result.success).toBe(false);
		});
	});

	describe("chat scoping", () => {
		it("rejects consumption from wrong chat", () => {
			const correctChatId = 111111;
			const wrongChatId = 222222;

			const nonce = createTestApproval(correctChatId);

			// Try to consume from wrong chat
			const result = consumeApproval(nonce, wrongChatId);

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error).toContain("different chat");
			}
		});
	});

	describe("expiration", () => {
		it("rejects expired approvals", async () => {
			const chatId = 123456;
			// Create approval with 1ms TTL
			const nonce = createTestApproval(chatId, 1);

			// Wait for expiration
			await new Promise((resolve) => setTimeout(resolve, 10));

			const result = consumeApproval(nonce, chatId);

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error).toContain("expired");
			}
		});
	});

	describe("data integrity", () => {
		it("preserves all approval fields", () => {
			const chatId = 123456;
			const nonce = createTestApproval(chatId);

			const result = consumeApproval(nonce, chatId);

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.tier).toBe("WRITE_SAFE");
				expect(result.data.body).toBe("Test message");
				expect(result.data.from).toBe("user123");
				expect(result.data.observerClassification).toBe("WARN");
				expect(result.data.observerConfidence).toBe(0.8);
			}
		});
	});
});
