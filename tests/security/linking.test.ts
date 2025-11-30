/**
 * Tests for identity linking security-critical behavior.
 *
 * Critical behaviors:
 * - Link codes can only be consumed once
 * - Expired codes cannot be consumed
 * - Links are scoped to specific chat
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import {
	consumeLinkCode,
	generateLinkCode,
	getIdentityLink,
	isLinked,
	listIdentityLinks,
	removeIdentityLink,
} from "../../src/security/linking.js";

// Mock the database module
vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;

	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				mockDb.exec(`
					CREATE TABLE IF NOT EXISTS pending_link_codes (
						code TEXT PRIMARY KEY,
						local_user_id TEXT NOT NULL,
						created_at INTEGER NOT NULL,
						expires_at INTEGER NOT NULL
					);
					CREATE INDEX IF NOT EXISTS idx_pending_link_codes_expires ON pending_link_codes(expires_at);

					CREATE TABLE IF NOT EXISTS identity_links (
						chat_id INTEGER PRIMARY KEY,
						local_user_id TEXT NOT NULL,
						linked_at INTEGER NOT NULL,
						linked_by TEXT NOT NULL
					);
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

describe("Identity Linking", () => {
	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
	});

	describe("link code generation", () => {
		it("generates formatted code", () => {
			const code = generateLinkCode("user-test");

			// Should be in XXXX-XXXX format
			expect(code).toMatch(/^[A-F0-9]{4}-[A-F0-9]{4}$/);
		});

		it("generates unique codes", () => {
			const codes = new Set<string>();
			for (let i = 0; i < 100; i++) {
				codes.add(generateLinkCode(`user-${i}`));
			}
			expect(codes.size).toBe(100);
		});
	});

	describe("code consumption", () => {
		it("successfully links on valid code", () => {
			const localUserId = "local-user-1";
			const chatId = 123456;
			const code = generateLinkCode(localUserId);

			const result = consumeLinkCode(code, chatId, "test-linker");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.localUserId).toBe(localUserId);
			}
		});

		it("accepts code without dash", () => {
			const localUserId = "local-user-nodash";
			const chatId = 234567;
			const code = generateLinkCode(localUserId);
			const codeWithoutDash = code.replace("-", "");

			const result = consumeLinkCode(codeWithoutDash, chatId, "test-linker");

			expect(result.success).toBe(true);
		});

		it("fails on second consume attempt (atomic)", () => {
			const code = generateLinkCode("user-once");
			const chatId = 345678;

			// First consumption
			const first = consumeLinkCode(code, chatId, "linker1");
			expect(first.success).toBe(true);

			// Second consumption should fail
			const second = consumeLinkCode(code, chatId, "linker2");
			expect(second.success).toBe(false);
		});

		it("fails for invalid code", () => {
			const result = consumeLinkCode("INVALID-CODE", 123456, "test");
			expect(result.success).toBe(false);
		});
	});

	describe("identity link storage", () => {
		it("stores link after consumption", () => {
			const localUserId = "stored-user";
			const chatId = 456789;
			const code = generateLinkCode(localUserId);

			consumeLinkCode(code, chatId, "test-linker");

			const link = getIdentityLink(chatId);
			expect(link).not.toBeNull();
			expect(link?.localUserId).toBe(localUserId);
			expect(link?.chatId).toBe(chatId);
		});

		it("isLinked returns correct status", () => {
			const chatId = 567890;
			expect(isLinked(chatId)).toBe(false);

			const code = generateLinkCode("linked-user");
			consumeLinkCode(code, chatId, "test");

			expect(isLinked(chatId)).toBe(true);
		});

		it("can remove identity link", () => {
			const chatId = 678901;
			const code = generateLinkCode("remove-user");
			consumeLinkCode(code, chatId, "test");

			expect(isLinked(chatId)).toBe(true);

			const removed = removeIdentityLink(chatId);
			expect(removed).toBe(true);
			expect(isLinked(chatId)).toBe(false);
		});

		it("lists all identity links", () => {
			// Create multiple links
			for (let i = 0; i < 3; i++) {
				const code = generateLinkCode(`list-user-${i}`);
				consumeLinkCode(code, 1000 + i, "test");
			}

			const links = listIdentityLinks();
			expect(links.length).toBeGreaterThanOrEqual(3);
		});
	});

	describe("link replacement", () => {
		it("replaces existing link for same chat", () => {
			const chatId = 789012;

			// First link
			const code1 = generateLinkCode("first-user");
			consumeLinkCode(code1, chatId, "linker1");
			expect(getIdentityLink(chatId)?.localUserId).toBe("first-user");

			// Second link replaces
			const code2 = generateLinkCode("second-user");
			consumeLinkCode(code2, chatId, "linker2");
			expect(getIdentityLink(chatId)?.localUserId).toBe("second-user");

			// Only one link exists
			const linksForChat = listIdentityLinks().filter((l) => l.chatId === chatId);
			expect(linksForChat.length).toBe(1);
		});
	});
});
