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
import {
	consumeApproval,
	createApproval,
	grantAllowlist,
	listAllowlist,
	lookupAllowlist,
	revokeAllowlistEntry,
	revokeSessionAllowlist,
} from "../../src/security/approvals.js";

// Mock the database module
vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;

	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				// Run minimal schema for approvals + approval_allowlist tables
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
					media_type TEXT,
					media_file_path TEXT,
					media_file_id TEXT,
						username TEXT,
						from_user TEXT NOT NULL,
						to_user TEXT NOT NULL,
						message_id TEXT NOT NULL,
						observer_classification TEXT NOT NULL,
						observer_confidence REAL NOT NULL,
						observer_reason TEXT,
						risk_tier TEXT,
						tool_key TEXT,
						session_key TEXT
					);
					CREATE INDEX IF NOT EXISTS idx_approvals_chat_id ON approvals(chat_id);
					CREATE INDEX IF NOT EXISTS idx_approvals_expires_at ON approvals(expires_at);

					CREATE TABLE IF NOT EXISTS approval_allowlist (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						user_id TEXT NOT NULL,
						tier TEXT NOT NULL,
						tool_key TEXT NOT NULL,
						scope TEXT NOT NULL,
						session_key TEXT,
						chat_id INTEGER NOT NULL,
						granted_at INTEGER NOT NULL,
						expires_at INTEGER,
						last_used_at INTEGER,
						UNIQUE(user_id, tool_key, scope)
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
		const result = createApproval(
			{
				requestId: "test-req-" + Math.random(),
				chatId,
				tier: "WRITE_LOCAL",
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
		return result.nonce;
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
				expect(result.data.tier).toBe("WRITE_LOCAL");
				expect(result.data.body).toBe("Test message");
				expect(result.data.from).toBe("user123");
				expect(result.data.observerClassification).toBe("WARN");
				expect(result.data.observerConfidence).toBe(0.8);
			}
		});

		it("persists W1 risk metadata through the round-trip", () => {
			const chatId = 123456;
			const { nonce } = createApproval({
				requestId: "rq-1",
				chatId,
				tier: "WRITE_LOCAL",
				body: "run npm test",
				from: "user123",
				to: "bot",
				messageId: "msg-1",
				observerClassification: "ALLOW",
				observerConfidence: 0.9,
				riskTier: "medium",
				toolKey: "Bash",
				sessionKey: "tg:123456",
			});

			const result = consumeApproval(nonce, chatId);
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.riskTier).toBe("medium");
				expect(result.data.toolKey).toBe("Bash");
				expect(result.data.sessionKey).toBe("tg:123456");
			}
		});
	});
});

describe("Approval allowlist (W1)", () => {
	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
	});

	describe("grant + lookup", () => {
		it("records an 'always' grant and returns it on lookup", () => {
			grantAllowlist({
				userId: "tg:42",
				tier: "WRITE_LOCAL",
				toolKey: "Read",
				scope: "always",
				sessionKey: null,
				chatId: 42,
			});
			const hit = lookupAllowlist({
				userId: "tg:42",
				toolKey: "Read",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:42",
			});
			expect(hit).not.toBeNull();
			expect(hit?.scope).toBe("always");
			expect(hit?.lastUsedAt).toBeTypeOf("number");
		});

		it("returns null when no grant exists", () => {
			const hit = lookupAllowlist({
				userId: "tg:99",
				toolKey: "Write",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:99",
			});
			expect(hit).toBeNull();
		});

		it("consumes a 'once' grant on first lookup", () => {
			grantAllowlist({
				userId: "tg:1",
				tier: "WRITE_LOCAL",
				toolKey: "Bash",
				scope: "once",
				sessionKey: null,
				chatId: 1,
			});
			const first = lookupAllowlist({
				userId: "tg:1",
				toolKey: "Bash",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:1",
			});
			expect(first?.scope).toBe("once");
			const second = lookupAllowlist({
				userId: "tg:1",
				toolKey: "Bash",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:1",
			});
			expect(second).toBeNull();
		});

		it("session scope only matches the exact session key", () => {
			grantAllowlist({
				userId: "tg:7",
				tier: "WRITE_LOCAL",
				toolKey: "Edit",
				scope: "session",
				sessionKey: "tg:7",
				chatId: 7,
			});
			const miss = lookupAllowlist({
				userId: "tg:7",
				toolKey: "Edit",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:other",
			});
			expect(miss).toBeNull();
			const hit = lookupAllowlist({
				userId: "tg:7",
				toolKey: "Edit",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:7",
			});
			expect(hit?.scope).toBe("session");
		});

		it("picks 'always' over 'session' when both apply", () => {
			grantAllowlist({
				userId: "tg:8",
				tier: "WRITE_LOCAL",
				toolKey: "Edit",
				scope: "session",
				sessionKey: "tg:8",
				chatId: 8,
			});
			grantAllowlist({
				userId: "tg:8",
				tier: "WRITE_LOCAL",
				toolKey: "Edit",
				scope: "always",
				sessionKey: null,
				chatId: 8,
			});
			const hit = lookupAllowlist({
				userId: "tg:8",
				toolKey: "Edit",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:8",
			});
			expect(hit?.scope).toBe("always");
		});

		it("refuses to record a session scope without a session key", () => {
			expect(() =>
				grantAllowlist({
					userId: "tg:5",
					tier: "WRITE_LOCAL",
					toolKey: "Edit",
					scope: "session",
					sessionKey: null,
					chatId: 5,
				}),
			).toThrow(/session scope requires sessionKey/);
		});

		it("re-granting an existing (user, tool, scope) upserts", () => {
			grantAllowlist({
				userId: "tg:2",
				tier: "READ_ONLY",
				toolKey: "Read",
				scope: "always",
				sessionKey: null,
				chatId: 2,
			});
			grantAllowlist({
				userId: "tg:2",
				tier: "WRITE_LOCAL",
				toolKey: "Read",
				scope: "always",
				sessionKey: null,
				chatId: 2,
			});
			const entries = listAllowlist({ userId: "tg:2" });
			expect(entries).toHaveLength(1);
			expect(entries[0]?.tier).toBe("WRITE_LOCAL");
		});
	});

	describe("tier cap", () => {
		it("rejects a grant at a lower tier than the caller requested", () => {
			grantAllowlist({
				userId: "tg:30",
				tier: "WRITE_LOCAL",
				toolKey: "Write",
				scope: "always",
				sessionKey: null,
				chatId: 30,
			});
			// FULL_ACCESS request must not be satisfied by a WRITE_LOCAL grant.
			const miss = lookupAllowlist({
				userId: "tg:30",
				toolKey: "Write",
				tier: "FULL_ACCESS",
				sessionKey: "tg:30",
			});
			expect(miss).toBeNull();
		});

		it("SOCIAL grant satisfies a WRITE_LOCAL request (equal rank)", () => {
			grantAllowlist({
				userId: "tg:31",
				tier: "SOCIAL",
				toolKey: "Edit",
				scope: "always",
				sessionKey: null,
				chatId: 31,
			});
			const hit = lookupAllowlist({
				userId: "tg:31",
				toolKey: "Edit",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:31",
			});
			expect(hit?.tier).toBe("SOCIAL");
		});
	});

	describe("risk-tier scope cap", () => {
		it("forbids 'always' and 'session' for high-risk actions", async () => {
			const { scopeAllowedForRisk } = await import(
				"../../src/security/risk-tiers.js"
			);
			expect(scopeAllowedForRisk("high", "once")).toBe(true);
			expect(scopeAllowedForRisk("high", "session")).toBe(false);
			expect(scopeAllowedForRisk("high", "always")).toBe(false);
		});

		it("allows all scopes for low and medium risk", async () => {
			const { scopeAllowedForRisk } = await import(
				"../../src/security/risk-tiers.js"
			);
			for (const scope of ["once", "session", "always"] as const) {
				expect(scopeAllowedForRisk("low", scope)).toBe(true);
				expect(scopeAllowedForRisk("medium", scope)).toBe(true);
			}
		});

		it("classifyRisk flags destructive Bash as high", async () => {
			const { classifyRisk } = await import("../../src/security/risk-tiers.js");
			expect(
				classifyRisk({ toolName: "Bash", bashCommand: "rm -rf /tmp/foo" }),
			).toBe("high");
			expect(classifyRisk({ toolName: "Bash", bashCommand: "ls -la" })).toBe(
				"medium",
			);
			expect(classifyRisk({ toolName: "Read" })).toBe("low");
		});
	});

	describe("expiry + revocation", () => {
		it("expired 'always' grants are not returned", () => {
			grantAllowlist({
				userId: "tg:40",
				tier: "WRITE_LOCAL",
				toolKey: "Read",
				scope: "always",
				sessionKey: null,
				chatId: 40,
				now: 1000,
			});
			const miss = lookupAllowlist({
				userId: "tg:40",
				toolKey: "Read",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:40",
				now: 1000 + 31 * 24 * 60 * 60 * 1000,
			});
			expect(miss).toBeNull();
		});

		it("revoke by id removes the entry", () => {
			const entry = grantAllowlist({
				userId: "tg:50",
				tier: "WRITE_LOCAL",
				toolKey: "Bash",
				scope: "always",
				sessionKey: null,
				chatId: 50,
			});
			expect(revokeAllowlistEntry(entry.id)).toBe(true);
			const hit = lookupAllowlist({
				userId: "tg:50",
				toolKey: "Bash",
				tier: "WRITE_LOCAL",
				sessionKey: "tg:50",
			});
			expect(hit).toBeNull();
		});

		it("revokeSessionAllowlist clears all session-scoped grants for a session", () => {
			grantAllowlist({
				userId: "tg:61",
				tier: "WRITE_LOCAL",
				toolKey: "Read",
				scope: "session",
				sessionKey: "tg:61",
				chatId: 61,
			});
			grantAllowlist({
				userId: "tg:61",
				tier: "WRITE_LOCAL",
				toolKey: "Edit",
				scope: "session",
				sessionKey: "tg:61",
				chatId: 61,
			});
			grantAllowlist({
				userId: "tg:61",
				tier: "WRITE_LOCAL",
				toolKey: "Write",
				scope: "always",
				sessionKey: null,
				chatId: 61,
			});
			const removed = revokeSessionAllowlist("tg:61");
			expect(removed).toBe(2);
			const remaining = listAllowlist({ userId: "tg:61" });
			expect(remaining).toHaveLength(1);
			expect(remaining[0]?.scope).toBe("always");
		});
	});
});
