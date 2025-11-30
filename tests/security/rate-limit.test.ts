/**
 * Tests for rate limiter security-critical behavior.
 *
 * Critical behaviors:
 * - Fails closed on errors (blocks requests, doesn't allow)
 * - Enforces limits atomically
 * - Per-tier limits are respected
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { RateLimiter } from "../../src/security/rate-limit.js";

// Mock the database module
vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;

	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				// Run minimal schema for rate_limits table
				mockDb.exec(`
					CREATE TABLE IF NOT EXISTS rate_limits (
						limiter_type TEXT NOT NULL,
						key TEXT NOT NULL,
						window_start INTEGER NOT NULL,
						points INTEGER NOT NULL DEFAULT 0,
						PRIMARY KEY (limiter_type, key, window_start)
					)
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

// Mock logging to avoid noise
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

describe("RateLimiter", () => {
	let limiter: RateLimiter;

	beforeEach(async () => {
		// Reset the mock database
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb(); // Recreate fresh db
		limiter = new RateLimiter();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
	});

	describe("basic limits", () => {
		it("allows requests within limits", async () => {
			const result = await limiter.checkLimit("user1", "READ_ONLY");
			expect(result.allowed).toBe(true);
			expect(result.remaining).toBeGreaterThanOrEqual(0);
		});

		it("blocks requests after per-user minute limit exceeded", async () => {
			const userId = "user-minute-test";

			// Exhaust per-user minute limit (default: 10)
			for (let i = 0; i < 10; i++) {
				const result = await limiter.checkLimit(userId, "READ_ONLY");
				expect(result.allowed).toBe(true);
			}

			// Next request should be blocked
			const blocked = await limiter.checkLimit(userId, "READ_ONLY");
			expect(blocked.allowed).toBe(false);
			expect(blocked.limitType).toBe("user");
		});

		it("blocks requests after per-tier minute limit exceeded", async () => {
			// FULL_ACCESS tier has stricter limits (5 per minute)
			const userId = "tier-test-user";

			for (let i = 0; i < 5; i++) {
				const result = await limiter.checkLimit(userId, "FULL_ACCESS");
				expect(result.allowed).toBe(true);
			}

			// Next request should be blocked by tier limit
			const blocked = await limiter.checkLimit(userId, "FULL_ACCESS");
			expect(blocked.allowed).toBe(false);
			expect(blocked.limitType).toBe("tier");
		});
	});

	describe("fail-closed behavior", () => {
		it("blocks requests when database throws", async () => {
			// Create a limiter that will fail
			const { getDb } = await import("../../src/storage/db.js");
			const db = getDb();

			// Close the database to force errors
			db.close();

			const result = await limiter.checkLimit("error-user", "READ_ONLY");

			// CRITICAL: Must block, not allow
			expect(result.allowed).toBe(false);
			expect(result.remaining).toBe(0);
		});
	});

	describe("reset functionality", () => {
		it("allows requests after user reset", async () => {
			const userId = "reset-test-user";

			// Exhaust limits
			for (let i = 0; i < 10; i++) {
				await limiter.checkLimit(userId, "READ_ONLY");
			}

			// Verify blocked
			const blocked = await limiter.checkLimit(userId, "READ_ONLY");
			expect(blocked.allowed).toBe(false);

			// Reset user
			await limiter.resetUser(userId);

			// Should be allowed again
			const allowed = await limiter.checkLimit(userId, "READ_ONLY");
			expect(allowed.allowed).toBe(true);
		});
	});

	describe("user usage tracking", () => {
		it("tracks usage correctly", async () => {
			const userId = "usage-test-user";

			// Make some requests
			await limiter.checkLimit(userId, "WRITE_SAFE");
			await limiter.checkLimit(userId, "WRITE_SAFE");
			await limiter.checkLimit(userId, "WRITE_SAFE");

			const usage = await limiter.getUserUsage(userId, "WRITE_SAFE");
			expect(usage.perUser.minute).toBe(3);
			expect(usage.perTier.minute).toBe(3);
		});
	});
});
