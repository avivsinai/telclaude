/**
 * Tests for circuit breaker pattern implementation.
 *
 * Critical behaviors:
 * - Opens after failure threshold
 * - Blocks requests when open
 * - Transitions to half-open after timeout
 * - Closes after success threshold in half-open
 * - Reopens on failure in half-open
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { CircuitBreaker } from "../../src/security/circuit-breaker.js";

// Mock the database module
vi.mock("../../src/storage/db.js", () => {
	let mockDb: Database.Database | null = null;

	return {
		getDb: () => {
			if (!mockDb) {
				mockDb = new Database(":memory:");
				mockDb.exec(`
					CREATE TABLE IF NOT EXISTS circuit_breaker (
						name TEXT PRIMARY KEY,
						state TEXT NOT NULL DEFAULT 'closed',
						failure_count INTEGER NOT NULL DEFAULT 0,
						last_failure_at INTEGER,
						next_attempt_at INTEGER
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

// Mock logging
vi.mock("../../src/logging.js", () => ({
	getChildLogger: () => ({
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		debug: vi.fn(),
	}),
}));

describe("CircuitBreaker", () => {
	beforeEach(async () => {
		const { closeDb, getDb } = await import("../../src/storage/db.js");
		closeDb();
		getDb();
	});

	afterEach(async () => {
		const { closeDb } = await import("../../src/storage/db.js");
		closeDb();
	});

	describe("closed state", () => {
		it("allows execution when closed", () => {
			const cb = new CircuitBreaker("test-closed", {
				failureThreshold: 3,
				resetTimeoutMs: 1000,
			});

			expect(cb.canExecute()).toBe(true);
			expect(cb.getStatus().state).toBe("closed");
		});

		it("resets failure count on success", () => {
			const cb = new CircuitBreaker("test-reset", {
				failureThreshold: 3,
				resetTimeoutMs: 1000,
			});

			// Record some failures
			cb.recordFailure();
			cb.recordFailure();
			expect(cb.getStatus().failureCount).toBe(2);

			// Success should reset
			cb.recordSuccess();
			expect(cb.getStatus().failureCount).toBe(0);
		});
	});

	describe("opening the circuit", () => {
		it("opens after reaching failure threshold", () => {
			const cb = new CircuitBreaker("test-open", {
				failureThreshold: 3,
				resetTimeoutMs: 1000,
			});

			cb.recordFailure();
			cb.recordFailure();
			expect(cb.getStatus().state).toBe("closed");

			cb.recordFailure(); // Third failure opens circuit
			expect(cb.getStatus().state).toBe("open");
		});

		it("blocks execution when open", () => {
			const cb = new CircuitBreaker("test-block", {
				failureThreshold: 2,
				resetTimeoutMs: 10000, // Long timeout
			});

			cb.recordFailure();
			cb.recordFailure();

			expect(cb.canExecute()).toBe(false);
		});
	});

	describe("half-open transition", () => {
		it("transitions to half-open after timeout", async () => {
			const cb = new CircuitBreaker("test-half-open", {
				failureThreshold: 1,
				resetTimeoutMs: 10, // Very short timeout
			});

			cb.recordFailure();
			expect(cb.getStatus().state).toBe("open");

			// Wait for timeout
			await new Promise((resolve) => setTimeout(resolve, 20));

			// Should transition on next canExecute check
			expect(cb.canExecute()).toBe(true);
			expect(cb.getStatus().state).toBe("half_open");
		});

		it("closes after success threshold in half-open", async () => {
			const cb = new CircuitBreaker("test-close-half", {
				failureThreshold: 1,
				resetTimeoutMs: 10,
				successThreshold: 2,
			});

			cb.recordFailure();
			await new Promise((resolve) => setTimeout(resolve, 20));
			cb.canExecute(); // Trigger half-open

			cb.recordSuccess();
			expect(cb.getStatus().state).toBe("half_open");

			cb.recordSuccess(); // Second success closes
			expect(cb.getStatus().state).toBe("closed");
		});

		it("reopens on failure in half-open", async () => {
			const cb = new CircuitBreaker("test-reopen", {
				failureThreshold: 1,
				resetTimeoutMs: 10,
			});

			cb.recordFailure();
			await new Promise((resolve) => setTimeout(resolve, 20));
			cb.canExecute(); // Trigger half-open

			cb.recordFailure(); // Failure reopens
			expect(cb.getStatus().state).toBe("open");
		});
	});

	describe("manual reset", () => {
		it("can be manually reset to closed", () => {
			const cb = new CircuitBreaker("test-manual-reset", {
				failureThreshold: 1,
				resetTimeoutMs: 10000,
			});

			cb.recordFailure();
			expect(cb.getStatus().state).toBe("open");

			cb.reset();
			expect(cb.getStatus().state).toBe("closed");
			expect(cb.getStatus().failureCount).toBe(0);
			expect(cb.canExecute()).toBe(true);
		});
	});

	describe("persistence", () => {
		it("maintains state across instances", () => {
			const name = "test-persist";
			const cb1 = new CircuitBreaker(name, {
				failureThreshold: 2,
				resetTimeoutMs: 10000,
			});

			cb1.recordFailure();
			cb1.recordFailure();
			expect(cb1.getStatus().state).toBe("open");

			// Create new instance with same name
			const cb2 = new CircuitBreaker(name, {
				failureThreshold: 2,
				resetTimeoutMs: 10000,
			});

			// Should have persisted state
			expect(cb2.getStatus().state).toBe("open");
		});
	});
});
