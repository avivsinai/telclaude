/**
 * Circuit breaker pattern for observer timeouts.
 *
 * Prevents cascading failures when the observer (Claude SDK) is slow or failing.
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Failures exceeded threshold, requests fail fast
 * - HALF_OPEN: Testing if service recovered, limited requests pass through
 */

import { getChildLogger } from "../logging.js";
import { getDb } from "../storage/db.js";

const logger = getChildLogger({ module: "circuit-breaker" });

export type CircuitState = "closed" | "open" | "half_open";

export type CircuitBreakerConfig = {
	/** Number of failures before opening the circuit */
	failureThreshold: number;
	/** Time in ms to wait before trying half-open */
	resetTimeoutMs: number;
	/** Number of successful requests in half-open before closing */
	successThreshold: number;
};

const DEFAULT_CONFIG: CircuitBreakerConfig = {
	failureThreshold: 5,
	resetTimeoutMs: 30000, // 30 seconds
	successThreshold: 2,
};

/**
 * Database row type for circuit breaker state.
 */
type CircuitBreakerRow = {
	name: string;
	state: string;
	failure_count: number;
	last_failure_at: number | null;
	next_attempt_at: number | null;
};

/**
 * Circuit breaker for managing service health.
 */
export class CircuitBreaker {
	private name: string;
	private config: CircuitBreakerConfig;
	private halfOpenSuccesses = 0;

	constructor(name: string, config: Partial<CircuitBreakerConfig> = {}) {
		this.name = name;
		this.config = { ...DEFAULT_CONFIG, ...config };
		this.ensureExists();
	}

	/**
	 * Ensure circuit breaker record exists in database.
	 */
	private ensureExists(): void {
		const db = getDb();
		db.prepare(
			`INSERT OR IGNORE INTO circuit_breaker (name, state, failure_count)
			 VALUES (?, 'closed', 0)`,
		).run(this.name);
	}

	/**
	 * Get current state from database.
	 */
	private getState(): { state: CircuitState; failureCount: number; nextAttemptAt: number | null } {
		const db = getDb();
		const row = db.prepare("SELECT * FROM circuit_breaker WHERE name = ?").get(this.name) as
			| CircuitBreakerRow
			| undefined;

		if (!row) {
			return { state: "closed", failureCount: 0, nextAttemptAt: null };
		}

		return {
			state: row.state as CircuitState,
			failureCount: row.failure_count,
			nextAttemptAt: row.next_attempt_at,
		};
	}

	/**
	 * Update state in database.
	 */
	private setState(state: CircuitState, failureCount: number, nextAttemptAt: number | null): void {
		const db = getDb();
		db.prepare(
			`UPDATE circuit_breaker
			 SET state = ?, failure_count = ?, next_attempt_at = ?, last_failure_at = ?
			 WHERE name = ?`,
		).run(state, failureCount, nextAttemptAt, state === "open" ? Date.now() : null, this.name);
	}

	/**
	 * Check if request should be allowed through.
	 */
	canExecute(): boolean {
		const { state, nextAttemptAt } = this.getState();

		switch (state) {
			case "closed":
				return true;

			case "open":
				// Check if reset timeout has passed
				if (nextAttemptAt && Date.now() >= nextAttemptAt) {
					// Transition to half-open
					this.setState("half_open", 0, null);
					this.halfOpenSuccesses = 0;
					logger.info({ name: this.name }, "circuit breaker transitioning to half-open");
					return true;
				}
				return false;

			case "half_open":
				// Allow limited requests through for testing
				return true;

			default:
				return true;
		}
	}

	/**
	 * Record a successful execution.
	 */
	recordSuccess(): void {
		const { state } = this.getState();

		if (state === "half_open") {
			this.halfOpenSuccesses++;
			if (this.halfOpenSuccesses >= this.config.successThreshold) {
				// Recovery confirmed, close the circuit
				this.setState("closed", 0, null);
				this.halfOpenSuccesses = 0;
				logger.info({ name: this.name }, "circuit breaker closed after recovery");
			}
		} else if (state === "closed") {
			// Reset failure count on success in closed state
			const db = getDb();
			db.prepare("UPDATE circuit_breaker SET failure_count = 0 WHERE name = ?").run(this.name);
		}
	}

	/**
	 * Record a failed execution.
	 */
	recordFailure(): void {
		const { state, failureCount } = this.getState();

		if (state === "half_open") {
			// Failure during testing, reopen circuit
			const nextAttempt = Date.now() + this.config.resetTimeoutMs;
			this.setState("open", failureCount + 1, nextAttempt);
			this.halfOpenSuccesses = 0;
			logger.warn({ name: this.name }, "circuit breaker reopened after half-open failure");
		} else if (state === "closed") {
			const newCount = failureCount + 1;
			if (newCount >= this.config.failureThreshold) {
				// Too many failures, open the circuit
				const nextAttempt = Date.now() + this.config.resetTimeoutMs;
				this.setState("open", newCount, nextAttempt);
				logger.warn(
					{ name: this.name, failures: newCount, resetIn: this.config.resetTimeoutMs },
					"circuit breaker opened",
				);
			} else {
				// Increment failure count
				const db = getDb();
				db.prepare(
					"UPDATE circuit_breaker SET failure_count = ?, last_failure_at = ? WHERE name = ?",
				).run(newCount, Date.now(), this.name);
			}
		}
	}

	/**
	 * Get current circuit state info for monitoring.
	 */
	getStatus(): { state: CircuitState; failureCount: number; canExecute: boolean } {
		const { state, failureCount } = this.getState();
		return {
			state,
			failureCount,
			canExecute: this.canExecute(),
		};
	}

	/**
	 * Reset the circuit breaker to closed state.
	 */
	reset(): void {
		this.setState("closed", 0, null);
		this.halfOpenSuccesses = 0;
		logger.info({ name: this.name }, "circuit breaker manually reset");
	}
}
