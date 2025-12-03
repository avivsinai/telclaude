/**
 * V2 Session Pool for Claude Agent SDK.
 *
 * Uses the unstable V2 API to maintain persistent SDK sessions,
 * reducing process spawn overhead by reusing connections across messages.
 *
 * Key features:
 * - Session pooling per user/chat
 * - Automatic cleanup on idle timeout
 * - Fallback to stable query() API if V2 fails
 * - Proper lifecycle management
 */

import {
	type SDKMessage,
	type Options as SDKOptions,
	type SDKSession,
	type SDKSessionOptions,
	query,
	unstable_v2_createSession,
	unstable_v2_resumeSession,
} from "@anthropic-ai/claude-agent-sdk";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "session-pool" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface PooledSession {
	session: SDKSession;
	createdAt: number;
	lastUsedAt: number;
	useCount: number;
	/** SDK session ID for resume operations */
	sdkSessionId?: string;
}

export interface SessionPoolOptions {
	/** Idle timeout in milliseconds before session is closed (default: 5 minutes) */
	idleTimeoutMs?: number;
	/** Maximum uses before recycling session (default: 100) */
	maxUses?: number;
	/** Cleanup interval in milliseconds (default: 60 seconds) */
	cleanupIntervalMs?: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session Pool
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_MAX_USES = 100;
const DEFAULT_CLEANUP_INTERVAL_MS = 60 * 1000; // 1 minute

export class SessionPool {
	private sessions = new Map<string, PooledSession>();
	private cleanupTimer: NodeJS.Timeout | null = null;
	private readonly idleTimeoutMs: number;
	private readonly maxUses: number;

	constructor(options: SessionPoolOptions = {}) {
		this.idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
		this.maxUses = options.maxUses ?? DEFAULT_MAX_USES;

		// Start cleanup timer
		const cleanupInterval = options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL_MS;
		this.cleanupTimer = setInterval(() => this.cleanup(), cleanupInterval);
		this.cleanupTimer.unref(); // Don't prevent process exit
	}

	/**
	 * Get or create a session for the given key.
	 */
	async acquire(
		key: string,
		sessionOptions: SDKSessionOptions,
		resumeSessionId?: string,
	): Promise<PooledSession> {
		const existing = this.sessions.get(key);

		// Check if existing session is still valid
		if (existing) {
			const now = Date.now();
			const isIdle = now - existing.lastUsedAt > this.idleTimeoutMs;
			const isExhausted = existing.useCount >= this.maxUses;

			if (!isIdle && !isExhausted) {
				// Reuse existing session
				existing.lastUsedAt = now;
				existing.useCount++;
				logger.debug({ key, useCount: existing.useCount }, "reusing pooled session");
				return existing;
			}

			// Session is stale or exhausted, close it
			logger.debug(
				{ key, isIdle, isExhausted, useCount: existing.useCount },
				"closing stale session",
			);
			await this.destroy(key);
		}

		// Create new session
		const now = Date.now();
		let session: SDKSession;

		try {
			if (resumeSessionId) {
				// Resume existing conversation
				session = unstable_v2_resumeSession(resumeSessionId, sessionOptions);
				logger.debug({ key, resumeSessionId }, "resumed V2 session");
			} else {
				// Create new conversation
				session = unstable_v2_createSession(sessionOptions);
				logger.debug({ key }, "created new V2 session");
			}
		} catch (err) {
			logger.error({ error: String(err), key }, "failed to create V2 session");
			throw err;
		}

		const pooledSession: PooledSession = {
			session,
			createdAt: now,
			lastUsedAt: now,
			useCount: 1,
			sdkSessionId: resumeSessionId,
		};

		this.sessions.set(key, pooledSession);
		return pooledSession;
	}

	/**
	 * Update the SDK session ID after a successful query.
	 * This captures the session ID from the result for future resume.
	 */
	updateSessionId(key: string, sdkSessionId: string): void {
		const pooled = this.sessions.get(key);
		if (pooled) {
			pooled.sdkSessionId = sdkSessionId;
		}
	}

	/**
	 * Get the SDK session ID for a key (for resume operations).
	 */
	getSessionId(key: string): string | undefined {
		return this.sessions.get(key)?.sdkSessionId;
	}

	/**
	 * Destroy a specific session.
	 */
	async destroy(key: string): Promise<void> {
		const pooled = this.sessions.get(key);
		if (pooled) {
			try {
				pooled.session.close();
			} catch (err) {
				logger.warn({ error: String(err), key }, "error closing session");
			}
			this.sessions.delete(key);
			logger.debug({ key }, "destroyed pooled session");
		}
	}

	/**
	 * Cleanup idle and exhausted sessions.
	 */
	private cleanup(): void {
		const now = Date.now();
		const keysToRemove: string[] = [];

		for (const [key, pooled] of this.sessions) {
			const isIdle = now - pooled.lastUsedAt > this.idleTimeoutMs;
			const isExhausted = pooled.useCount >= this.maxUses;

			if (isIdle || isExhausted) {
				keysToRemove.push(key);
			}
		}

		for (const key of keysToRemove) {
			const pooled = this.sessions.get(key);
			if (pooled) {
				try {
					pooled.session.close();
				} catch {
					// Ignore close errors during cleanup
				}
				this.sessions.delete(key);
			}
		}

		if (keysToRemove.length > 0) {
			logger.debug({ cleaned: keysToRemove.length }, "cleaned up idle sessions");
		}
	}

	/**
	 * Destroy all sessions and stop cleanup timer.
	 */
	async destroyAll(): Promise<void> {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = null;
		}

		for (const pooled of this.sessions.values()) {
			try {
				pooled.session.close();
			} catch {
				// Ignore close errors during shutdown
			}
		}

		const count = this.sessions.size;
		this.sessions.clear();
		logger.info({ count }, "destroyed all pooled sessions");
	}

	/**
	 * Get pool statistics.
	 */
	stats(): { size: number; totalUses: number } {
		let totalUses = 0;
		for (const pooled of this.sessions.values()) {
			totalUses += pooled.useCount;
		}
		return { size: this.sessions.size, totalUses };
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Query with Session Pool
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Execute a query using the session pool with automatic fallback.
 *
 * If V2 session fails, falls back to the stable query() API.
 */
export async function* executeWithPool(
	pool: SessionPool,
	poolKey: string,
	message: string,
	sessionOptions: SDKSessionOptions,
	queryOptions: SDKOptions,
	resumeSessionId?: string,
): AsyncGenerator<SDKMessage, void, unknown> {
	let pooledSession: PooledSession | null = null;
	let usedFallback = false;

	console.log(`[DEBUG session-pool] executeWithPool starting for poolKey=${poolKey}`);

	try {
		// Try V2 session pool
		console.log("[DEBUG session-pool] About to acquire session...");
		pooledSession = await pool.acquire(poolKey, sessionOptions, resumeSessionId);
		console.log("[DEBUG session-pool] Session acquired, about to send message...");

		// Send message and yield responses
		await pooledSession.session.send(message);
		console.log("[DEBUG session-pool] Message sent, about to receive responses...");

		let msgCount = 0;
		for await (const msg of pooledSession.session.receive()) {
			msgCount++;
			console.log(`[DEBUG session-pool] Received msg #${msgCount}, type=${msg.type}`);
			// Capture session ID from result for future resume
			if (msg.type === "result" || msg.type === "system") {
				if ("session_id" in msg && msg.session_id) {
					pool.updateSessionId(poolKey, msg.session_id);
				}
			}
			yield msg;
		}
		console.log(`[DEBUG session-pool] Receive loop finished, total msgs=${msgCount}`);
	} catch (err) {
		// Log the error and try fallback
		console.log(`[DEBUG session-pool] V2 failed with error: ${String(err)}`);
		logger.warn({ error: String(err), poolKey }, "V2 session failed, falling back to query()");

		// Destroy the failed session
		await pool.destroy(poolKey);
		usedFallback = true;

		// Fallback to stable query() API
		console.log("[DEBUG session-pool] Starting fallback query()...");
		const q = query({
			prompt: message,
			options: { ...queryOptions, resume: resumeSessionId },
		});

		let fallbackMsgCount = 0;
		for await (const msg of q) {
			fallbackMsgCount++;
			console.log(`[DEBUG session-pool] Fallback msg #${fallbackMsgCount}, type=${msg.type}`);
			yield msg;
		}
		console.log(`[DEBUG session-pool] Fallback completed, total msgs=${fallbackMsgCount}`);
	}

	if (usedFallback) {
		logger.debug({ poolKey }, "fallback query completed");
	}
	console.log("[DEBUG session-pool] executeWithPool finished");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Pool Instance
// ═══════════════════════════════════════════════════════════════════════════════

let globalPool: SessionPool | null = null;

/**
 * Get the global session pool instance.
 */
export function getSessionPool(): SessionPool {
	if (!globalPool) {
		globalPool = new SessionPool();
		logger.info("global session pool initialized");
	}
	return globalPool;
}

/**
 * Destroy the global session pool (call on shutdown).
 */
export async function destroySessionPool(): Promise<void> {
	if (globalPool) {
		await globalPool.destroyAll();
		globalPool = null;
	}
}
