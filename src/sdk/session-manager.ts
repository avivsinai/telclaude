/**
 * Session Manager for Claude Agent SDK.
 *
 * Uses the STABLE query() API with resume option for multi-turn conversations.
 * Session IDs are captured from result messages and used for resume.
 */

import { type SDKMessage, type Options as SDKOptions, query } from "@anthropic-ai/claude-agent-sdk";
import { getChildLogger } from "../logging.js";

const logger = getChildLogger({ module: "session-manager" });

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface SessionInfo {
	sessionId: string;
	lastUsedAt: number;
	turnCount: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Session Manager
// ═══════════════════════════════════════════════════════════════════════════════

const SESSION_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

class SessionManager {
	private sessions = new Map<string, SessionInfo>();
	private cleanupTimer: NodeJS.Timeout | null = null;

	constructor() {
		this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
		this.cleanupTimer.unref();
	}

	getSessionId(key: string): string | undefined {
		const session = this.sessions.get(key);
		if (session) {
			if (Date.now() - session.lastUsedAt > SESSION_EXPIRY_MS) {
				this.sessions.delete(key);
				logger.debug({ key }, "session expired");
				return undefined;
			}
			return session.sessionId;
		}
		return undefined;
	}

	updateSession(key: string, sessionId: string): void {
		const existing = this.sessions.get(key);
		const now = Date.now();

		if (existing) {
			existing.sessionId = sessionId;
			existing.lastUsedAt = now;
			existing.turnCount++;
		} else {
			this.sessions.set(key, { sessionId, lastUsedAt: now, turnCount: 1 });
		}
	}

	clearSession(key: string): void {
		this.sessions.delete(key);
	}

	private cleanup(): void {
		const now = Date.now();
		for (const [key, session] of this.sessions) {
			if (now - session.lastUsedAt > SESSION_EXPIRY_MS) {
				this.sessions.delete(key);
			}
		}
	}

	destroy(): void {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = null;
		}
		this.sessions.clear();
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Instance
// ═══════════════════════════════════════════════════════════════════════════════

let manager: SessionManager | null = null;

export function getSessionManager(): SessionManager {
	if (!manager) {
		manager = new SessionManager();
		logger.info("session manager initialized");
	}
	return manager;
}

export function destroySessionManager(): void {
	if (manager) {
		manager.destroy();
		manager = null;
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Query Execution with Session Resume
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Execute a query with automatic session resume support.
 *
 * This is the idiomatic pattern for multi-turn conversations with the Claude Agent SDK:
 * 1. Look up existing session ID for this key
 * 2. Pass it via `options.resume` to the stable query() API
 * 3. Capture new session ID from response for future turns
 */
export async function* executeWithSession(
	sessionManager: SessionManager,
	sessionKey: string,
	message: string,
	queryOptions: SDKOptions,
): AsyncGenerator<SDKMessage, void, unknown> {
	const existingSessionId = sessionManager.getSessionId(sessionKey);
	const options: SDKOptions = { ...queryOptions, resume: existingSessionId };

	if (existingSessionId) {
		logger.debug({ sessionKey, sessionId: existingSessionId }, "resuming session");
	} else {
		logger.debug({ sessionKey }, "creating new session");
	}

	const q = query({ prompt: message, options });

	for await (const msg of q) {
		// Capture session ID for future resume
		if ((msg.type === "system" || msg.type === "result") && "session_id" in msg && msg.session_id) {
			sessionManager.updateSession(sessionKey, msg.session_id);
		}

		yield msg;
	}
}
