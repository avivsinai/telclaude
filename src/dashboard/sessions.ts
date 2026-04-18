/**
 * In-memory session store for the dashboard.
 *
 * Sessions are issued only after a successful TOTP verification. They are
 * stored in-process (never persisted) because:
 *   - the dashboard is a single-node, localhost-only surface; there's no
 *     HA/scale requirement
 *   - persisting session IDs to disk would be a recovery hazard (stolen
 *     ~/.telclaude → persistent auth bypass)
 *
 * The session token itself is an opaque 256-bit random id set as a cookie.
 * TTL is fixed at 15 minutes from creation (no sliding window) to keep the
 * dashboard's attack surface small.
 */

import crypto from "node:crypto";

/** Fixed 15-minute TTL. Matches the W15 spec. */
export const DASHBOARD_SESSION_TTL_MS = 15 * 60 * 1000;

/** Cookie name used for the dashboard session. */
export const DASHBOARD_COOKIE_NAME = "telclaude_dash";

type SessionRow = {
	id: string;
	createdAt: number;
	expiresAt: number;
	localUserId: string;
};

export class DashboardSessionStore {
	private sessions = new Map<string, SessionRow>();

	/** Purge expired rows. Called on every lookup. */
	private sweep(now: number): void {
		for (const [id, row] of this.sessions) {
			if (row.expiresAt <= now) {
				this.sessions.delete(id);
			}
		}
	}

	create(localUserId: string, now: number = Date.now()): SessionRow {
		this.sweep(now);
		const id = crypto.randomBytes(32).toString("base64url");
		const row: SessionRow = {
			id,
			createdAt: now,
			expiresAt: now + DASHBOARD_SESSION_TTL_MS,
			localUserId,
		};
		this.sessions.set(id, row);
		return row;
	}

	lookup(id: string | undefined, now: number = Date.now()): SessionRow | null {
		if (!id) return null;
		this.sweep(now);
		const row = this.sessions.get(id);
		if (!row) return null;
		if (row.expiresAt <= now) {
			this.sessions.delete(id);
			return null;
		}
		return row;
	}

	revoke(id: string): void {
		this.sessions.delete(id);
	}

	/** Testing helper. */
	size(): number {
		return this.sessions.size;
	}
}
