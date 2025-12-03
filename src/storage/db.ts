/**
 * SQLite storage layer for telclaude.
 *
 * Provides persistent, atomic storage for:
 * - Pending approvals (with TTL)
 * - Rate limit counters
 * - Identity links
 * - Sessions
 */

import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { getChildLogger } from "../logging.js";
import { CONFIG_DIR } from "../utils.js";

const logger = getChildLogger({ module: "storage" });

const DB_PATH = path.join(CONFIG_DIR, "telclaude.db");
const SCHEMA_VERSION = 2;

let db: Database.Database | null = null;

/**
 * Get or create the database connection.
 * Uses WAL mode for better concurrency.
 *
 * SECURITY: Sets restrictive file permissions on database and config directory.
 */
export function getDb(): Database.Database {
	if (db) return db;

	const dbDir = path.dirname(DB_PATH);

	// Ensure directory exists with secure permissions (owner only)
	fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });

	// Harden existing directory permissions if it already existed
	try {
		fs.chmodSync(dbDir, 0o700);
	} catch {
		// May fail on some filesystems, log but continue
		logger.warn({ path: dbDir }, "could not set directory permissions to 0700");
	}

	db = new Database(DB_PATH);

	// SECURITY: Set database file to owner read/write only
	try {
		fs.chmodSync(DB_PATH, 0o600);
	} catch {
		logger.warn({ path: DB_PATH }, "could not set database file permissions to 0600");
	}

	// Enable WAL mode for better concurrency
	db.pragma("journal_mode = WAL");

	// Run migrations
	migrate(db);

	logger.info({ path: DB_PATH }, "database initialized");

	return db;
}

/**
 * Close the database connection.
 */
export function closeDb(): void {
	if (db) {
		db.close();
		db = null;
		logger.debug("database closed");
	}
}

/**
 * Run database migrations.
 */
function migrate(database: Database.Database): void {
	// Create schema version table if not exists
	database.exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY
		)
	`);

	const row = database.prepare("SELECT version FROM schema_version LIMIT 1").get() as
		| { version: number }
		| undefined;
	const currentVersion = row?.version ?? 0;

	if (currentVersion >= SCHEMA_VERSION) {
		return;
	}

	logger.info({ from: currentVersion, to: SCHEMA_VERSION }, "running migrations");

	// Migration 1: Initial schema
	if (currentVersion < 1) {
		database.exec(`
			-- Pending approvals with TTL
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

			-- Rate limit counters
			-- Using composite key of (limiter_type, key, window_start)
			CREATE TABLE IF NOT EXISTS rate_limits (
				limiter_type TEXT NOT NULL,
				key TEXT NOT NULL,
				window_start INTEGER NOT NULL,
				points INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (limiter_type, key, window_start)
			);
			CREATE INDEX IF NOT EXISTS idx_rate_limits_expiry ON rate_limits(window_start);

			-- Identity links (Telegram chat -> local user)
			CREATE TABLE IF NOT EXISTS identity_links (
				chat_id INTEGER PRIMARY KEY,
				local_user_id TEXT NOT NULL,
				linked_at INTEGER NOT NULL,
				linked_by TEXT NOT NULL
			);

			-- Pending link codes (for out-of-band verification)
			CREATE TABLE IF NOT EXISTS pending_link_codes (
				code TEXT PRIMARY KEY,
				local_user_id TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_pending_link_codes_expires ON pending_link_codes(expires_at);

			-- Sessions
			CREATE TABLE IF NOT EXISTS sessions (
				session_key TEXT PRIMARY KEY,
				session_id TEXT NOT NULL,
				updated_at INTEGER NOT NULL,
				system_sent INTEGER NOT NULL DEFAULT 0
			);

			-- Circuit breaker state
			CREATE TABLE IF NOT EXISTS circuit_breaker (
				name TEXT PRIMARY KEY,
				state TEXT NOT NULL DEFAULT 'closed',
				failure_count INTEGER NOT NULL DEFAULT 0,
				last_failure_at INTEGER,
				next_attempt_at INTEGER
			);

		`);
	}

	// Migration 2: Remove totp_secrets table (now stored in OS keychain via daemon)
	if (currentVersion < 2) {
		database.exec(`
			DROP TABLE IF EXISTS totp_secrets;
		`);
		logger.info("migration 2: removed totp_secrets table (secrets now in OS keychain)");
	}

	// Update schema version
	database.prepare("DELETE FROM schema_version").run();
	database.prepare("INSERT INTO schema_version (version) VALUES (?)").run(SCHEMA_VERSION);

	logger.info({ version: SCHEMA_VERSION }, "migrations complete");
}

/**
 * Clean up expired entries from all tables.
 * Call periodically to prevent database bloat.
 */
export function cleanupExpired(): { approvals: number; linkCodes: number; rateLimits: number } {
	const database = getDb();
	const now = Date.now();

	// Clean expired approvals
	const approvalsResult = database.prepare("DELETE FROM approvals WHERE expires_at < ?").run(now);

	// Clean expired link codes
	const linkCodesResult = database
		.prepare("DELETE FROM pending_link_codes WHERE expires_at < ?")
		.run(now);

	// Clean old rate limit windows (older than 1 hour)
	const oneHourAgo = now - 3600 * 1000;
	const rateLimitsResult = database
		.prepare("DELETE FROM rate_limits WHERE window_start < ?")
		.run(oneHourAgo);

	const result = {
		approvals: approvalsResult.changes,
		linkCodes: linkCodesResult.changes,
		rateLimits: rateLimitsResult.changes,
	};

	if (result.approvals > 0 || result.linkCodes > 0 || result.rateLimits > 0) {
		logger.debug(result, "cleaned up expired entries");
	}

	return result;
}

/**
 * Get database file path.
 */
export function getDbPath(): string {
	return DB_PATH;
}
