/**
 * SQLite storage layer for telclaude.
 *
 * One-shot schema (no migrations). DB is treated as ephemeral operational state.
 */

import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { getChildLogger } from "../logging.js";
import { CONFIG_DIR } from "../utils.js";

const logger = getChildLogger({ module: "storage" });

const DB_PATH = path.join(CONFIG_DIR, "telclaude.db");

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

	// Create schema (single-version, no migrations)
	initializeSchema(db);

	logger.info({ path: DB_PATH }, "database initialized");

	return db;
}

/**
 * Dangerously reset the database file and recreate schema.
 * Intended for guarded CLI usage only.
 */
export function resetDatabase(): void {
	closeDb();

	const dbDir = path.dirname(DB_PATH);
	fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });

	try {
		if (fs.existsSync(DB_PATH)) {
			fs.unlinkSync(DB_PATH);
			logger.warn({ path: DB_PATH }, "database file removed by resetDatabase()");
		}
	} catch (err) {
		logger.error(
			{ path: DB_PATH, error: String(err) },
			"failed to remove database file during reset",
		);
		throw err;
	}

	db = new Database(DB_PATH);
	try {
		fs.chmodSync(DB_PATH, 0o600);
	} catch {
		logger.warn({ path: DB_PATH }, "could not set database file permissions to 0600 after reset");
	}

	db.pragma("journal_mode = WAL");
	initializeSchema(db);

	logger.info({ path: DB_PATH }, "database reset and reinitialized");
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
 * Initialize database schema (single version, no migrations).
 */
function initializeSchema(database: Database.Database): void {
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
			media_file_path TEXT,
			media_file_id TEXT,
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

		-- TOTP sessions (per-user verification "remember me")
		CREATE TABLE IF NOT EXISTS totp_sessions (
			local_user_id TEXT PRIMARY KEY,
			verified_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_totp_sessions_expires ON totp_sessions(expires_at);

		-- Pending admin claims (first-time setup flow)
		CREATE TABLE IF NOT EXISTS pending_admin_claims (
			code TEXT PRIMARY KEY,
			chat_id INTEGER NOT NULL,
			user_id INTEGER,
			username TEXT,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_pending_admin_claims_chat ON pending_admin_claims(chat_id);
		CREATE INDEX IF NOT EXISTS idx_pending_admin_claims_expires ON pending_admin_claims(expires_at);

		-- Pending TOTP messages (saved while awaiting auth gate verification)
		CREATE TABLE IF NOT EXISTS pending_totp_messages (
			chat_id INTEGER PRIMARY KEY,
			message_id TEXT NOT NULL,
			body TEXT NOT NULL,
			media_path TEXT,
			media_type TEXT,
			mime_type TEXT,
			username TEXT,
			sender_id INTEGER,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_pending_totp_messages_expires ON pending_totp_messages(expires_at);

		-- Banned chats (blocked from using the bot entirely)
		CREATE TABLE IF NOT EXISTS banned_chats (
			chat_id INTEGER PRIMARY KEY,
			banned_at INTEGER NOT NULL,
			banned_by TEXT NOT NULL,
			reason TEXT
		);

		-- Bot outbound messages (for tracking reactions)
		CREATE TABLE IF NOT EXISTS bot_messages (
			chat_id INTEGER NOT NULL,
			message_id INTEGER NOT NULL,
			sent_at INTEGER NOT NULL,
			PRIMARY KEY (chat_id, message_id)
		);
		CREATE INDEX IF NOT EXISTS idx_bot_messages_chat ON bot_messages(chat_id, sent_at DESC);

		-- Message reactions (emoji reactions on bot messages)
		CREATE TABLE IF NOT EXISTS message_reactions (
			chat_id INTEGER NOT NULL,
			message_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			emoji TEXT NOT NULL,
			reacted_at INTEGER NOT NULL,
			PRIMARY KEY (chat_id, message_id, user_id, emoji)
		);
		CREATE INDEX IF NOT EXISTS idx_message_reactions_chat ON message_reactions(chat_id, message_id);

		-- Attachment refs (proxy-intercepted attachments for delivery)
		CREATE TABLE IF NOT EXISTS attachment_refs (
			ref TEXT PRIMARY KEY,
			actor_user_id TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			filepath TEXT NOT NULL,
			filename TEXT NOT NULL,
			mime_type TEXT,
			size INTEGER,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_attachment_refs_expires ON attachment_refs(expires_at);
		CREATE INDEX IF NOT EXISTS idx_attachment_refs_actor ON attachment_refs(actor_user_id);
	`);

	ensureApprovalsColumns(database);

	logger.info("database schema initialized");
}

function ensureApprovalsColumns(database: Database.Database): void {
	const requiredColumns = new Set([
		"nonce",
		"request_id",
		"chat_id",
		"created_at",
		"expires_at",
		"tier",
		"body",
		"media_path",
		"media_file_path",
		"media_file_id",
		"media_type",
		"username",
		"from_user",
		"to_user",
		"message_id",
		"observer_classification",
		"observer_confidence",
		"observer_reason",
	]);

	const rows = database.prepare("PRAGMA table_info(approvals)").all() as Array<{ name: string }>;
	const hasAll =
		rows.length > 0 &&
		rows.every((r) => requiredColumns.has(r.name)) &&
		requiredColumns.size === rows.length;

	if (rows.length > 0 && hasAll) {
		return;
	}

	if (rows.length > 0 && !hasAll) {
		logger.warn("approvals table schema mismatch detected; dropping and recreating");
		database.exec("DROP TABLE IF EXISTS approvals");
	}

	database.exec(`
		CREATE TABLE IF NOT EXISTS approvals (
			nonce TEXT PRIMARY KEY,
			request_id TEXT NOT NULL,
			chat_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			tier TEXT NOT NULL,
			body TEXT NOT NULL,
			media_path TEXT,
			media_file_path TEXT,
			media_file_id TEXT,
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

/**
 * Clean up expired entries from all tables.
 * Call periodically to prevent database bloat.
 */
export function cleanupExpired(): {
	approvals: number;
	linkCodes: number;
	rateLimits: number;
	totpSessions: number;
	adminClaims: number;
	pendingTotpMessages: number;
	botMessages: number;
	messageReactions: number;
	attachmentRefs: number;
} {
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

	// Clean expired TOTP sessions
	const totpSessionsResult = database
		.prepare("DELETE FROM totp_sessions WHERE expires_at < ?")
		.run(now);

	// Clean expired admin claims
	const adminClaimsResult = database
		.prepare("DELETE FROM pending_admin_claims WHERE expires_at < ?")
		.run(now);

	// Clean expired pending TOTP messages
	const pendingTotpResult = database
		.prepare("DELETE FROM pending_totp_messages WHERE expires_at < ?")
		.run(now);

	// Clean old bot messages (older than 24 hours)
	const oneDayAgo = now - 24 * 3600 * 1000;
	const botMessagesResult = database
		.prepare("DELETE FROM bot_messages WHERE sent_at < ?")
		.run(oneDayAgo);

	// Clean reactions for deleted bot messages (cascade via subquery)
	const reactionsResult = database
		.prepare(
			`DELETE FROM message_reactions
			 WHERE (chat_id, message_id) NOT IN (
				 SELECT chat_id, message_id FROM bot_messages
			 )`,
		)
		.run();

	// Clean expired attachment refs
	const attachmentRefsResult = database
		.prepare("DELETE FROM attachment_refs WHERE expires_at < ?")
		.run(now);

	const result = {
		approvals: approvalsResult.changes,
		linkCodes: linkCodesResult.changes,
		rateLimits: rateLimitsResult.changes,
		totpSessions: totpSessionsResult.changes,
		adminClaims: adminClaimsResult.changes,
		pendingTotpMessages: pendingTotpResult.changes,
		botMessages: botMessagesResult.changes,
		messageReactions: reactionsResult.changes,
		attachmentRefs: attachmentRefsResult.changes,
	};

	logger.info(result, "expired entries cleaned up");

	return result;
}
