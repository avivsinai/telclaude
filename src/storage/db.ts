/**
 * SQLite storage layer for telclaude.
 *
 * One-shot schema plus small additive/data migrations for existing local DBs.
 */

import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { getChildLogger } from "../logging.js";
import { CONFIG_DIR } from "../utils.js";

const logger = getChildLogger({ module: "storage" });

let db: Database.Database | null = null;
let dbPath: string | null = null;

function resolveDbPath(): string {
	const dataDir = process.env.TELCLAUDE_DATA_DIR;
	if (dataDir && path.isAbsolute(dataDir) && !dataDir.startsWith("~")) {
		return path.join(dataDir, "telclaude.db");
	}
	return path.join(CONFIG_DIR, "telclaude.db");
}

/**
 * Get or create the database connection.
 * Uses WAL mode for better concurrency.
 *
 * SECURITY: Sets restrictive file permissions on database and config directory.
 */
export function getDb(): Database.Database {
	const targetPath = resolveDbPath();
	if (db && dbPath === targetPath) return db;
	if (db) closeDb();

	const dbDir = path.dirname(targetPath);

	// Ensure directory exists with secure permissions (owner only)
	fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });

	// Harden existing directory permissions if it already existed
	try {
		fs.chmodSync(dbDir, 0o700);
	} catch {
		logger.warn({ path: dbDir }, "could not set directory permissions to 0700");
	}

	db = new Database(targetPath);
	dbPath = targetPath;

	// SECURITY: Set database file to owner read/write only
	try {
		fs.chmodSync(targetPath, 0o600);
	} catch {
		logger.warn({ path: targetPath }, "could not set database file permissions to 0600");
	}

	// Enable WAL mode for better concurrency
	db.pragma("journal_mode = WAL");

	// Create schema (single-version, no migrations)
	initializeSchema(db);

	logger.info({ path: targetPath }, "database initialized");

	return db;
}

/**
 * Dangerously reset the database file and recreate schema.
 * Intended for guarded CLI usage only.
 */
export function resetDatabase(): void {
	closeDb();

	const targetPath = resolveDbPath();
	const dbDir = path.dirname(targetPath);
	fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });

	try {
		if (fs.existsSync(targetPath)) {
			fs.unlinkSync(targetPath);
			logger.warn({ path: targetPath }, "database file removed by resetDatabase()");
		}
	} catch (err) {
		logger.error(
			{ path: targetPath, error: String(err) },
			"failed to remove database file during reset",
		);
		throw err;
	}

	db = new Database(targetPath);
	dbPath = targetPath;
	try {
		fs.chmodSync(targetPath, 0o600);
	} catch {
		logger.warn(
			{ path: targetPath },
			"could not set database file permissions to 0600 after reset",
		);
	}

	db.pragma("journal_mode = WAL");
	initializeSchema(db);

	logger.info({ path: targetPath }, "database reset and reinitialized");
}

/**
 * Close the database connection.
 */
export function closeDb(): void {
	if (db) {
		db.close();
		db = null;
		dbPath = null;
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
			sender_id INTEGER,
			message_thread_id INTEGER,
			turn_conversation_ref TEXT,
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

		-- Active private operator profile per Telegram chat.
		CREATE TABLE IF NOT EXISTS chat_profiles (
			chat_id INTEGER PRIMARY KEY,
			active_profile_id TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);

		-- Home delivery targets for conversational cron
		CREATE TABLE IF NOT EXISTS home_targets (
			owner_id TEXT PRIMARY KEY,
			chat_id INTEGER NOT NULL,
			thread_id INTEGER,
			updated_at INTEGER NOT NULL
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
			message_thread_id INTEGER,
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

		-- Relay-local raw attachment quarantine. Paths and owner tokens never leave
		-- this private table; Hermes receives only the AttachmentRef projection.
		CREATE TABLE IF NOT EXISTS attachment_quarantine (
			quarantine_id TEXT PRIMARY KEY,
			owner_scope_hash TEXT NOT NULL,
			conversation_token TEXT NOT NULL,
			supplied_media_type TEXT NOT NULL,
			sniffed_media_type TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			content_hash TEXT NOT NULL,
			trust_label TEXT NOT NULL,
			access_class TEXT NOT NULL CHECK(access_class IN ('outbound-delivery','media-processor')),
			state TEXT NOT NULL CHECK(state IN ('pending','clean','blocked','expired','deleted')),
			byte_path TEXT,
			created_at_ms INTEGER NOT NULL,
			updated_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL,
			lease_id TEXT,
			lease_expires_at_ms INTEGER,
			deleted_at_ms INTEGER,
			deletion_reason TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_attachment_quarantine_expiry
			ON attachment_quarantine(state, expires_at_ms);
		CREATE INDEX IF NOT EXISTS idx_attachment_quarantine_owner
			ON attachment_quarantine(owner_scope_hash, created_at_ms DESC);

		-- Content-free terminal deletion evidence. The source quarantine id is
		-- represented only by a SHA-256 digest so receipts are safe to retain.
		CREATE TABLE IF NOT EXISTS attachment_quarantine_deletion_receipts (
			receipt_id TEXT PRIMARY KEY,
			quarantine_id_hash TEXT NOT NULL UNIQUE,
			content_hash TEXT NOT NULL,
			owner_scope_hash TEXT NOT NULL,
			reason TEXT NOT NULL,
			received_at_ms INTEGER NOT NULL,
			deleted_at_ms INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_attachment_quarantine_receipts_deleted
			ON attachment_quarantine_deletion_receipts(deleted_at_ms);

		-- Memory entries (social memory with provenance tracking)
		CREATE TABLE IF NOT EXISTS memory_entries (
			id TEXT PRIMARY KEY,
			category TEXT NOT NULL,
			content TEXT NOT NULL,
			metadata TEXT,
			source TEXT NOT NULL,
			trust TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			promoted_at INTEGER,
			promoted_by TEXT,
			posted_at INTEGER,
			chat_id TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_memory_entries_category ON memory_entries(category);
		CREATE INDEX IF NOT EXISTS idx_memory_entries_source ON memory_entries(source);
		CREATE INDEX IF NOT EXISTS idx_memory_entries_trust ON memory_entries(trust);
		CREATE INDEX IF NOT EXISTS idx_memory_entries_created ON memory_entries(created_at);
		CREATE INDEX IF NOT EXISTS idx_memory_entries_posted ON memory_entries(posted_at);
		CREATE INDEX IF NOT EXISTS idx_memory_entries_chat ON memory_entries(chat_id);

		-- Episodic memory archive (relay-owned conversation history)
		CREATE TABLE IF NOT EXISTS memory_episodes (
			id TEXT PRIMARY KEY,
			source TEXT NOT NULL,
			scope_key TEXT NOT NULL,
			chat_id TEXT,
			session_key TEXT,
			session_id TEXT,
			user_text TEXT NOT NULL,
			assistant_text TEXT NOT NULL,
			summary TEXT NOT NULL,
			metadata TEXT,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_memory_episodes_scope_created
			ON memory_episodes(scope_key, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_memory_episodes_source_created
			ON memory_episodes(source, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_memory_episodes_chat_created
			ON memory_episodes(chat_id, created_at DESC);

		-- Hermes relay-owned conversation authority for no-fork wrapper routing.
		CREATE TABLE IF NOT EXISTS hermes_relay_conversations (
			token TEXT PRIMARY KEY,
			channel TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			thread_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			domain TEXT NOT NULL CHECK(domain IN ('private','household','public','public-social','specialist')),
			mcp_domain TEXT NOT NULL CHECK(mcp_domain IN ('private','social','household','public','specialist')),
			edge_domain TEXT CHECK(edge_domain IN ('private','household','public','public-social')),
			routing_session_id TEXT NOT NULL,
			route_key TEXT NOT NULL,
			authorization_state TEXT NOT NULL CHECK(authorization_state IN ('authorized','approval_required','denied','revoked')),
			human_pairing_provenance INTEGER NOT NULL DEFAULT 0 CHECK(human_pairing_provenance IN (0,1)),
			authorization_scopes_json TEXT NOT NULL,
			members_json TEXT NOT NULL,
			thread_message_ids_json TEXT NOT NULL DEFAULT '[]',
			inbound_cursor TEXT,
			audit_ids_json TEXT NOT NULL DEFAULT '[]',
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER,
			revoked_at_ms INTEGER,
			revoke_reason TEXT,
			updated_at_ms INTEGER NOT NULL
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_hermes_relay_conversation_identity
			ON hermes_relay_conversations(channel, conversation_id);
		CREATE INDEX IF NOT EXISTS idx_hermes_relay_conversation_route
			ON hermes_relay_conversations(route_key);
		CREATE INDEX IF NOT EXISTS idx_hermes_relay_conversation_expiry
			ON hermes_relay_conversations(expires_at_ms);
		CREATE INDEX IF NOT EXISTS idx_hermes_relay_conversation_domain_state
			ON hermes_relay_conversations(domain, authorization_state);

		-- Relay-minted inbound turn refs. These bind Hermes outbound work to a
		-- trusted inbound transport event without accepting model-supplied turn ids.
		CREATE TABLE IF NOT EXISTS hermes_relay_conversation_turns (
			ref TEXT PRIMARY KEY,
			conversation_token TEXT NOT NULL,
			channel TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			thread_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			domain TEXT NOT NULL CHECK(domain IN ('private','household','public','public-social','specialist')),
			mcp_domain TEXT NOT NULL CHECK(mcp_domain IN ('private','social','household','public','specialist')),
			inbound_message_id TEXT NOT NULL,
			sender_actor_id TEXT NOT NULL,
			sender_principal_id TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER,
			revoked_at_ms INTEGER,
			revoke_reason TEXT,
			FOREIGN KEY(conversation_token) REFERENCES hermes_relay_conversations(token)
		);
		CREATE INDEX IF NOT EXISTS idx_hermes_relay_conversation_turn_conversation
			ON hermes_relay_conversation_turns(conversation_token, created_at_ms DESC);
		CREATE INDEX IF NOT EXISTS idx_hermes_relay_conversation_turn_expiry
			ON hermes_relay_conversation_turns(expires_at_ms);

		-- Cron jobs (local scheduler state)
		CREATE TABLE IF NOT EXISTS cron_jobs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			running INTEGER NOT NULL DEFAULT 0,
			schedule_kind TEXT NOT NULL,
			schedule_at INTEGER,
			schedule_every_ms INTEGER,
			schedule_cron TEXT,
			action_kind TEXT NOT NULL,
			action_service_id TEXT,
			action_prompt TEXT,
			action_allowed_skills_json TEXT,
			action_preprocess_json TEXT,
			action_reminder_id TEXT,
			action_reminder_revision INTEGER,
			owner_id TEXT,
			delivery_target_kind TEXT NOT NULL DEFAULT 'origin',
			delivery_chat_id INTEGER,
			delivery_thread_id INTEGER,
			next_run_at INTEGER,
			last_run_at INTEGER,
			last_status TEXT,
			last_error TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_cron_jobs_next_run ON cron_jobs(enabled, next_run_at);
		CREATE INDEX IF NOT EXISTS idx_cron_jobs_running ON cron_jobs(running, next_run_at);

		-- Cron run history (operational visibility)
		CREATE TABLE IF NOT EXISTS cron_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id TEXT NOT NULL,
			started_at INTEGER NOT NULL,
			finished_at INTEGER,
			status TEXT NOT NULL,
			message TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_cron_runs_job_started ON cron_runs(job_id, started_at DESC);

		-- Household reminder revisions. Destination addresses are never stored here;
		-- delivery resolves the current server-owned household binding at fire time.
		CREATE TABLE IF NOT EXISTS household_reminders (
			id TEXT NOT NULL,
			revision INTEGER NOT NULL CHECK(revision > 0),
			actor_id TEXT NOT NULL,
			subject_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			sender_principal_hash TEXT NOT NULL,
			recipient_principal_hash TEXT NOT NULL,
			binding_fingerprint TEXT NOT NULL,
			consent_hash TEXT NOT NULL,
			text TEXT NOT NULL,
			label TEXT,
			locale TEXT NOT NULL CHECK(locale = 'he-IL'),
			source_kind TEXT NOT NULL CHECK(source_kind IN ('parent','clalit-appointment')),
			source_observation_hash TEXT,
			time_zone TEXT NOT NULL CHECK(time_zone = 'Asia/Jerusalem'),
			local_date_time TEXT NOT NULL,
			resolved_at_ms INTEGER NOT NULL,
			resolved_at TEXT NOT NULL,
			offset_minutes INTEGER NOT NULL,
			content_hash TEXT NOT NULL,
			schedule_hash TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('pending_confirmation','scheduled','paused_confirmation','superseded','cancelled','revoked','completed','failed_terminal')),
			confirmed_at_ms INTEGER,
			created_at_ms INTEGER NOT NULL,
			updated_at_ms INTEGER NOT NULL,
			PRIMARY KEY (id, revision)
		);
		CREATE INDEX IF NOT EXISTS idx_household_reminders_authority
			ON household_reminders(actor_id, subject_user_id, profile_id, id, revision DESC);
		CREATE INDEX IF NOT EXISTS idx_household_reminders_due
			ON household_reminders(status, resolved_at_ms);

		CREATE TABLE IF NOT EXISTS household_reminder_proposals (
			ref TEXT PRIMARY KEY,
			action TEXT NOT NULL CHECK(action IN ('create','update','cancel')),
			reminder_id TEXT NOT NULL,
			base_revision INTEGER NOT NULL CHECK(base_revision > 0),
			proposed_revision INTEGER NOT NULL CHECK(proposed_revision > 0),
			actor_id TEXT NOT NULL,
			subject_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			sender_principal_hash TEXT NOT NULL,
			recipient_principal_hash TEXT NOT NULL,
			binding_fingerprint TEXT NOT NULL,
			consent_hash TEXT NOT NULL,
			proposal_hash TEXT NOT NULL,
			proposed_payload_json TEXT,
			status TEXT NOT NULL CHECK(status IN ('pending','confirmed','rejected','expired')),
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL,
			resolved_at_ms INTEGER
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_household_reminder_proposals_conversation_pending
			ON household_reminder_proposals(conversation_id) WHERE status = 'pending';
		CREATE INDEX IF NOT EXISTS idx_household_reminder_proposals_authority
			ON household_reminder_proposals(actor_id, subject_user_id, profile_id, created_at_ms DESC);

		-- A reminder proposal and a media action confirmation both consume the
		-- same small choice vocabulary. One durable conversation-keyed lease keeps
		-- them mutually exclusive even when their creation attempts race.
		CREATE TABLE IF NOT EXISTS household_interactive_choice_leases (
			conversation_id TEXT PRIMARY KEY,
			actor_id TEXT NOT NULL,
			subject_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			owner_kind TEXT NOT NULL CHECK(owner_kind IN ('reminder','media_confirmation')),
			owner_ref TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms)
		);
		CREATE INDEX IF NOT EXISTS idx_household_interactive_choice_lease_expiry
			ON household_interactive_choice_leases(expires_at_ms);
		INSERT OR IGNORE INTO household_interactive_choice_leases (
			actor_id, subject_user_id, profile_id, binding_id, conversation_id,
			owner_kind, owner_ref, created_at_ms, expires_at_ms
		)
		SELECT actor_id, subject_user_id, profile_id, binding_id, conversation_id,
			'reminder', ref, created_at_ms, expires_at_ms
		FROM household_reminder_proposals WHERE status = 'pending';

		-- Media-derived text and canonical action parameters remain encrypted.
		-- The control table carries only content-free owner bindings and digests.
		CREATE TABLE IF NOT EXISTS household_media_turn_derivations (
			turn_ref TEXT PRIMARY KEY,
			actor_id TEXT NOT NULL,
			subject_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			sender_principal_hash TEXT NOT NULL,
			owner_scope_hash TEXT NOT NULL,
			source_digest TEXT NOT NULL,
			derived_digest TEXT NOT NULL,
			media_kinds_json TEXT NOT NULL,
			provenance_json TEXT NOT NULL,
			action_bearing INTEGER NOT NULL CHECK(action_bearing IN (0,1)),
			low_confidence INTEGER NOT NULL CHECK(low_confidence IN (0,1)),
			kdf_salt TEXT NOT NULL,
			iv TEXT NOT NULL,
			auth_tag TEXT NOT NULL,
			ciphertext TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms)
		);
		CREATE INDEX IF NOT EXISTS idx_household_media_turn_derivation_expiry
			ON household_media_turn_derivations(expires_at_ms);

		CREATE TABLE IF NOT EXISTS household_media_action_confirmations (
			confirmation_id TEXT PRIMARY KEY,
			jti_hash TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL CHECK(status IN ('pending','confirmed','rejected','expired','revoked')),
			actor_id TEXT NOT NULL,
			subject_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			sender_principal_hash TEXT NOT NULL,
			original_turn_ref TEXT NOT NULL,
			owner_scope_hash TEXT NOT NULL,
			source_digest TEXT NOT NULL,
			derived_digest TEXT NOT NULL,
			action_digest TEXT NOT NULL,
			action_tool_name TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL,
			expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms),
			resolved_at_ms INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_household_media_action_confirmation_pending
			ON household_media_action_confirmations(conversation_id, status, expires_at_ms);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_household_media_action_confirmation_turn_action_pending
			ON household_media_action_confirmations(original_turn_ref, action_digest)
			WHERE status = 'pending';

		CREATE TABLE IF NOT EXISTS household_media_action_confirmation_content (
			confirmation_id TEXT PRIMARY KEY,
			kdf_salt TEXT NOT NULL,
			iv TEXT NOT NULL,
			auth_tag TEXT NOT NULL,
			ciphertext TEXT NOT NULL
		);

		CREATE TRIGGER IF NOT EXISTS expire_household_media_confirmation_with_lease
		AFTER DELETE ON household_interactive_choice_leases
		WHEN OLD.owner_kind = 'media_confirmation'
		BEGIN
			DELETE FROM household_media_action_confirmation_content
			 WHERE confirmation_id = OLD.owner_ref;
			UPDATE household_media_action_confirmations
			 SET status = 'expired', resolved_at_ms = expires_at_ms
			 WHERE confirmation_id = OLD.owner_ref AND status = 'pending';
		END;

		CREATE TABLE IF NOT EXISTS household_reminder_interception_receipts (
			receipt_id TEXT PRIMARY KEY,
			event_id_hash TEXT NOT NULL,
			message_id_hash TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			subject_user_id TEXT NOT NULL,
			profile_id TEXT NOT NULL,
			binding_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			proposal_ref TEXT NOT NULL,
			proposal_hash TEXT NOT NULL,
			template_id TEXT NOT NULL CHECK(template_id IN ('confirmed','rejected','unchanged','proposal_expired','failed')),
			status TEXT NOT NULL CHECK(status IN ('pending_ack','acked')),
			created_at_ms INTEGER NOT NULL,
			updated_at_ms INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_household_reminder_interception_receipts_status
			ON household_reminder_interception_receipts(status, updated_at_ms);

		CREATE TABLE IF NOT EXISTS household_reminder_fires (
			fire_id TEXT PRIMARY KEY,
			reminder_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			scheduled_for_ms INTEGER NOT NULL,
			state TEXT NOT NULL CHECK(state IN ('claimed','prepared','dispatched','delivered','retryable_failed','dead_lettered','cancelled')),
			attempt_count INTEGER NOT NULL CHECK(attempt_count > 0),
			lease_expires_at_ms INTEGER,
			outbound_ref TEXT,
			edge_prepared_hash TEXT,
			idempotency_key TEXT,
			whatsapp_message_id TEXT,
			receipt_status TEXT,
			platform_message_id_hash TEXT,
			failure_class TEXT,
			created_at_ms INTEGER NOT NULL,
			updated_at_ms INTEGER NOT NULL,
			UNIQUE(reminder_id, revision, scheduled_for_ms),
			FOREIGN KEY(reminder_id, revision) REFERENCES household_reminders(id, revision)
		);
		CREATE INDEX IF NOT EXISTS idx_household_reminder_fires_state
			ON household_reminder_fires(state, updated_at_ms);

		-- Plan approvals (two-phase execution preview for FULL_ACCESS)
		CREATE TABLE IF NOT EXISTS plan_approvals (
			nonce TEXT PRIMARY KEY,
			request_id TEXT NOT NULL,
			chat_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			tier TEXT NOT NULL,
			original_body TEXT NOT NULL,
			plan_text TEXT NOT NULL,
			session_key TEXT NOT NULL,
			session_id TEXT NOT NULL,
			media_path TEXT,
			media_file_id TEXT,
			media_type TEXT,
			username TEXT,
			from_user TEXT NOT NULL,
			to_user TEXT NOT NULL,
			message_id TEXT NOT NULL,
			sender_id INTEGER,
			message_thread_id INTEGER,
			turn_conversation_ref TEXT,
			observer_classification TEXT NOT NULL,
			observer_confidence REAL NOT NULL,
			observer_reason TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_plan_approvals_chat_id ON plan_approvals(chat_id);
		CREATE INDEX IF NOT EXISTS idx_plan_approvals_expires_at ON plan_approvals(expires_at);

		-- Background jobs (Workstream W12 — long-running agent/operator-spawned tasks)
		CREATE TABLE IF NOT EXISTS background_jobs (
			id TEXT PRIMARY KEY,
			short_id TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			chat_id INTEGER,
			thread_id INTEGER,
			tier TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			status TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			result_json TEXT,
			error TEXT,
			created_at INTEGER NOT NULL,
			started_at INTEGER,
			completed_at INTEGER,
			cancelled_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON background_jobs(status, created_at);
		CREATE INDEX IF NOT EXISTS idx_background_jobs_chat ON background_jobs(chat_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_background_jobs_short ON background_jobs(short_id);

		-- Relay-owned Telegram cards for typed control-plane UI
		CREATE TABLE IF NOT EXISTS card_instances (
			card_id TEXT PRIMARY KEY,
			short_id TEXT NOT NULL UNIQUE,
			kind TEXT NOT NULL,
			version INTEGER NOT NULL,
			chat_id INTEGER NOT NULL,
			message_id INTEGER NOT NULL,
			thread_id INTEGER,
			actor_scope TEXT NOT NULL,
			entity_ref TEXT NOT NULL,
			revision INTEGER NOT NULL,
			state TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			status TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_card_instances_short_id ON card_instances(short_id);
		CREATE INDEX IF NOT EXISTS idx_card_instances_chat_message ON card_instances(chat_id, message_id);
		CREATE INDEX IF NOT EXISTS idx_card_instances_entity ON card_instances(kind, chat_id, entity_ref, status);
		CREATE INDEX IF NOT EXISTS idx_card_instances_expires_at ON card_instances(status, expires_at);

		-- DM pairing codes (Workstream W4). Stores sha256(code) + signature only;
		-- the plaintext code lives in the user's Telegram message and nowhere else.
		CREATE TABLE IF NOT EXISTS pairing_requests (
			code_hash TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			chat_id INTEGER NOT NULL,
			username TEXT,
			tier TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			approved_at INTEGER,
			approved_by TEXT,
			signature TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_pairing_requests_user ON pairing_requests(user_id, status);
		CREATE INDEX IF NOT EXISTS idx_pairing_requests_expires ON pairing_requests(status, expires_at);

		-- Per-user failed-approval counter (feeds the 5-attempts-per-user lockout).
		CREATE TABLE IF NOT EXISTS pairing_failed_attempts (
			user_id INTEGER PRIMARY KEY,
			attempts INTEGER NOT NULL DEFAULT 0,
			last_attempt_at INTEGER NOT NULL
		);

		-- Active per-user lockouts (5 failures → 1h lockout).
		CREATE TABLE IF NOT EXISTS pairing_lockouts (
			user_id INTEGER PRIMARY KEY,
			locked_until INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_pairing_lockouts_until ON pairing_lockouts(locked_until);

		-- Durable approved (user, chat) pairs. Additive to telegram.allowedChats.
		CREATE TABLE IF NOT EXISTS paired_chats (
			chat_id INTEGER PRIMARY KEY,
			user_id INTEGER NOT NULL,
			tier TEXT NOT NULL,
			paired_at INTEGER NOT NULL,
			approved_by TEXT NOT NULL,
			username TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_paired_chats_user ON paired_chats(user_id);

		-- Graduated approval allowlist (Workstream W1).
		-- "once" is consumed on first lookup. "session" is scoped to session_key
		-- and allows concurrent sessions to coexist. "always" gets a rolling
		-- 30-day expiry refreshed on use.
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
			last_used_at INTEGER
		);
		-- Partial unique indexes: one row per (user, tool) for non-session scopes,
		-- and one per (user, tool, session) for session-scoped grants so that
		-- concurrent sessions do not overwrite each other's entries (Wave 2 review fix).
		CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_allowlist_singleton
			ON approval_allowlist(user_id, tool_key, scope)
			WHERE scope != 'session';
		CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_allowlist_session_scope
			ON approval_allowlist(user_id, tool_key, session_key)
			WHERE scope = 'session';
		CREATE INDEX IF NOT EXISTS idx_approval_allowlist_user
			ON approval_allowlist(user_id, tool_key);
		CREATE INDEX IF NOT EXISTS idx_approval_allowlist_session
			ON approval_allowlist(session_key);
		CREATE INDEX IF NOT EXISTS idx_approval_allowlist_expires
			ON approval_allowlist(expires_at);

		-- Per-chat model preference (W2 model picker)
		CREATE TABLE IF NOT EXISTS model_preferences (
			chat_id INTEGER PRIMARY KEY,
			provider_id TEXT NOT NULL,
			model_id TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);

		-- Curator triage inbox (review-only suggestions, no privileged mutation)
		CREATE TABLE IF NOT EXISTS curator_items (
			id TEXT PRIMARY KEY,
			short_id TEXT NOT NULL UNIQUE,
			fingerprint TEXT NOT NULL UNIQUE,
			kind TEXT NOT NULL,
			status TEXT NOT NULL,
			severity TEXT NOT NULL,
			source TEXT NOT NULL,
			title TEXT NOT NULL,
			summary TEXT NOT NULL,
			rationale TEXT,
			entity_ref TEXT NOT NULL,
			proposed_action_json TEXT NOT NULL,
			evidence_json TEXT NOT NULL,
			producer_kind TEXT NOT NULL,
			producer_id TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			expires_at INTEGER,
			decided_at INTEGER,
			decided_by TEXT,
			decision_reason TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_curator_items_status ON curator_items(status, updated_at DESC);
		CREATE INDEX IF NOT EXISTS idx_curator_items_kind ON curator_items(kind, status);
		CREATE INDEX IF NOT EXISTS idx_curator_items_source ON curator_items(source, status);

		-- Skill invocation telemetry (metadata only; no args, outputs, or skill bodies)
		CREATE TABLE IF NOT EXISTS skill_invocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_key TEXT NOT NULL,
			turn_index INTEGER,
			skill_name TEXT NOT NULL,
			decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
			deny_reason TEXT,
			source TEXT NOT NULL CHECK(source IN ('telegram', 'social')),
			service_id TEXT,
			duration_ms INTEGER,
			result_status TEXT CHECK(result_status IN ('success', 'error', 'unknown') OR result_status IS NULL),
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_skill_invocations_session_created
			ON skill_invocations(session_key, created_at);
		CREATE INDEX IF NOT EXISTS idx_skill_invocations_skill_source_created
			ON skill_invocations(skill_name, source, created_at);

		-- Signed inbound webhooks (definitions only; HMAC secrets live in vault/secrets storage)
		CREATE TABLE IF NOT EXISTS webhooks (
			slug TEXT PRIMARY KEY,
			enabled INTEGER NOT NULL DEFAULT 0,
			target_cron_job_id TEXT NOT NULL,
			vault_secret_id TEXT NOT NULL,
			allowed_cidrs_json TEXT,
			rate_limit_per_hour INTEGER NOT NULL DEFAULT 60,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			last_hit_at INTEGER,
			hit_count INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_webhooks_target_cron_job
			ON webhooks(target_cron_job_id);

		-- Webhook hit audit trail. Body is represented only by SHA-256.
		CREATE TABLE IF NOT EXISTS webhook_hits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			slug TEXT NOT NULL,
			source_ip TEXT,
			signature_valid INTEGER NOT NULL,
			timestamp_delta_seconds INTEGER,
			action_taken TEXT NOT NULL,
			target_cron_job_id TEXT,
			background_job_id TEXT,
			failure_reason TEXT,
			body_sha256 TEXT,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_webhook_hits_slug_created
			ON webhook_hits(slug, created_at DESC);

		-- Replay guard for accepted signed webhook deliveries. The signature digest
		-- is SHA-256 over the signature header plus body hash; raw body is never stored.
		CREATE TABLE IF NOT EXISTS webhook_deliveries (
			slug TEXT NOT NULL,
			signature_digest TEXT NOT NULL,
			body_sha256 TEXT NOT NULL,
			background_job_id TEXT,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (slug, signature_digest)
		);
		CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created
			ON webhook_deliveries(created_at);
	`);

	// Wave 2 review fix: migrate approval_allowlist from v1 (inline
	// UNIQUE(user_id, tool_key, scope)) to v2 (partial unique indexes that
	// let concurrent sessions coexist). The CREATE TABLE IF NOT EXISTS above
	// is a no-op on existing v1 tables; this migration drops the v1 shape so
	// the v2 shape can be recreated on the next init pass.
	migrateApprovalAllowlistV2(database);

	ensureColumn(
		database,
		"cron_jobs",
		"action_prompt",
		"ALTER TABLE cron_jobs ADD COLUMN action_prompt TEXT",
	);
	ensureColumn(
		database,
		"cron_jobs",
		"action_allowed_skills_json",
		"ALTER TABLE cron_jobs ADD COLUMN action_allowed_skills_json TEXT",
	);
	ensureColumn(
		database,
		"cron_jobs",
		"action_preprocess_json",
		"ALTER TABLE cron_jobs ADD COLUMN action_preprocess_json TEXT",
	);
	ensureColumn(
		database,
		"cron_jobs",
		"action_reminder_id",
		"ALTER TABLE cron_jobs ADD COLUMN action_reminder_id TEXT",
	);
	ensureColumn(
		database,
		"cron_jobs",
		"action_reminder_revision",
		"ALTER TABLE cron_jobs ADD COLUMN action_reminder_revision INTEGER",
	);
	ensureColumn(database, "cron_jobs", "owner_id", "ALTER TABLE cron_jobs ADD COLUMN owner_id TEXT");
	ensureColumn(
		database,
		"cron_jobs",
		"delivery_target_kind",
		"ALTER TABLE cron_jobs ADD COLUMN delivery_target_kind TEXT NOT NULL DEFAULT 'origin'",
	);
	ensureColumn(
		database,
		"cron_jobs",
		"delivery_chat_id",
		"ALTER TABLE cron_jobs ADD COLUMN delivery_chat_id INTEGER",
	);
	ensureColumn(
		database,
		"cron_jobs",
		"delivery_thread_id",
		"ALTER TABLE cron_jobs ADD COLUMN delivery_thread_id INTEGER",
	);
	ensureColumn(
		database,
		"hermes_relay_conversations",
		"human_pairing_provenance",
		"ALTER TABLE hermes_relay_conversations ADD COLUMN human_pairing_provenance INTEGER NOT NULL DEFAULT 0 CHECK(human_pairing_provenance IN (0,1))",
	);
	ensureApprovalsColumns(database);
	ensureColumn(
		database,
		"pending_totp_messages",
		"message_thread_id",
		"ALTER TABLE pending_totp_messages ADD COLUMN message_thread_id INTEGER",
	);
	ensureColumn(
		database,
		"plan_approvals",
		"sender_id",
		"ALTER TABLE plan_approvals ADD COLUMN sender_id INTEGER",
	);
	ensureColumn(
		database,
		"plan_approvals",
		"message_thread_id",
		"ALTER TABLE plan_approvals ADD COLUMN message_thread_id INTEGER",
	);
	ensureColumn(
		database,
		"plan_approvals",
		"turn_conversation_ref",
		"ALTER TABLE plan_approvals ADD COLUMN turn_conversation_ref TEXT",
	);
	ensureHouseholdReminderColumns(database);
	ensureMemoryEntriesColumns(database);
	migrateDefaultTelegramMemorySource(database);
	// chat_id index is created in ensureMemoryEntriesColumns after the column is ensured to exist

	logger.info("database schema initialized");
}

function ensureHouseholdReminderColumns(database: Database.Database): void {
	const legacyConsentHash = `sha256:${"0".repeat(64)}`;
	ensureColumn(
		database,
		"household_reminders",
		"consent_hash",
		`ALTER TABLE household_reminders ADD COLUMN consent_hash TEXT NOT NULL DEFAULT '${legacyConsentHash}'`,
	);
	ensureColumn(
		database,
		"household_reminder_proposals",
		"consent_hash",
		`ALTER TABLE household_reminder_proposals ADD COLUMN consent_hash TEXT NOT NULL DEFAULT '${legacyConsentHash}'`,
	);

	const nullableColumns = [
		["lease_expires_at_ms", "INTEGER"],
		["outbound_ref", "TEXT"],
		["edge_prepared_hash", "TEXT"],
		["idempotency_key", "TEXT"],
		["whatsapp_message_id", "TEXT"],
		["receipt_status", "TEXT"],
		["platform_message_id_hash", "TEXT"],
		["failure_class", "TEXT"],
	] as const;
	for (const [column, type] of nullableColumns) {
		ensureColumn(
			database,
			"household_reminder_fires",
			column,
			`ALTER TABLE household_reminder_fires ADD COLUMN ${column} ${type}`,
		);
	}

	database.exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS idx_household_reminder_fires_idempotency
			ON household_reminder_fires(idempotency_key) WHERE idempotency_key IS NOT NULL
	`);
}

/**
 * Wave 2 review fix (Bug #2): migrate approval_allowlist from the original
 * Wave-2 schema (inline `UNIQUE(user_id, tool_key, scope)`) to partial
 * unique indexes that allow concurrent session-scoped grants to coexist.
 *
 * Detects the old constraint by sniffing `sqlite_master.sql`; drops the
 * table so the `CREATE TABLE IF NOT EXISTS` at init time can recreate it
 * with the new shape. Runs once per process; subsequent startups on the
 * new schema are no-ops.
 */
function migrateApprovalAllowlistV2(database: Database.Database): void {
	const row = database
		.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'approval_allowlist'")
		.get() as { sql?: string } | undefined;
	if (!row?.sql) {
		return;
	}
	// v1 inlined the UNIQUE constraint; v2 moves it to partial indexes.
	const hasV1Constraint = /UNIQUE\s*\(\s*user_id\s*,\s*tool_key\s*,\s*scope\s*\)/i.test(row.sql);
	if (hasV1Constraint) {
		logger.warn(
			"migrating approval_allowlist: dropping v1 table (incorrect UNIQUE constraint) — any existing grants will need to be re-issued",
		);
		database.exec("DROP TABLE approval_allowlist");
		// Recreate with the new shape from initializeSchema's definition.
		database.exec(`
			CREATE TABLE approval_allowlist (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id TEXT NOT NULL,
				tier TEXT NOT NULL,
				tool_key TEXT NOT NULL,
				scope TEXT NOT NULL,
				session_key TEXT,
				chat_id INTEGER NOT NULL,
				granted_at INTEGER NOT NULL,
				expires_at INTEGER,
				last_used_at INTEGER
			);
			CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_allowlist_singleton
				ON approval_allowlist(user_id, tool_key, scope)
				WHERE scope != 'session';
			CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_allowlist_session_scope
				ON approval_allowlist(user_id, tool_key, session_key)
				WHERE scope = 'session';
			CREATE INDEX IF NOT EXISTS idx_approval_allowlist_user
				ON approval_allowlist(user_id, tool_key);
			CREATE INDEX IF NOT EXISTS idx_approval_allowlist_session
				ON approval_allowlist(session_key);
			CREATE INDEX IF NOT EXISTS idx_approval_allowlist_expires
				ON approval_allowlist(expires_at);
		`);
	}
}

function ensureColumn(
	database: Database.Database,
	tableName: string,
	columnName: string,
	alterStatement: string,
): void {
	const columns = database.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{
		name: string;
	}>;
	if (columns.some((column) => column.name === columnName)) {
		return;
	}
	database.exec(alterStatement);
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
		"sender_id",
		"message_thread_id",
		"turn_conversation_ref",
		"observer_classification",
		"observer_confidence",
		"observer_reason",
		// W1 graduated approvals
		"risk_tier",
		"tool_key",
		"session_key",
		// W1↔W8 integration: persist the exact Bash command so "always" grants
		// can derive an exec-policy glob.
		"bash_command",
	]);

	const rows = database.prepare("PRAGMA table_info(approvals)").all() as Array<{ name: string }>;
	const existing = new Set(rows.map((r) => r.name));
	const hasAll =
		rows.length > 0 &&
		rows.every((r) => requiredColumns.has(r.name)) &&
		requiredColumns.size === rows.length;

	if (rows.length > 0 && hasAll) {
		return;
	}

	// Additive migration path — if the existing table is missing only additive
	// approval metadata, ALTER it in instead of dropping. Older schemas that
	// are missing other columns still hit the drop-and-recreate fallback.
	if (rows.length > 0) {
		const additiveColumns = [
			"sender_id",
			"message_thread_id",
			"turn_conversation_ref",
			"risk_tier",
			"tool_key",
			"session_key",
			"bash_command",
		];
		const legacyExpected = new Set(
			[...requiredColumns].filter((name) => !additiveColumns.includes(name)),
		);
		const hasLegacyColumns =
			rows.every((r) => legacyExpected.has(r.name) || additiveColumns.includes(r.name)) &&
			[...legacyExpected].every((name) => existing.has(name));

		if (hasLegacyColumns) {
			if (!existing.has("sender_id")) {
				logger.info("adding sender_id column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN sender_id INTEGER");
			}
			if (!existing.has("message_thread_id")) {
				logger.info("adding message_thread_id column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN message_thread_id INTEGER");
			}
			if (!existing.has("turn_conversation_ref")) {
				logger.info("adding turn_conversation_ref column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN turn_conversation_ref TEXT");
			}
			if (!existing.has("risk_tier")) {
				logger.info("adding risk_tier column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN risk_tier TEXT");
			}
			if (!existing.has("tool_key")) {
				logger.info("adding tool_key column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN tool_key TEXT");
			}
			if (!existing.has("session_key")) {
				logger.info("adding session_key column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN session_key TEXT");
			}
			if (!existing.has("bash_command")) {
				logger.info("adding bash_command column to approvals table");
				database.exec("ALTER TABLE approvals ADD COLUMN bash_command TEXT");
			}
			return;
		}

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
			sender_id INTEGER,
			message_thread_id INTEGER,
			turn_conversation_ref TEXT,
			observer_classification TEXT NOT NULL,
			observer_confidence REAL NOT NULL,
			observer_reason TEXT,
			risk_tier TEXT,
			tool_key TEXT,
			session_key TEXT,
			bash_command TEXT
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
	planApprovals: number;
	linkCodes: number;
	rateLimits: number;
	totpSessions: number;
	adminClaims: number;
	pendingTotpMessages: number;
	botMessages: number;
	messageReactions: number;
	attachmentRefs: number;
	cronRuns: number;
	cardInstances: number;
	pairingRequests: number;
	pairingLockouts: number;
	backgroundJobs: number;
	approvalAllowlist: number;
	skillInvocations: number;
	webhookHits: number;
	webhookDeliveries: number;
} {
	const database = getDb();
	const now = Date.now();
	const oneHourAgo = now - 3600 * 1000;
	const oneDayAgo = now - 24 * 3600 * 1000;
	const thirtyDaysAgo = now - 30 * 24 * 3600 * 1000;
	const oneYearAgo = now - 365 * 24 * 3600 * 1000;

	const run = database.transaction(() => {
		const approvalsResult = database.prepare("DELETE FROM approvals WHERE expires_at < ?").run(now);
		const planApprovalsResult = database
			.prepare("DELETE FROM plan_approvals WHERE expires_at < ?")
			.run(now);
		const linkCodesResult = database
			.prepare("DELETE FROM pending_link_codes WHERE expires_at < ?")
			.run(now);
		const rateLimitsResult = database
			.prepare("DELETE FROM rate_limits WHERE window_start < ?")
			.run(oneHourAgo);
		const totpSessionsResult = database
			.prepare("DELETE FROM totp_sessions WHERE expires_at < ?")
			.run(now);
		const adminClaimsResult = database
			.prepare("DELETE FROM pending_admin_claims WHERE expires_at < ?")
			.run(now);
		const pendingTotpResult = database
			.prepare("DELETE FROM pending_totp_messages WHERE expires_at < ?")
			.run(now);
		const botMessagesResult = database
			.prepare("DELETE FROM bot_messages WHERE sent_at < ?")
			.run(oneDayAgo);
		const reactionsResult = database
			.prepare(
				`DELETE FROM message_reactions
				 WHERE (chat_id, message_id) NOT IN (
					 SELECT chat_id, message_id FROM bot_messages
				 )`,
			)
			.run();
		const attachmentRefsResult = database
			.prepare("DELETE FROM attachment_refs WHERE expires_at < ?")
			.run(now);
		const cronRunsResult = database
			.prepare("DELETE FROM cron_runs WHERE started_at < ?")
			.run(thirtyDaysAgo);
		const cardInstancesResult = database
			.prepare(
				`UPDATE card_instances
				 SET status = 'expired', revision = revision + 1, updated_at = ?
				 WHERE status = 'active' AND expires_at < ?`,
			)
			.run(now, now);

		// Pairing requests: pending → expired once past TTL, and prune old terminal
		// rows after 7 days so the table doesn't accumulate forever.
		const oneWeekAgo = now - 7 * 24 * 60 * 60 * 1000;
		const pairingMarked = database
			.prepare(
				"UPDATE pairing_requests SET status = 'expired' WHERE status = 'pending' AND expires_at < ?",
			)
			.run(now);
		const pairingPruned = database
			.prepare(
				`DELETE FROM pairing_requests
				 WHERE status IN ('expired', 'revoked') AND expires_at < ?`,
			)
			.run(oneWeekAgo);
		const pairingLockoutsResult = database
			.prepare("DELETE FROM pairing_lockouts WHERE locked_until < ?")
			.run(now);

		// Background jobs: prune terminal rows older than 30 days.
		const backgroundJobsResult = database
			.prepare(
				`DELETE FROM background_jobs
				 WHERE status IN ('completed', 'failed', 'cancelled', 'interrupted')
				   AND COALESCE(completed_at, cancelled_at, created_at) < ?`,
			)
			.run(thirtyDaysAgo);
		const webhookDeliveriesResult = database
			.prepare("DELETE FROM webhook_deliveries WHERE created_at < ?")
			.run(oneDayAgo);
		const webhookHitsResult = database
			.prepare("DELETE FROM webhook_hits WHERE created_at < ?")
			.run(thirtyDaysAgo);
		const skillInvocationsResult = database
			.prepare("DELETE FROM skill_invocations WHERE created_at < ?")
			.run(oneYearAgo);

		// W1 graduated approval allowlist:
		//   - delete anything past its expiry
		//   - prune "once" grants older than 24h that never fired
		//   - prune "always" grants whose last use is older than 30d
		const allowlistExpiredResult = database
			.prepare("DELETE FROM approval_allowlist WHERE expires_at IS NOT NULL AND expires_at < ?")
			.run(now);
		const allowlistStaleOnceResult = database
			.prepare("DELETE FROM approval_allowlist WHERE scope = 'once' AND granted_at < ?")
			.run(oneDayAgo);
		const allowlistStaleAlwaysResult = database
			.prepare(
				`DELETE FROM approval_allowlist
				 WHERE scope = 'always'
				   AND last_used_at IS NOT NULL
				   AND last_used_at < ?`,
			)
			.run(thirtyDaysAgo);

		return {
			approvals: approvalsResult.changes,
			planApprovals: planApprovalsResult.changes,
			linkCodes: linkCodesResult.changes,
			rateLimits: rateLimitsResult.changes,
			totpSessions: totpSessionsResult.changes,
			adminClaims: adminClaimsResult.changes,
			pendingTotpMessages: pendingTotpResult.changes,
			botMessages: botMessagesResult.changes,
			messageReactions: reactionsResult.changes,
			attachmentRefs: attachmentRefsResult.changes,
			cronRuns: cronRunsResult.changes,
			cardInstances: cardInstancesResult.changes,
			pairingRequests: pairingMarked.changes + pairingPruned.changes,
			pairingLockouts: pairingLockoutsResult.changes,
			backgroundJobs: backgroundJobsResult.changes,
			approvalAllowlist:
				allowlistExpiredResult.changes +
				allowlistStaleOnceResult.changes +
				allowlistStaleAlwaysResult.changes,
			skillInvocations: skillInvocationsResult.changes,
			webhookHits: webhookHitsResult.changes,
			webhookDeliveries: webhookDeliveriesResult.changes,
		};
	});

	const result = run();

	logger.info(result, "expired entries cleaned up");

	return result;
}

/**
 * Ensure memory_entries table has the current optional columns.
 * Adds it if missing (for existing databases).
 */
function ensureMemoryEntriesColumns(database: Database.Database): void {
	const rows = database.prepare("PRAGMA table_info(memory_entries)").all() as Array<{
		name: string;
	}>;
	const columns = new Set(rows.map((r) => r.name));

	if (!columns.has("posted_at")) {
		logger.info("adding posted_at column to memory_entries table");
		database.exec("ALTER TABLE memory_entries ADD COLUMN posted_at INTEGER");
		database.exec(
			"CREATE INDEX IF NOT EXISTS idx_memory_entries_posted ON memory_entries(posted_at)",
		);
	}

	if (!columns.has("chat_id")) {
		logger.info("adding chat_id column to memory_entries table");
		database.exec("ALTER TABLE memory_entries ADD COLUMN chat_id TEXT");
	}

	if (!columns.has("metadata")) {
		logger.info("adding metadata column to memory_entries table");
		database.exec("ALTER TABLE memory_entries ADD COLUMN metadata TEXT");
	}

	// Always ensure index exists (handles both migration and fresh DB)
	database.exec("CREATE INDEX IF NOT EXISTS idx_memory_entries_chat ON memory_entries(chat_id)");
}

function migrateDefaultTelegramMemorySource(database: Database.Database): void {
	const migrate = database.transaction(() => {
		const entries = database
			.prepare("UPDATE memory_entries SET source = 'telegram:default' WHERE source = 'telegram'")
			.run();
		const episodes = database
			.prepare("UPDATE memory_episodes SET source = 'telegram:default' WHERE source = 'telegram'")
			.run();
		return { entries: entries.changes, episodes: episodes.changes };
	});
	const result = migrate();
	logger.info(result, "memory source migration checked");
}
