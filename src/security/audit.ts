import fs from "node:fs";
import path from "node:path";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import { CONFIG_DIR } from "../utils.js";
import { redactSecrets } from "./output-filter.js";
import type { AuditEntry, SecurityClassification } from "./types.js";

const DEFAULT_AUDIT_DIR = path.join(CONFIG_DIR, "logs");
const DEFAULT_AUDIT_FILE = path.join(DEFAULT_AUDIT_DIR, "audit.log");

const logger = getChildLogger({ module: "audit" });

/** Valid permission tiers for validation */
const VALID_PERMISSION_TIERS: PermissionTier[] = ["READ_ONLY", "WRITE_LOCAL", "FULL_ACCESS"];

/** Valid outcomes for validation */
const VALID_OUTCOMES = ["success", "blocked", "timeout", "error", "rate_limited"] as const;

/** Valid classifications for validation */
const VALID_CLASSIFICATIONS: SecurityClassification[] = ["ALLOW", "WARN", "BLOCK"];

/**
 * Type guard for PermissionTier.
 */
function isValidPermissionTier(tier: unknown): tier is PermissionTier {
	return typeof tier === "string" && VALID_PERMISSION_TIERS.includes(tier as PermissionTier);
}

/**
 * Type guard for parsed audit entry from JSON.
 */
function isValidParsedAuditEntry(
	entry: unknown,
): entry is Omit<AuditEntry, "timestamp"> & { timestamp: string } {
	if (typeof entry !== "object" || entry === null) return false;

	const e = entry as Record<string, unknown>;

	return (
		typeof e.timestamp === "string" &&
		typeof e.requestId === "string" &&
		typeof e.telegramUserId === "string" &&
		typeof e.chatId === "number" &&
		typeof e.messagePreview === "string" &&
		isValidPermissionTier(e.permissionTier) &&
		typeof e.outcome === "string" &&
		VALID_OUTCOMES.includes(e.outcome as (typeof VALID_OUTCOMES)[number]) &&
		(e.observerClassification === undefined ||
			VALID_CLASSIFICATIONS.includes(e.observerClassification as SecurityClassification)) &&
		(e.observerConfidence === undefined || typeof e.observerConfidence === "number") &&
		(e.executionTimeMs === undefined || typeof e.executionTimeMs === "number") &&
		(e.costUsd === undefined || typeof e.costUsd === "number")
	);
}

export type AuditConfig = {
	enabled: boolean;
	logFile?: string;
};

/**
 * Audit logger for security events.
 */
export class AuditLogger {
	private config: AuditConfig;
	private logFile: string;
	private initialized = false;

	constructor(config: AuditConfig) {
		this.config = config;
		this.logFile = config.logFile ?? DEFAULT_AUDIT_FILE;

		if (config.enabled) {
			this.initializeSecurely();
		}
	}

	/**
	 * Initialize audit log directory and file with secure permissions.
	 * SECURITY: Directory 0700, file 0600 to prevent other users from
	 * reading or tampering with audit logs.
	 */
	private initializeSecurely(): void {
		const dir = path.dirname(this.logFile);

		try {
			// Create directory with restricted permissions (atomic with recursive: true)
			fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

			// SECURITY: Use lstatSync to avoid TOCTOU and prevent symlink attacks
			// lstatSync doesn't follow symlinks, so we can detect and reject them
			try {
				const dirStats = fs.lstatSync(dir);
				// Reject if directory is a symlink
				if (dirStats.isSymbolicLink()) {
					logger.warn({ dir }, "audit directory is a symlink - skipping");
					this.initialized = false;
					return;
				}
				const dirMode = dirStats.mode & 0o777;
				if (dirMode !== 0o700) {
					fs.chmodSync(dir, 0o700);
					logger.info(
						{ dir, oldMode: dirMode.toString(8), newMode: "700" },
						"fixed audit directory permissions",
					);
				}
			} catch {
				// Directory doesn't exist after mkdir - something is wrong
				this.initialized = false;
				return;
			}

			// SECURITY: Use lstatSync to check file without TOCTOU vulnerability
			try {
				const fileStats = fs.lstatSync(this.logFile);
				// Reject if file is a symlink
				if (fileStats.isSymbolicLink()) {
					logger.warn({ file: this.logFile }, "audit file is a symlink - skipping");
					this.initialized = false;
					return;
				}
				const fileMode = fileStats.mode & 0o777;
				if (fileMode !== 0o600) {
					fs.chmodSync(this.logFile, 0o600);
					logger.info(
						{ file: this.logFile, oldMode: fileMode.toString(8), newMode: "600" },
						"fixed audit file permissions",
					);
				}
			} catch {
				// File doesn't exist yet - that's fine, it will be created on first write
			}

			this.initialized = true;
		} catch (err) {
			// Log error but don't fail - audit logging is best-effort
			// However, we mark as not initialized to prevent writing to insecure locations
			logger.error(
				{ error: String(err), dir, file: this.logFile },
				"failed to initialize secure audit log",
			);
			this.initialized = false;
		}
	}

	/**
	 * Log an audit entry.
	 *
	 * SECURITY: Message preview is sanitized to redact any detected secrets
	 * before being written to the audit log.
	 */
	async log(entry: AuditEntry): Promise<void> {
		if (!this.config.enabled) return;

		// Don't write to insecure locations
		if (!this.initialized) {
			logger.warn({ requestId: entry.requestId }, "audit log not initialized - entry not written");
			return;
		}

		try {
			// SECURITY: Redact secrets from message preview before logging
			const sanitizedEntry = {
				...entry,
				messagePreview: redactSecrets(entry.messagePreview),
				timestamp: entry.timestamp.toISOString(),
			};

			const line = JSON.stringify(sanitizedEntry);

			// Check if file exists to determine if we need to set permissions
			const fileExisted = fs.existsSync(this.logFile);

			await fs.promises.appendFile(this.logFile, `${line}\n`, { encoding: "utf-8", mode: 0o600 });

			// Set permissions if file was just created
			// (appendFile's mode only applies to new files, but verify anyway)
			if (!fileExisted) {
				try {
					await fs.promises.chmod(this.logFile, 0o600);
				} catch {
					// Ignore chmod errors on append
				}
			}

			// Also log to the regular logger
			logger.info(
				{
					requestId: entry.requestId,
					userId: entry.telegramUserId,
					outcome: entry.outcome,
					classification: entry.observerClassification,
				},
				"audit entry logged",
			);
		} catch (err) {
			logger.error({ error: String(err) }, "failed to write audit log");
		}
	}

	/**
	 * Log a blocked request.
	 */
	async logBlocked(entry: Omit<AuditEntry, "outcome">, reason: string): Promise<void> {
		await this.log({
			...entry,
			outcome: "blocked",
			errorType: reason,
		});
	}

	/**
	 * Log a rate-limited request.
	 */
	async logRateLimited(
		telegramUserId: string,
		chatId: number,
		tier: PermissionTier,
	): Promise<void> {
		await this.log({
			timestamp: new Date(),
			requestId: `rate_${Date.now()}`,
			telegramUserId,
			chatId,
			messagePreview: "(rate limited)",
			permissionTier: tier,
			outcome: "rate_limited",
		});
	}

	/**
	 * Read recent audit entries.
	 */
	async readRecent(limit = 100): Promise<AuditEntry[]> {
		if (!this.config.enabled) return [];

		try {
			const content = await fs.promises.readFile(this.logFile, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);
			const entries = lines
				.slice(-limit)
				.map((line): AuditEntry | null => {
					try {
						const parsed: unknown = JSON.parse(line);
						if (isValidParsedAuditEntry(parsed)) {
							return {
								...parsed,
								timestamp: new Date(parsed.timestamp),
							};
						}
						return null;
					} catch {
						return null;
					}
				})
				.filter((e): e is AuditEntry => e !== null);

			return entries;
		} catch {
			return [];
		}
	}

	/**
	 * Get statistics from audit log.
	 */
	async getStats(): Promise<{
		total: number;
		blocked: number;
		rateLimited: number;
		errors: number;
		success: number;
	}> {
		const entries = await this.readRecent(1000);
		return {
			total: entries.length,
			blocked: entries.filter((e) => e.outcome === "blocked").length,
			rateLimited: entries.filter((e) => e.outcome === "rate_limited").length,
			errors: entries.filter((e) => e.outcome === "error").length,
			success: entries.filter((e) => e.outcome === "success").length,
		};
	}
}

/**
 * Create an audit logger from config.
 */
export function createAuditLogger(config: AuditConfig): AuditLogger {
	return new AuditLogger(config);
}
