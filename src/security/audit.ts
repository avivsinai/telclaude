import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { PermissionTier } from "../config/config.js";
import { getChildLogger } from "../logging.js";
import type { AuditEntry, SecurityClassification } from "./types.js";

const DEFAULT_AUDIT_DIR = path.join(os.tmpdir(), "telclaude");
const DEFAULT_AUDIT_FILE = path.join(DEFAULT_AUDIT_DIR, "audit.log");

const logger = getChildLogger({ module: "audit" });

/** Valid permission tiers for validation */
const VALID_PERMISSION_TIERS: PermissionTier[] = ["READ_ONLY", "WRITE_SAFE", "FULL_ACCESS"];

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

	constructor(config: AuditConfig) {
		this.config = config;
		this.logFile = config.logFile ?? DEFAULT_AUDIT_FILE;

		if (config.enabled) {
			// Ensure directory exists
			const dir = path.dirname(this.logFile);
			if (!fs.existsSync(dir)) {
				fs.mkdirSync(dir, { recursive: true });
			}
		}
	}

	/**
	 * Log an audit entry.
	 */
	async log(entry: AuditEntry): Promise<void> {
		if (!this.config.enabled) return;

		try {
			const line = JSON.stringify({
				...entry,
				timestamp: entry.timestamp.toISOString(),
			});

			await fs.promises.appendFile(this.logFile, `${line}\n`, "utf-8");

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
