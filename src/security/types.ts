import type { PermissionTier } from "../config/config.js";

/**
 * Classification result from the security observer.
 */
export type SecurityClassification = "ALLOW" | "WARN" | "BLOCK";

/**
 * Result from analyzing a message.
 */
export type ObserverResult = {
	classification: SecurityClassification;
	confidence: number;
	reason?: string;
	flaggedPatterns?: string[];
	suggestedTier?: PermissionTier;
	latencyMs: number;
};

/**
 * Audit log entry.
 */
export type AuditEntry = {
	timestamp: Date;
	requestId: string;
	telegramUserId: string;
	telegramUsername?: string;
	chatId: number;
	messagePreview: string;
	observerClassification?: SecurityClassification;
	observerConfidence?: number;
	permissionTier: PermissionTier;
	executionTimeMs?: number;
	outcome: "success" | "blocked" | "timeout" | "error" | "rate_limited";
	errorType?: string;
	costUsd?: number;
};

/**
 * Rate limit check result.
 */
export type RateLimitResult = {
	allowed: boolean;
	remaining: number;
	resetMs: number;
	limitType?: "global" | "user" | "tier";
};

/**
 * Standardized result type for operations that can fail.
 * Use this for functions that can return either success with data or failure with an error message.
 */
export type Result<T> = { success: true; data: T } | { success: false; error: string };
