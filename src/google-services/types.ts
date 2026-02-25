/**
 * Shared types for the Google Services sidecar.
 */

import { z } from "zod";

// ═══════════════════════════════════════════════════════════════════════════════
// Core Enums
// ═══════════════════════════════════════════════════════════════════════════════

export const ActionType = z.enum(["read", "action"]);
export type ActionType = z.infer<typeof ActionType>;

export const ServiceId = z.enum(["gmail", "calendar", "drive", "contacts"]);
export type ServiceId = z.infer<typeof ServiceId>;

// ═══════════════════════════════════════════════════════════════════════════════
// Request / Response
// ═══════════════════════════════════════════════════════════════════════════════

export const FetchRequestSchema = z.object({
	service: ServiceId,
	action: z.string().min(1),
	params: z.record(z.string(), z.unknown()).default({}),
});
export type FetchRequest = z.infer<typeof FetchRequestSchema>;

export const FetchResponseSchema = z.object({
	status: z.enum(["ok", "error"]),
	data: z.unknown().optional(),
	error: z.string().optional(),
	errorCode: z.string().optional(),
	attachments: z.array(z.record(z.string(), z.unknown())).default([]),
});
export type FetchResponse = z.infer<typeof FetchResponseSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Action Definition
// ═══════════════════════════════════════════════════════════════════════════════

export interface ParamDef {
	type: string;
	required: boolean;
	description: string;
	default?: unknown;
}

export interface ActionDefinition {
	id: string;
	service: ServiceId;
	type: ActionType;
	description: string;
	params: Record<string, ParamDef>;
	scope: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Health
// ═══════════════════════════════════════════════════════════════════════════════

export const HealthStatus = z.enum(["ok", "degraded", "auth_expired", "config_error"]);
export type HealthStatus = z.infer<typeof HealthStatus>;

export interface ServiceHealth {
	status: HealthStatus;
	lastSuccess?: number;
	lastAttempt?: number;
	failureCount: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Approval Token Claims
// ═══════════════════════════════════════════════════════════════════════════════

export const ApprovalClaimsSchema = z.object({
	ver: z.literal(1),
	iss: z.literal("telclaude-vault"),
	aud: z.literal("google-services"),
	/** Issued-at timestamp (Unix seconds, NOT milliseconds) */
	iat: z.number().int(),
	/** Expiration timestamp (Unix seconds, NOT milliseconds) */
	exp: z.number().int(),
	jti: z.string().min(1),
	approvalNonce: z.string().min(1),
	actorUserId: z.string().min(1),
	providerId: z.literal("google"),
	service: ServiceId,
	action: z.string().min(1),
	subjectUserId: z.string().nullable(),
	/** SHA-256 hex digest binding request params to approval */
	paramsHash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
});
export type ApprovalClaims = z.infer<typeof ApprovalClaimsSchema>;
