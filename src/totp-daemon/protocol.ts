/**
 * TOTP daemon IPC protocol types.
 *
 * Uses Zod for runtime validation of messages.
 * Protocol is newline-delimited JSON over Unix socket.
 */

import { z } from "zod";

// ═══════════════════════════════════════════════════════════════════════════════
// Request Types
// ═══════════════════════════════════════════════════════════════════════════════

export const SetupRequestSchema = z.object({
	type: z.literal("setup"),
	localUserId: z.string().min(1),
	label: z.string().optional(),
});

export const VerifyRequestSchema = z.object({
	type: z.literal("verify"),
	localUserId: z.string().min(1),
	code: z.string().regex(/^\d{6}$/, "Code must be exactly 6 digits"),
});

export const CheckRequestSchema = z.object({
	type: z.literal("check"),
	localUserId: z.string().min(1),
});

export const DisableRequestSchema = z.object({
	type: z.literal("disable"),
	localUserId: z.string().min(1),
});

export const PingRequestSchema = z.object({
	type: z.literal("ping"),
});

export const TOTPRequestSchema = z.discriminatedUnion("type", [
	SetupRequestSchema,
	VerifyRequestSchema,
	CheckRequestSchema,
	DisableRequestSchema,
	PingRequestSchema,
]);

export type TOTPRequest = z.infer<typeof TOTPRequestSchema>;
export type SetupRequest = z.infer<typeof SetupRequestSchema>;
export type VerifyRequest = z.infer<typeof VerifyRequestSchema>;
export type CheckRequest = z.infer<typeof CheckRequestSchema>;
export type DisableRequest = z.infer<typeof DisableRequestSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Response Types (with Zod validation)
// ═══════════════════════════════════════════════════════════════════════════════

export const SetupSuccessResponseSchema = z.object({
	type: z.literal("setup"),
	success: z.literal(true),
	uri: z.string().startsWith("otpauth://"),
});

export const SetupErrorResponseSchema = z.object({
	type: z.literal("setup"),
	success: z.literal(false),
	error: z.string(),
});

export const SetupResponseSchema = z.union([SetupSuccessResponseSchema, SetupErrorResponseSchema]);

export const VerifyResponseSchema = z.object({
	type: z.literal("verify"),
	valid: z.boolean(),
});

export const CheckResponseSchema = z.object({
	type: z.literal("check"),
	enabled: z.boolean(),
});

export const DisableResponseSchema = z.object({
	type: z.literal("disable"),
	removed: z.boolean(),
});

export const PongResponseSchema = z.object({
	type: z.literal("pong"),
});

export const ErrorResponseSchema = z.object({
	type: z.literal("error"),
	error: z.string(),
});

export const TOTPResponseSchema = z.union([
	SetupResponseSchema,
	VerifyResponseSchema,
	CheckResponseSchema,
	DisableResponseSchema,
	PongResponseSchema,
	ErrorResponseSchema,
]);

// Infer types from schemas
export type SetupSuccessResponse = z.infer<typeof SetupSuccessResponseSchema>;
export type SetupErrorResponse = z.infer<typeof SetupErrorResponseSchema>;
export type SetupResponse = z.infer<typeof SetupResponseSchema>;
export type VerifyResponse = z.infer<typeof VerifyResponseSchema>;
export type CheckResponse = z.infer<typeof CheckResponseSchema>;
export type DisableResponse = z.infer<typeof DisableResponseSchema>;
export type PongResponse = z.infer<typeof PongResponseSchema>;
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
export type TOTPResponse = z.infer<typeof TOTPResponseSchema>;

// ═══════════════════════════════════════════════════════════════════════════════
// Socket Path
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get the default socket path for the TOTP daemon.
 * Uses ~/.telclaude/totp.sock
 */
export function getDefaultSocketPath(): string {
	const home = process.env.HOME || "/tmp";
	return `${home}/.telclaude/totp.sock`;
}
