/**
 * TOTP daemon Unix socket server.
 *
 * Listens on a Unix socket and handles TOTP requests.
 * Uses newline-delimited JSON protocol.
 *
 * Security:
 * - Socket permissions set to 0600 (owner only)
 * - Never returns raw secrets in responses
 * - Only exposes verification API
 */

import fs from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import path from "node:path";
import { getChildLogger } from "../logging.js";
import * as keychain from "./keychain.js";
import {
	getDefaultSocketPath,
	type TOTPRequest,
	TOTPRequestSchema,
	type TOTPResponse,
} from "./protocol.js";

const logger = getChildLogger({ module: "totp-server" });

// ═══════════════════════════════════════════════════════════════════════════════
// TOTP Verification Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Rate limit configuration for TOTP verification.
 * Prevents brute-force attacks on 6-digit codes (1M possibilities).
 */
const VERIFY_RATE_LIMIT = {
	maxAttempts: 5, // Max attempts per window
	windowMs: 60 * 1000, // 1 minute window
	lockoutMs: 5 * 60 * 1000, // 5 minute lockout after exceeding
};

type RateLimitEntry = {
	attempts: number;
	windowStart: number;
	lockedUntil?: number;
};

const verifyRateLimits = new Map<string, RateLimitEntry>();

/**
 * Check if a user is rate limited for TOTP verification.
 * Returns true if request should be allowed, false if rate limited.
 */
function checkVerifyRateLimit(localUserId: string): { allowed: boolean; retryAfterMs?: number } {
	const now = Date.now();
	let entry = verifyRateLimits.get(localUserId);

	// Check if currently locked out
	if (entry?.lockedUntil && entry.lockedUntil > now) {
		return { allowed: false, retryAfterMs: entry.lockedUntil - now };
	}

	// Create or reset entry if window expired
	if (!entry || now - entry.windowStart > VERIFY_RATE_LIMIT.windowMs) {
		entry = { attempts: 0, windowStart: now };
		verifyRateLimits.set(localUserId, entry);
	}

	// Check if over limit
	if (entry.attempts >= VERIFY_RATE_LIMIT.maxAttempts) {
		// Apply lockout
		entry.lockedUntil = now + VERIFY_RATE_LIMIT.lockoutMs;
		logger.warn(
			{ localUserId, lockoutMs: VERIFY_RATE_LIMIT.lockoutMs },
			"TOTP verification locked out",
		);
		return { allowed: false, retryAfterMs: VERIFY_RATE_LIMIT.lockoutMs };
	}

	// Increment and allow
	entry.attempts++;
	return { allowed: true };
}

/**
 * Reset rate limit for a user (called on successful verification).
 */
function resetVerifyRateLimit(localUserId: string): void {
	verifyRateLimits.delete(localUserId);
}

function startVerifyRateLimitCleanupTimer(): NodeJS.Timeout {
	// Clean up stale entries periodically.
	// IMPORTANT: This must not run at module import time; otherwise every CLI command
	// would keep the event loop alive even when the daemon isn't started.
	const timer = setInterval(() => {
		const now = Date.now();
		for (const [userId, entry] of verifyRateLimits.entries()) {
			// Remove if window expired and not locked out
			if (
				now - entry.windowStart > VERIFY_RATE_LIMIT.windowMs &&
				(!entry.lockedUntil || entry.lockedUntil <= now)
			) {
				verifyRateLimits.delete(userId);
			}
		}
	}, 60 * 1000); // Every minute
	timer.unref();
	return timer;
}

export type ServerOptions = {
	socketPath?: string;
};

export type ServerHandle = {
	isRunning: () => boolean;
	stop: () => Promise<void>;
	socketPath: string;
};

/**
 * Start the TOTP daemon server.
 */
export async function startServer(options: ServerOptions = {}): Promise<ServerHandle> {
	const socketPath = options.socketPath ?? getDefaultSocketPath();

	// Ensure directory exists
	const socketDir = path.dirname(socketPath);
	fs.mkdirSync(socketDir, { recursive: true });

	// Remove stale socket file if it exists
	try {
		fs.unlinkSync(socketPath);
	} catch {
		// Ignore if doesn't exist
	}

	const server = createServer((socket) => {
		handleConnection(socket);
	});

	return new Promise((resolve, reject) => {
		server.on("error", (err) => {
			logger.error({ error: String(err) }, "server error");
			reject(err);
		});

		server.listen(socketPath, () => {
			// Set socket permissions to owner only (0600)
			// SECURITY: This MUST succeed - other users could connect otherwise
			try {
				fs.chmodSync(socketPath, 0o600);
				// Verify the permissions were actually set
				const stats = fs.statSync(socketPath);
				const mode = stats.mode & 0o777;
				if (mode !== 0o600) {
					throw new Error(`Socket permissions are ${mode.toString(8)}, expected 600`);
				}
			} catch (err) {
				logger.error(
					{ error: String(err), socketPath },
					"CRITICAL: failed to secure socket permissions",
				);
				server.close();
				reject(new Error(`Failed to set socket permissions: ${String(err)}`));
				return;
			}

			logger.info({ socketPath }, "TOTP daemon listening");

			const cleanupTimer = startVerifyRateLimitCleanupTimer();
			resolve({
				isRunning: () => server.listening,
				stop: () => stopServer(server, socketPath, cleanupTimer),
				socketPath,
			});
		});
	});
}

/**
 * Stop the server and clean up.
 */
async function stopServer(
	server: Server,
	socketPath: string,
	cleanupTimer: NodeJS.Timeout,
): Promise<void> {
	return new Promise((resolve) => {
		clearInterval(cleanupTimer);
		server.close(() => {
			try {
				fs.unlinkSync(socketPath);
			} catch {
				// Ignore if already removed
			}
			logger.info("TOTP daemon stopped");
			resolve();
		});
	});
}

/**
 * Handle a new client connection.
 */
function handleConnection(socket: Socket): void {
	const clientId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
	logger.debug({ clientId }, "client connected");

	let buffer = "";

	socket.on("data", async (data) => {
		buffer += data.toString();

		// Process complete lines (newline-delimited JSON)
		const lines = buffer.split("\n");
		buffer = lines.pop() ?? ""; // Keep incomplete line in buffer

		for (const line of lines) {
			if (!line.trim()) continue;

			const response = await processLine(line, clientId);
			socket.write(`${JSON.stringify(response)}\n`);
		}
	});

	socket.on("error", (err) => {
		logger.debug({ clientId, error: String(err) }, "socket error");
	});

	socket.on("close", () => {
		logger.debug({ clientId }, "client disconnected");
	});
}

/**
 * Process a single request line.
 */
async function processLine(line: string, clientId: string): Promise<TOTPResponse> {
	try {
		const parsed = JSON.parse(line);
		const request = TOTPRequestSchema.parse(parsed);
		return await handleRequest(request, clientId);
	} catch (err) {
		logger.warn({ clientId, error: String(err), line: line.slice(0, 100) }, "invalid request");
		return {
			type: "error",
			error: `Invalid request: ${String(err)}`,
		};
	}
}

/**
 * Handle a validated request.
 */
async function handleRequest(request: TOTPRequest, clientId: string): Promise<TOTPResponse> {
	logger.debug({ clientId, requestType: request.type }, "handling request");

	switch (request.type) {
		case "ping": {
			return { type: "pong" };
		}

		case "setup": {
			const result = await keychain.setupTOTP(request.localUserId, request.label);
			if (result.success) {
				return {
					type: "setup",
					success: true,
					uri: result.uri,
				};
			}
			return {
				type: "setup",
				success: false,
				error: result.error,
			};
		}

		case "verify": {
			// Check rate limit before verification
			const rateLimit = checkVerifyRateLimit(request.localUserId);
			if (!rateLimit.allowed) {
				logger.warn({ localUserId: request.localUserId }, "TOTP verification rate limited");
				return {
					type: "error",
					error: `Rate limited. Try again in ${Math.ceil((rateLimit.retryAfterMs ?? 0) / 1000)} seconds.`,
				};
			}

			const valid = await keychain.verifyTOTP(request.localUserId, request.code);

			// Reset rate limit on successful verification
			if (valid) {
				resetVerifyRateLimit(request.localUserId);
			}

			return {
				type: "verify",
				valid,
			};
		}

		case "check": {
			const enabled = await keychain.hasSecret(request.localUserId);
			return {
				type: "check",
				enabled,
			};
		}

		case "disable": {
			const removed = await keychain.disableTOTP(request.localUserId);
			return {
				type: "disable",
				removed,
			};
		}
	}
}
