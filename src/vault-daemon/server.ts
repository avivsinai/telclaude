/**
 * Credential vault Unix socket server.
 *
 * Listens on a Unix socket and handles credential requests.
 * Uses newline-delimited JSON protocol.
 *
 * Security:
 * - Socket permissions set to 0600 (owner only)
 * - Never returns raw credentials in list operations
 * - Credentials only returned via get operations
 * - No network access (Unix socket only)
 */

import fs from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import path from "node:path";

import { getChildLogger } from "../logging.js";
import {
	clearTokenCache,
	getAccessToken,
	invalidateToken,
	startCleanupTimer,
	stopCleanupTimer,
} from "./oauth.js";
import {
	getDefaultSocketPath,
	type VaultRequest,
	VaultRequestSchema,
	type VaultResponse,
} from "./protocol.js";
import { getVaultStore, resetVaultStore, type VaultStoreOptions } from "./store.js";

const logger = getChildLogger({ module: "vault-server" });

// ═══════════════════════════════════════════════════════════════════════════════
// Server Types
// ═══════════════════════════════════════════════════════════════════════════════

export interface ServerOptions {
	socketPath?: string;
	storeOptions?: VaultStoreOptions;
}

export interface ServerHandle {
	isRunning: () => boolean;
	stop: () => Promise<void>;
	socketPath: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Start the vault daemon server.
 */
export async function startServer(options: ServerOptions = {}): Promise<ServerHandle> {
	const socketPath = options.socketPath ?? getDefaultSocketPath();

	// Initialize store (validates encryption key)
	getVaultStore(options.storeOptions);

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

			// Start OAuth token cleanup timer
			startCleanupTimer();

			logger.info({ socketPath }, "vault daemon listening");

			resolve({
				isRunning: () => server.listening,
				stop: () => stopServer(server, socketPath),
				socketPath,
			});
		});
	});
}

/**
 * Stop the server and clean up.
 */
async function stopServer(server: Server, socketPath: string): Promise<void> {
	return new Promise((resolve) => {
		// Stop OAuth cleanup timer
		stopCleanupTimer();

		// Clear token cache
		clearTokenCache();

		// Reset store singleton
		resetVaultStore();

		server.close(() => {
			try {
				fs.unlinkSync(socketPath);
			} catch {
				// Ignore if already removed
			}
			logger.info("vault daemon stopped");
			resolve();
		});
	});
}

// ═══════════════════════════════════════════════════════════════════════════════
// Connection Handler
// ═══════════════════════════════════════════════════════════════════════════════

// Max request size (1MB - credentials with SSH keys can be large)
const MAX_REQUEST_SIZE = 1024 * 1024;

/**
 * Handle a new client connection.
 */
function handleConnection(socket: Socket): void {
	const clientId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
	logger.debug({ clientId }, "client connected");

	let buffer = "";

	socket.on("data", async (data) => {
		buffer += data.toString();

		// SECURITY: Enforce max request size to prevent memory exhaustion
		if (buffer.length > MAX_REQUEST_SIZE) {
			logger.warn({ clientId, bufferSize: buffer.length }, "request too large, closing connection");
			socket.write(`${JSON.stringify({ type: "error", error: "Request too large" })}\n`);
			socket.end();
			return;
		}

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
async function processLine(line: string, clientId: string): Promise<VaultResponse> {
	try {
		const parsed = JSON.parse(line);
		const request = VaultRequestSchema.parse(parsed);
		return await handleRequest(request, clientId);
	} catch (err) {
		// SECURITY: Never log line content - it may contain credentials
		logger.warn({ clientId, error: String(err), lineLength: line.length }, "invalid request");
		return {
			type: "error",
			error: `Invalid request: ${String(err)}`,
		};
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request Handlers
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Handle a validated request.
 */
async function handleRequest(request: VaultRequest, clientId: string): Promise<VaultResponse> {
	logger.debug({ clientId, requestType: request.type }, "handling request");
	const store = getVaultStore();

	switch (request.type) {
		case "ping": {
			return { type: "pong" };
		}

		case "get": {
			const entry = await store.get(request.protocol, request.target);
			if (!entry) {
				return { type: "get", ok: false, error: "not_found" };
			}
			return { type: "get", ok: true, entry };
		}

		case "get-token": {
			// Get the credential first
			const entry = await store.get(request.protocol, request.target);
			if (!entry) {
				return { type: "get-token", ok: false, error: "Credential not found" };
			}

			// Must be an OAuth2 credential
			if (entry.credential.type !== "oauth2") {
				return {
					type: "get-token",
					ok: false,
					error: `Credential is type '${entry.credential.type}', not 'oauth2'`,
				};
			}

			// Get access token (handles refresh)
			const result = await getAccessToken(request.target, entry.credential);
			if (!result.ok) {
				return { type: "get-token", ok: false, error: result.error };
			}

			// Handle refresh token rotation - update stored credential with new refresh token
			if (result.newRefreshToken) {
				logger.info({ target: request.target }, "persisting rotated refresh token");
				const updatedCredential = {
					...entry.credential,
					refreshToken: result.newRefreshToken,
				};
				await store.store(request.protocol, request.target, updatedCredential, {
					label: entry.label,
					allowedPaths: entry.allowedPaths,
					rateLimitPerMinute: entry.rateLimitPerMinute,
					expiresAt: entry.expiresAt,
				});
			}

			return {
				type: "get-token",
				ok: true,
				token: result.token,
				expiresAt: result.expiresAt,
			};
		}

		case "store": {
			await store.store(request.protocol, request.target, request.credential, {
				label: request.label,
				allowedPaths: request.allowedPaths,
				rateLimitPerMinute: request.rateLimitPerMinute,
				expiresAt: request.expiresAt,
			});

			// Invalidate any cached OAuth token for this target
			invalidateToken(request.target);

			return { type: "store", ok: true };
		}

		case "delete": {
			const deleted = await store.delete(request.protocol, request.target);

			// Invalidate any cached OAuth token for this target
			invalidateToken(request.target);

			return { type: "delete", ok: true, deleted };
		}

		case "list": {
			const entries = await store.list(request.protocol);
			return { type: "list", ok: true, entries };
		}
	}
}
