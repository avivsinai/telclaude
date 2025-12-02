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
import { type Server, type Socket, createServer } from "node:net";
import path from "node:path";
import { getChildLogger } from "../logging.js";
import * as keychain from "./keychain.js";
import {
	type TOTPRequest,
	TOTPRequestSchema,
	type TOTPResponse,
	getDefaultSocketPath,
} from "./protocol.js";

const logger = getChildLogger({ module: "totp-server" });

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
			try {
				fs.chmodSync(socketPath, 0o600);
			} catch (err) {
				logger.warn({ error: String(err) }, "failed to set socket permissions");
			}

			logger.info({ socketPath }, "TOTP daemon listening");

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
			const valid = await keychain.verifyTOTP(request.localUserId, request.code);
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
