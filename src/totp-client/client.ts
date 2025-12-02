/**
 * TOTP client for communicating with the TOTP daemon.
 *
 * Uses Unix socket IPC with newline-delimited JSON protocol.
 * Provides a high-level API for TOTP operations.
 */

import { type Socket, createConnection } from "node:net";
import { getChildLogger } from "../logging.js";
import {
	type TOTPRequest,
	type TOTPResponse,
	TOTPResponseSchema,
	getDefaultSocketPath,
} from "../totp-daemon/protocol.js";

const logger = getChildLogger({ module: "totp-client" });

const DEFAULT_TIMEOUT_MS = 10000;

export type SetupResult = { success: true; uri: string } | { success: false; error: string };

/**
 * Client for the TOTP daemon.
 */
export class TOTPClient {
	private socketPath: string;
	private timeoutMs: number;

	constructor(options: { socketPath?: string; timeoutMs?: number } = {}) {
		this.socketPath =
			options.socketPath ?? process.env.TELCLAUDE_TOTP_SOCKET ?? getDefaultSocketPath();
		this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	}

	/**
	 * Send a request to the daemon and wait for a response.
	 */
	private async sendRequest(request: TOTPRequest): Promise<TOTPResponse> {
		return new Promise((resolve, reject) => {
			let socket: Socket | null = null;
			let buffer = "";
			let resolved = false;

			const timeout = setTimeout(() => {
				if (!resolved) {
					resolved = true;
					socket?.destroy();
					reject(new Error("TOTP daemon request timed out"));
				}
			}, this.timeoutMs);

			const cleanup = () => {
				clearTimeout(timeout);
				socket?.destroy();
			};

			try {
				socket = createConnection(this.socketPath);

				socket.on("connect", () => {
					socket?.write(`${JSON.stringify(request)}\n`);
				});

				socket.on("data", (data) => {
					buffer += data.toString();
					const lines = buffer.split("\n");
					buffer = lines.pop() ?? "";

					for (const line of lines) {
						if (!line.trim()) continue;

						resolved = true;
						cleanup();

						try {
							const parsed = JSON.parse(line);
							const response = TOTPResponseSchema.parse(parsed);
							resolve(response);
						} catch (err) {
							reject(new Error(`Invalid response from TOTP daemon: ${String(err)}`));
						}
						return;
					}
				});

				socket.on("error", (err) => {
					if (!resolved) {
						resolved = true;
						cleanup();
						logger.debug({ error: String(err) }, "TOTP daemon connection error");
						reject(new Error(`TOTP daemon unavailable: ${String(err)}`));
					}
				});

				socket.on("close", () => {
					if (!resolved) {
						resolved = true;
						cleanup();
						reject(new Error("TOTP daemon connection closed unexpectedly"));
					}
				});
			} catch (err) {
				cleanup();
				reject(new Error(`Failed to connect to TOTP daemon: ${String(err)}`));
			}
		});
	}

	/**
	 * Check if the TOTP daemon is available.
	 */
	async isAvailable(): Promise<boolean> {
		try {
			const response = await this.sendRequest({ type: "ping" });
			return response.type === "pong";
		} catch {
			return false;
		}
	}

	/**
	 * Set up TOTP for a user.
	 * Returns the otpauth:// URI for QR code generation.
	 */
	async setup(localUserId: string, label?: string): Promise<SetupResult> {
		try {
			const response = await this.sendRequest({
				type: "setup",
				localUserId,
				label,
			});

			if (response.type === "setup") {
				if (response.success) {
					return { success: true, uri: response.uri };
				}
				return { success: false, error: response.error };
			}

			if (response.type === "error") {
				return { success: false, error: response.error };
			}

			return { success: false, error: "Unexpected response from TOTP daemon" };
		} catch (err) {
			return { success: false, error: String(err) };
		}
	}

	/**
	 * Verify a TOTP code for a user.
	 */
	async verify(localUserId: string, code: string): Promise<boolean> {
		try {
			const response = await this.sendRequest({
				type: "verify",
				localUserId,
				code,
			});

			if (response.type === "verify") {
				return response.valid;
			}

			logger.warn({ response }, "unexpected verify response");
			return false;
		} catch (err) {
			logger.warn({ error: String(err) }, "TOTP verify failed");
			return false;
		}
	}

	/**
	 * Check if a user has TOTP enabled.
	 */
	async check(localUserId: string): Promise<boolean> {
		try {
			const response = await this.sendRequest({
				type: "check",
				localUserId,
			});

			if (response.type === "check") {
				return response.enabled;
			}

			return false;
		} catch (err) {
			logger.debug({ error: String(err) }, "TOTP check failed");
			return false;
		}
	}

	/**
	 * Disable TOTP for a user.
	 */
	async disable(localUserId: string): Promise<boolean> {
		try {
			const response = await this.sendRequest({
				type: "disable",
				localUserId,
			});

			if (response.type === "disable") {
				return response.removed;
			}

			return false;
		} catch (err) {
			logger.warn({ error: String(err) }, "TOTP disable failed");
			return false;
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Singleton
// ═══════════════════════════════════════════════════════════════════════════════

let client: TOTPClient | null = null;

/**
 * Get the singleton TOTP client.
 */
export function getTOTPClient(): TOTPClient {
	if (!client) {
		client = new TOTPClient();
	}
	return client;
}

/**
 * Reset the singleton client (for testing).
 */
export function resetTOTPClient(): void {
	client = null;
}
