/**
 * Git credential helper for telclaude.
 *
 * This implements the git credential helper protocol to provide
 * credentials from telclaude's secure storage without writing
 * them to disk as plaintext.
 *
 * Usage:
 *   git config --global credential.helper '/path/to/telclaude git-credential'
 *
 * Or for GitHub only:
 *   git config --global credential.https://github.com.helper '/path/to/telclaude git-credential'
 *
 * Protocol:
 *   https://git-scm.com/docs/git-credential#IOFMT
 */

import * as readline from "node:readline";

import type { Command } from "commander";

import { getChildLogger } from "../logging.js";
import { getGitCredentials, isHostAllowed } from "../services/git-credentials.js";

const logger = getChildLogger({ module: "git-credential" });

/** Keys that should never be logged (may contain secrets). */
const SENSITIVE_KEYS = new Set(["password", "token", "secret", "credential"]);

export function registerGitCredentialCommand(program: Command): void {
	program
		.command("git-credential")
		.description("Git credential helper (internal use)")
		.argument("<operation>", "Operation: get, store, or erase")
		.action(async (operation: string) => {
			try {
				switch (operation) {
					case "get":
						await handleGet();
						break;
					case "store":
						// We don't store credentials via the helper protocol
						// Users should use `telclaude setup-git` instead
						logger.debug("git-credential store called (ignored - use setup-git)");
						break;
					case "erase":
						// We don't erase via the helper protocol
						// Users should use `telclaude setup-git --delete` instead
						logger.debug("git-credential erase called (ignored - use setup-git --delete)");
						break;
					default:
						logger.warn({ operation }, "unknown git-credential operation");
						process.exit(1);
				}
			} catch (err) {
				logger.error({ error: String(err) }, "git-credential failed");
				process.exit(1);
			}
		});
}

/**
 * Redact sensitive keys from attributes for safe logging.
 */
function redactAttrs(attrs: Record<string, string>): Record<string, string> {
	const safe: Record<string, string> = {};
	for (const [key, value] of Object.entries(attrs)) {
		if (SENSITIVE_KEYS.has(key.toLowerCase())) {
			safe[key] = "***";
		} else {
			safe[key] = value;
		}
	}
	return safe;
}

/**
 * Handle the 'get' operation.
 * Reads input from stdin, outputs credentials to stdout.
 */
async function handleGet(): Promise<void> {
	// Read input from stdin (git sends attributes we might need)
	const input = await readInput();
	const attrs = parseAttributes(input);

	// Log only safe attributes (redact password/token if present)
	logger.debug({ attrs: redactAttrs(attrs) }, "git-credential get request");

	// Only handle HTTPS protocol
	if (attrs.protocol && attrs.protocol !== "https") {
		logger.debug({ protocol: attrs.protocol }, "ignoring non-https protocol");
		return;
	}

	// Check if host is in our allowlist (exact match or subdomain only)
	const host = attrs.host || "";
	if (!isHostAllowed(host)) {
		logger.debug({ host }, "host not in allowlist");
		return;
	}

	// Get credentials from secure storage
	const creds = await getGitCredentials();
	if (!creds) {
		logger.debug("no credentials available");
		return;
	}

	// Output in git credential format
	// Each line is key=value, terminated by empty line
	const output = [
		"protocol=https",
		`host=${host}`,
		`username=${creds.username}`,
		`password=${creds.token}`,
		"", // Empty line terminates
	].join("\n");

	process.stdout.write(output);
	logger.debug({ host, username: creds.username }, "credentials provided");
}

/**
 * Read all input from stdin.
 * Uses a timeout to handle cases where stdin is empty or slow.
 */
async function readInput(): Promise<string> {
	return new Promise((resolve) => {
		let input = "";
		let resolved = false;

		const rl = readline.createInterface({
			input: process.stdin,
			terminal: false,
		});

		// Set a timeout in case stdin is empty or takes too long
		const timeout = setTimeout(() => {
			if (!resolved) {
				resolved = true;
				rl.close();
				resolve(input);
			}
		}, 5000); // Increased to 5 seconds for slow systems

		rl.on("line", (line) => {
			input += `${line}\n`;
		});

		rl.on("close", () => {
			if (!resolved) {
				resolved = true;
				clearTimeout(timeout);
				resolve(input);
			}
		});
	});
}

/**
 * Parse git credential attributes from input.
 * Format: key=value lines, terminated by empty line.
 */
function parseAttributes(input: string): Record<string, string> {
	const attrs: Record<string, string> = {};

	for (const line of input.split("\n")) {
		if (!line || line.trim() === "") continue;

		const eqIndex = line.indexOf("=");
		if (eqIndex > 0) {
			const key = line.slice(0, eqIndex).trim();
			const value = line.slice(eqIndex + 1).trim();
			attrs[key] = value;
		}
	}

	return attrs;
}
