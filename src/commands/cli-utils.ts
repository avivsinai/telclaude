/**
 * Shared CLI utilities.
 *
 * Consolidates duplicate helper functions from various command files:
 * - parseChatId: access-control, send, link
 * - copyDirRecursive: skills-promote, skills-import
 * - formatDuration: sessions (formatAge)
 * - formatUptime: status
 * - confirmDangerousReset: reset-auth, reset-db
 * - runDaemon: totp-daemon, vault-daemon, git-proxy-init, agent
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { promptLine } from "./cli-prompt.js";

/**
 * Parse a string as a chat ID (integer). Exits on failure.
 */
export function parseChatId(raw: string): number {
	const id = Number.parseInt(raw, 10);
	if (Number.isNaN(id)) {
		console.error(`Invalid chat ID: ${raw}`);
		process.exit(1);
	}
	return id;
}

/**
 * Recursively copy a directory.
 */
export function copyDirRecursive(source: string, target: string): void {
	fs.mkdirSync(target, { recursive: true });
	const entries = fs.readdirSync(source, { withFileTypes: true });
	for (const entry of entries) {
		const srcPath = path.join(source, entry.name);
		const tgtPath = path.join(target, entry.name);
		if (entry.isDirectory()) {
			copyDirRecursive(srcPath, tgtPath);
		} else if (entry.isFile()) {
			fs.copyFileSync(srcPath, tgtPath);
		}
	}
}

/**
 * Format a duration in ms as a short human string (e.g., "5s", "3m", "2h", "1d").
 */
export function formatDuration(ms: number): string {
	const seconds = Math.floor(ms / 1000);
	if (seconds < 60) return `${seconds}s`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h`;
	const days = Math.floor(hours / 24);
	return `${days}d`;
}

/**
 * Format an uptime in seconds as a compound string (e.g., "2h 15m 30s").
 */
export function formatUptime(seconds: number): string {
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);
	const remainingMinutes = minutes % 60;
	const remainingSeconds = seconds % 60;

	if (hours > 0) return `${hours}h ${remainingMinutes}m ${remainingSeconds}s`;
	if (minutes > 0) return `${minutes}m ${remainingSeconds}s`;
	return `${remainingSeconds}s`;
}

/**
 * Two-step dangerous reset confirmation.
 * 1. User types the label (e.g., "RESET") to confirm.
 * 2. On TTY, user must also enter a random confirmation code.
 *
 * Returns true if confirmed, false if aborted.
 * --force skips confirmation in non-TTY environments only.
 */
export async function confirmDangerousReset(opts: {
	label: string;
	force?: boolean;
}): Promise<boolean> {
	const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);

	if (opts.force && isTty) {
		console.log("--force ignored on TTY; interactive confirmations are required.");
	}

	if (!opts.force || isTty) {
		const answer = await promptLine(`Type "${opts.label}" to confirm: `);
		if (answer?.trim().toUpperCase() !== opts.label.toUpperCase()) {
			console.log("");
			console.log("Aborted. No changes made.");
			return false;
		}
	}

	if (isTty) {
		const code = crypto.randomBytes(3).toString("hex").toUpperCase();
		const codeAnswer = await promptLine(`Enter confirmation code ${code}: `);
		if (codeAnswer?.trim().toUpperCase() !== code) {
			console.log("");
			console.log("Aborted. No changes made.");
			return false;
		}
	}

	return true;
}

/**
 * Keep a daemon process alive until SIGINT/SIGTERM.
 * Optionally runs cleanup before exit.
 */
export async function runDaemon(opts?: {
	onShutdown?: () => Promise<void> | void;
}): Promise<never> {
	const shutdown = async (signal: string) => {
		console.log(`\nReceived ${signal}, shutting down...`);
		if (opts?.onShutdown) {
			await opts.onShutdown();
		}
		process.exit(0);
	};

	process.on("SIGINT", () => shutdown("SIGINT"));
	process.on("SIGTERM", () => shutdown("SIGTERM"));

	// Never resolves - daemon runs until signal
	return new Promise(() => {});
}
