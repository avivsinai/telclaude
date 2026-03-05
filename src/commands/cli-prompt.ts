/**
 * Shared CLI prompt helpers.
 *
 * Consolidates duplicate readline prompt implementations from setup-openai,
 * setup-git, setup-google, oauth, vault, totp-setup, quickstart, reset-auth,
 * and reset-db commands.
 */

import * as readline from "node:readline";

/**
 * Prompt for visible text input.
 * Returns null on EOF or Ctrl+C.
 */
export async function promptLine(question: string): Promise<string | null> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		rl.question(question, (answer) => {
			rl.close();
			resolve(answer.trim() || null);
		});

		rl.on("close", () => {
			resolve(null);
		});
	});
}

/**
 * Prompt for secret input (hidden, echoes asterisks on TTY).
 * Returns null on EOF or Ctrl+C.
 */
export async function promptSecret(prompt: string): Promise<string | null> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		const stdin = process.stdin;
		const wasRaw = stdin.isRaw;

		if (stdin.isTTY) {
			process.stdout.write(prompt);
			stdin.setRawMode(true);

			let secret = "";
			stdin.resume();
			const handler = (char: Buffer) => {
				const c = char.toString();
				if (c === "\n" || c === "\r" || c === "\u0004") {
					stdin.setRawMode(wasRaw ?? false);
					stdin.removeListener("data", handler);
					process.stdout.write("\n");
					rl.close();
					resolve(secret.trim() || null);
				} else if (c === "\u0003") {
					stdin.setRawMode(wasRaw ?? false);
					stdin.removeListener("data", handler);
					process.stdout.write("\n");
					rl.close();
					resolve(null);
				} else if (c === "\u007F" || c === "\b") {
					if (secret.length > 0) {
						secret = secret.slice(0, -1);
						process.stdout.write("\b \b");
					}
				} else if (c.charCodeAt(0) >= 32) {
					secret += c;
					process.stdout.write("*");
				}
			};
			stdin.on("data", handler);
		} else {
			rl.question(prompt, (answer) => {
				rl.close();
				resolve(answer.trim() || null);
			});
		}
	});
}

/**
 * Prompt for yes/no confirmation.
 * Returns true for "y" or "yes" (case-insensitive), false otherwise.
 */
export async function promptYesNo(question: string): Promise<boolean> {
	return new Promise((resolve) => {
		const rl = readline.createInterface({
			input: process.stdin,
			output: process.stdout,
		});

		rl.question(`${question} (y/N): `, (answer) => {
			rl.close();
			resolve(answer.toLowerCase() === "y" || answer.toLowerCase() === "yes");
		});

		rl.on("close", () => {
			resolve(false);
		});
	});
}
