/**
 * Shared CLI prompt helpers.
 *
 * Consolidates duplicate readline prompt implementations from setup-openai,
 * setup-git, setup-google, oauth, vault, totp-setup, quickstart, reset-auth,
 * and reset-db commands.
 */

import * as readline from "node:readline";

/**
 * Mutable accumulator for raw-mode secret entry.
 *
 * `done` is set once a submit key (Enter/CR/EOF) is seen; `cancelled` is set on
 * Ctrl+C. Once either flag is set the rest of the chunk is ignored.
 */
export interface SecretInputState {
	value: string;
	done?: boolean;
	cancelled?: boolean;
}

const ESC = "";
const BRACKETED_PASTE_START = "[200~";
const BRACKETED_PASTE_END = "[201~";

/**
 * Apply one raw-mode stdin chunk to the secret-entry state, character by
 * character.
 *
 * A single `data` event can carry many characters — most importantly on paste,
 * where terminals may also wrap the payload in bracketed-paste markers
 * (`ESC[200~ … ESC[201~`). Treating the whole buffer as one logical "key" (the
 * previous bug) duplicated and corrupted pasted secrets — a 31-char key could
 * arrive as 61 chars. This helper instead:
 *
 * - submits on Enter (`\n`/`\r`) or EOF (``), ignoring the rest of the chunk;
 * - cancels on Ctrl+C (``);
 * - applies backspace (``/`\b`) per character;
 * - drops bracketed-paste markers and any other ESC-led control sequence
 *   (a CSI/SS3 run skips parameter bytes then one final byte in 0x40-0x7e,
 *   e.g. the `~` ending `ESC[3~`; other ESC runs drop the next byte);
 * - appends only printable characters (code point >= 32).
 *
 * Pure and synchronous so it can be unit-tested without a TTY.
 */
export function applySecretInputChunk(state: SecretInputState, chunk: string): SecretInputState {
	if (state.done || state.cancelled) return state;

	for (let i = 0; i < chunk.length; i++) {
		const ch = chunk[i];

		// Strip bracketed-paste markers and any other ESC-led control sequence.
		if (ch === ESC) {
			if (chunk.startsWith(BRACKETED_PASTE_START, i)) {
				i += BRACKETED_PASTE_START.length - 1;
				continue;
			}
			if (chunk.startsWith(BRACKETED_PASTE_END, i)) {
				i += BRACKETED_PASTE_END.length - 1;
				continue;
			}
			// Generic ESC sequence (arrow keys, Delete/Home/Fn, etc.). A CSI (ESC[)
			// or SS3 (ESCO) run consumes parameter/intermediate bytes then ONE final
			// byte in 0x40-0x7e — which includes the "~" that ends sequences like
			// ESC[3~ (Delete). Terminating only on an ASCII letter would swallow the
			// next real character after a ~-terminated sequence. Any other ESC run
			// drops the single following byte. Bracketed-paste markers are handled above.
			let j = i + 1;
			if (chunk[j] === "[" || chunk[j] === "O") {
				j++;
				while (j < chunk.length) {
					const code = chunk.charCodeAt(j);
					j++;
					if (code >= 0x40 && code <= 0x7e) break; // CSI/SS3 final byte
				}
			} else if (j < chunk.length) {
				j++; // two-byte ESC sequence
			}
			i = j - 1; // loop's i++ resumes at the byte after the sequence
			continue;
		}

		if (ch === "\n" || ch === "\r" || ch === "") {
			state.done = true;
			return state;
		}
		if (ch === "") {
			state.cancelled = true;
			return state;
		}
		if (ch === "" || ch === "\b") {
			if (state.value.length > 0) state.value = state.value.slice(0, -1);
			continue;
		}
		if (ch.charCodeAt(0) >= 32) {
			state.value += ch;
		}
	}

	return state;
}

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
		const stdin = process.stdin;
		const wasRaw = stdin.isRaw;

		if (stdin.isTTY) {
			process.stdout.write(prompt);
			stdin.setRawMode(true);

			const state: SecretInputState = { value: "" };
			stdin.resume();
			const handler = (char: Buffer) => {
				const before = state.value.length;
				applySecretInputChunk(state, char.toString());

				// Reconcile the (cosmetic) asterisk echo with the new secret length.
				const after = state.value.length;
				if (after > before) {
					process.stdout.write("*".repeat(after - before));
				} else if (after < before) {
					process.stdout.write("\b \b".repeat(before - after));
				}

				if (state.cancelled || state.done) {
					stdin.setRawMode(wasRaw ?? false);
					stdin.removeListener("data", handler);
					stdin.pause();
					process.stdout.write("\n");
					resolve(state.cancelled ? null : state.value.trim() || null);
				}
			};
			stdin.on("data", handler);
		} else {
			const rl = readline.createInterface({
				input: process.stdin,
				output: process.stdout,
			});
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
