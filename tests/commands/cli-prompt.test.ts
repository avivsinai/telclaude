import { describe, expect, it } from "vitest";

import { applySecretInputChunk, type SecretInputState } from "../../src/commands/cli-prompt.js";

const ESC = "";
const PASTE_START = `${ESC}[200~`;
const PASTE_END = `${ESC}[201~`;
const CR = "\r";
const LF = "\n";
const EOT = ""; // Ctrl+D
const ETX = ""; // Ctrl+C
const DEL = ""; // backspace key
const BS = "\b"; // ^H

function fresh(): SecretInputState {
	return { value: "" };
}

describe("applySecretInputChunk", () => {
	it("appends a normal multi-character paste verbatim in one data event", () => {
		// Pasting a 31-char key used to come back duplicated/corrupted because the
		// whole buffer was treated as a single key.
		const key = "BSA0123456789abcdefghijKLMNOPqr"; // 31 chars
		expect(key).toHaveLength(31);

		const state = applySecretInputChunk(fresh(), key);

		expect(state.value).toBe(key);
		expect(state.value).toHaveLength(31);
		expect(state.done).toBeFalsy();
		expect(state.cancelled).toBeFalsy();
	});

	it("strips bracketed-paste markers wrapping the payload", () => {
		const key = "BSA0123456789abcdefghijKLMNOPqr"; // 31 chars
		const chunk = `${PASTE_START}${key}${PASTE_END}`;

		const state = applySecretInputChunk(fresh(), chunk);

		// Only the clean key survives — no ESC, no [200~/[201~ residue, no doubling.
		expect(state.value).toBe(key);
		expect(state.value).toHaveLength(31);
		expect(state.value).not.toContain("[");
		expect(state.value).not.toContain("~");
		expect(state.value).not.toContain(ESC);
	});

	it("submits on an embedded newline using only the pre-newline text", () => {
		const state = applySecretInputChunk(fresh(), `secret-key${LF}trailing-garbage`);

		expect(state.done).toBe(true);
		expect(state.value).toBe("secret-key");
		// Anything after the newline is ignored.
		expect(state.value).not.toContain("trailing");
	});

	it("submits on a bracketed paste that ends with Enter", () => {
		const state = applySecretInputChunk(fresh(), `${PASTE_START}my-key${PASTE_END}${CR}`);

		expect(state.done).toBe(true);
		expect(state.value).toBe("my-key");
	});

	it("treats CR and EOT as submit", () => {
		expect(applySecretInputChunk(fresh(), `abc${CR}`)).toMatchObject({ value: "abc", done: true });
		expect(applySecretInputChunk(fresh(), `abc${EOT}`)).toMatchObject({
			value: "abc",
			done: true,
		});
	});

	it("cancels on Ctrl+C and keeps no value past it", () => {
		const state = applySecretInputChunk(fresh(), `abc${ETX}def`);

		expect(state.cancelled).toBe(true);
		expect(state.done).toBeFalsy();
		expect(state.value).toBe("abc");
	});

	it("applies DEL and ^H backspaces per character", () => {
		// "abcd" then two DEL then "Z" -> "abZ"
		const state = applySecretInputChunk(fresh(), `abcd${DEL}${DEL}Z`);
		expect(state.value).toBe("abZ");

		const state2 = applySecretInputChunk(fresh(), `xy${BS}Z`);
		expect(state2.value).toBe("xZ");
	});

	it("ignores backspace on an empty buffer", () => {
		expect(applySecretInputChunk(fresh(), `${DEL}${DEL}`).value).toBe("");
	});

	it("drops other ESC-led control sequences (e.g. arrow keys)", () => {
		// Left arrow is ESC[D; it must not leave "[D" in the secret.
		const state = applySecretInputChunk(fresh(), `ab${ESC}[Dcd`);
		expect(state.value).toBe("abcd");
		expect(state.value).not.toContain("[");
	});

	it("accumulates across multiple data events", () => {
		const state = fresh();
		applySecretInputChunk(state, PASTE_START);
		applySecretInputChunk(state, "chunk-one");
		applySecretInputChunk(state, "chunk-two");
		applySecretInputChunk(state, PASTE_END);
		expect(state.value).toBe("chunk-onechunk-two");

		applySecretInputChunk(state, LF);
		expect(state.done).toBe(true);
		expect(state.value).toBe("chunk-onechunk-two");
	});

	it("ignores further chunks once done or cancelled", () => {
		const done = applySecretInputChunk(fresh(), `done${LF}`);
		applySecretInputChunk(done, "ignored");
		expect(done.value).toBe("done");

		const cancelled = applySecretInputChunk(fresh(), `x${ETX}`);
		applySecretInputChunk(cancelled, "ignored");
		expect(cancelled.value).toBe("x");
	});
});
