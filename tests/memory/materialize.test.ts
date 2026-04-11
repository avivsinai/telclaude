import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
	materializeClaudeProjectMemory,
	resolveClaudeProjectMemoryPath,
	toClaudeProjectSlug,
} from "../../src/memory/materialize.js";

const ORIGINAL_CLAUDE_CONFIG_DIR = process.env.CLAUDE_CONFIG_DIR;
const ORIGINAL_TELCLAUDE_CLAUDE_HOME = process.env.TELCLAUDE_CLAUDE_HOME;

describe("Claude memory materialization", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-claude-memory-"));
		process.env.CLAUDE_CONFIG_DIR = tempDir;
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
		if (ORIGINAL_CLAUDE_CONFIG_DIR === undefined) {
			delete process.env.CLAUDE_CONFIG_DIR;
		} else {
			process.env.CLAUDE_CONFIG_DIR = ORIGINAL_CLAUDE_CONFIG_DIR;
		}
		if (ORIGINAL_TELCLAUDE_CLAUDE_HOME === undefined) {
			delete process.env.TELCLAUDE_CLAUDE_HOME;
		} else {
			process.env.TELCLAUDE_CLAUDE_HOME = ORIGINAL_TELCLAUDE_CLAUDE_HOME;
		}
	});

	it("derives the Claude project memory path from cwd", () => {
		expect(toClaudeProjectSlug("/workspace")).toBe("-workspace");
		expect(resolveClaudeProjectMemoryPath("/workspace")).toBe(
			path.join(tempDir, "projects", "-workspace", "memory", "MEMORY.md"),
		);
	});

	it("writes the compiled relay memory into the Claude project memory file", () => {
		const written = materializeClaudeProjectMemory("/workspace", "# Test Memory\nhello");
		expect(written).toBe(path.join(tempDir, "projects", "-workspace", "memory", "MEMORY.md"));
		expect(fs.readFileSync(written!, "utf-8")).toBe("# Test Memory\nhello\n");
	});
});
