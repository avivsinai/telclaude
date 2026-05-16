import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCronPreprocess } from "../../src/cron/preprocess.js";

describe("cron preprocess", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "telclaude-preprocess-"));
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("runs an executable with JSON input on stdin", async () => {
		const result = await runCronPreprocess(
			{
				command: "node",
				args: [
					"-e",
					[
						"let body='';",
						"process.stdin.on('data', chunk => body += chunk);",
						"process.stdin.on('end', () => {",
						" const parsed = JSON.parse(body);",
						" console.log('routine=' + parsed.routineId);",
						"});",
					].join(""),
				],
				timeoutMs: 5_000,
			},
			{
				routineId: "cron-test",
				trigger: "cron",
				input: {},
			},
			new AbortController().signal,
			{ rootCwd: tempDir },
		);

		expect(result.stdout.trim()).toBe("routine=cron-test");
		expect(result.stderr).toBe("");
		expect(result.truncatedStdout).toBe(false);
	});

	it("allows workspace-confined executable paths", async () => {
		const scriptPath = path.join(tempDir, "routine.js");
		fs.writeFileSync(
			scriptPath,
			[
				"#!/usr/bin/env node",
				"let body='';",
				"process.stdin.on('data', chunk => body += chunk);",
				"process.stdin.on('end', () => {",
				" const parsed = JSON.parse(body);",
				" console.log('path-routine=' + parsed.routineId);",
				"});",
			].join("\n"),
			{ mode: 0o755 },
		);

		const result = await runCronPreprocess(
			{
				command: scriptPath,
				timeoutMs: 5_000,
			},
			{
				routineId: "cron-test",
				trigger: "cron",
				input: {},
			},
			new AbortController().signal,
			{ rootCwd: tempDir },
		);

		expect(result.stdout.trim()).toBe("path-routine=cron-test");
	});

	it("rejects shell syntax and shell executables", async () => {
		await expect(
			runCronPreprocess(
				{ command: "node -e", timeoutMs: 5_000 },
				{ routineId: "cron-test", trigger: "cron", input: {} },
				new AbortController().signal,
				{ rootCwd: tempDir },
			),
		).rejects.toThrow(/not shell syntax/);

		await expect(
			runCronPreprocess(
				{ command: "sh", timeoutMs: 5_000 },
				{ routineId: "cron-test", trigger: "cron", input: {} },
				new AbortController().signal,
				{ rootCwd: tempDir },
			),
		).rejects.toThrow(/must not be a shell/);
	});

	it("confines cwd to the configured root", async () => {
		await expect(
			runCronPreprocess(
				{ command: "node", cwd: "..", timeoutMs: 5_000 },
				{ routineId: "cron-test", trigger: "cron", input: {} },
				new AbortController().signal,
				{ rootCwd: tempDir },
			),
		).rejects.toThrow(/cwd must stay inside/);
	});

	it("rejects unsafe path commands outside the configured root", async () => {
		await expect(
			runCronPreprocess(
				{ command: process.execPath, timeoutMs: 5_000 },
				{ routineId: "cron-test", trigger: "cron", input: {} },
				new AbortController().signal,
				{ rootCwd: tempDir },
			),
		).rejects.toThrow(/command path must stay inside/);

		await expect(
			runCronPreprocess(
				{ command: "curl", timeoutMs: 5_000 },
				{ routineId: "cron-test", trigger: "cron", input: {} },
				new AbortController().signal,
				{ rootCwd: tempDir },
			),
		).rejects.toThrow(/safe command allowlist/);
	});
});
