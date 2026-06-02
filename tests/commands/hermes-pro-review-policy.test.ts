import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { registerHermesCommand } from "../../src/commands/hermes.js";
import {
	buildProReviewRequestDraft,
	evaluateProReviewCheck,
	REQUIRED_PRO_REVIEW_FILES,
} from "../../src/hermes/pro-review.js";

describe("Hermes Pro review dirty selected-file policy", () => {
	it("does not make the core Pro-review check depend on git worktree cleanliness", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-core-policy-"));
		await withCwd(tempDir, async () => {
			writeRequiredWorkspace(tempDir);
			initGitFixture(tempDir);
			fs.appendFileSync("src/hermes/pro-review.ts", "dirty selected file\n", "utf8");
			writeJson(
				"docs/hermes/pro-review-request.json",
				buildProReviewRequestDraft({
					canaryPath: "artifacts/hermes/pro-review-native-canary.json",
					prompt: "Review the attached Hermes wrapper files.",
				}),
			);

			const report = evaluateProReviewCheck({
				now: new Date("2026-06-01T00:00:00.000Z"),
			});

			expect(report.gates.some((gate) => gate.name === "request.selectedFilesClean")).toBe(false);
			expect(report.gates.find((gate) => gate.name === "request.payloadBinding")).toMatchObject({
				status: "pass",
			});
		});
	});

	it("still refuses tracked Pro-review seed refreshes that bind dirty selected files", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-pro-review-refresh-policy-"));
		await withCwd(tempDir, async () => {
			writeRequiredWorkspace(tempDir);
			initGitFixture(tempDir);
			fs.appendFileSync("src/hermes/pro-review.ts", "dirty selected file\n", "utf8");

			const result = await runHermesCommand([
				"hermes",
				"pro-review-refresh",
				"--write",
				"--write-tracked-seed",
				"--json",
				"--request",
				"docs/hermes/pro-review-request.json",
				"--canary",
				"artifacts/hermes/pro-review-native-canary.json",
				"--prompt",
				"Review the attached Hermes wrapper files.",
			]);
			const report = JSON.parse(result.stdout) as { status: string; detail: string };

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({ status: "input_error" });
			expect(report.detail).toContain(
				"Refusing to write tracked Pro review request while selected tracked file(s) are dirty",
			);
			expect(report.detail).toContain("src/hermes/pro-review.ts");
		});
	});
});

async function runHermesCommand(args: string[]): Promise<{ exitCode: unknown; stdout: string }> {
	const output: string[] = [];
	const logSpy = vi.spyOn(console, "log").mockImplementation((...values: unknown[]) => {
		output.push(values.map(String).join(" "));
	});
	const program = new Command();
	registerHermesCommand(program);
	process.exitCode = undefined;
	try {
		await program.parseAsync(["node", "telclaude", ...args]);
		return { exitCode: process.exitCode, stdout: output.join("\n") };
	} finally {
		process.exitCode = undefined;
		logSpy.mockRestore();
	}
}

async function withCwd<T>(cwd: string, fn: () => Promise<T> | T): Promise<T> {
	const original = process.cwd();
	process.chdir(cwd);
	try {
		return await fn();
	} finally {
		process.chdir(original);
	}
}

function initGitFixture(cwd: string): void {
	execFileSync("git", ["init", "-q"], { cwd });
	execFileSync("git", ["config", "user.email", "hermes-wrapper-test@example.invalid"], {
		cwd,
	});
	execFileSync("git", ["config", "user.name", "Hermes Wrapper Test"], { cwd });
	execFileSync("git", ["add", "."], { cwd });
	execFileSync("git", ["commit", "-q", "-m", "fixture"], { cwd });
}

function writeRequiredWorkspace(root: string): void {
	for (const file of REQUIRED_PRO_REVIEW_FILES) {
		const resolved = path.join(root, file);
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		if (file.endsWith(".json")) {
			writeJson(resolved, { fixture: file });
		} else {
			fs.writeFileSync(resolved, `test fixture for ${file}\n`, "utf8");
		}
	}
	writeJson(path.join(root, "artifacts/hermes/pro-review-native-canary.json"), proReviewCanary());
}

function proReviewCanary() {
	const observedAt = "2026-06-01T00:00:00.000Z";
	return {
		schemaVersion: "telclaude.hermes.pro-review-native-canary.v1",
		status: "pass",
		transport: "chrome-extension-native",
		recipe: "chatgpt",
		modelSelectionStatus: "selected",
		modelUsed: "Extended Pro",
		live: true,
		runId: "canary_test",
		conversationId: "conv_test",
		conversationUrl: "https://chatgpt.com/c/conv_test",
		extensionInstanceId: "ext_test",
		extensionVersion: "0.5.19",
		promptClass: "non-private transport canary",
		expectedResponse: "OK",
		response: "OK",
		warnings: [],
		observedAt,
		reverifiedAt: observedAt,
		dryCanary: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "ok",
			transport: "chrome-extension-native",
			live: false,
		},
		liveCanary: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension canary --chatgpt --live --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "ok",
			transport: "chrome-extension-native",
			live: true,
			modelUsed: "Extended Pro",
			response: "OK",
		},
		nativeStatus: {
			command:
				"YOETZ_AGENT=1 yoetz browser extension reconnect --chatgpt --extension-instance-id ext_test --format json",
			exitCode: 0,
			status: "connected",
			detail: "native host socket is reachable and extension hello was observed",
			extensionId: "njdakhppfigmloihiikbjmheejfndbfa",
			extensionInstanceId: "ext_test",
			extensionVersion: "0.5.19",
			nativeHostName: "com.yoetz.chatgpt_native",
			protocolVersion: 1,
			socketReachable: true,
			transport: "chrome-extension-native",
		},
		checks: [
			{
				name: "native.status",
				status: "pass",
				detail: "host command reported Yoetz ChatGPT native extension connected",
			},
		],
	};
}

function writeJson(filePath: string, value: unknown): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
