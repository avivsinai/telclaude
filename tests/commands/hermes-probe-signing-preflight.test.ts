import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { registerHermesCommand } from "../../src/commands/hermes.js";

describe("Hermes signed probe CLI preflight", () => {
	it.each([
		["edge.whatsapp", "edge-whatsapp.json"],
		["sideeffect.ledger", "sideeffect-ledger.json"],
		["providers.approval-binding", "providers-approval-binding.json"],
		["workflow.cron", "workflow-cron.json"],
	] as const)("refuses %s live evidence writes without the operator relay signing key", async (surface, fileName) => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hermes-probe-no-signing-key-"));
		const evidencePath = path.join(tempDir, fileName);
		const originalPrivateKey = process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
		const originalPublicKey = process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;

		try {
			delete process.env.OPERATOR_RPC_RELAY_PRIVATE_KEY;
			delete process.env.OPERATOR_RPC_RELAY_PUBLIC_KEY;
			const result = await runHermesCommand([
				"hermes",
				"probe",
				surface,
				"--allow-run",
				"--json",
				"--out",
				evidencePath,
			]);
			const report = JSON.parse(result.stdout) as {
				status: string;
				surface: string;
				detail: string;
			};

			expect(result.exitCode).toBe(1);
			expect(report).toMatchObject({
				status: "input_error",
				surface,
				detail:
					"Missing relay response signing key for operator. Set OPERATOR_RPC_RELAY_PRIVATE_KEY.",
			});
			expect(fs.existsSync(evidencePath)).toBe(false);
		} finally {
			restoreEnv("OPERATOR_RPC_RELAY_PRIVATE_KEY", originalPrivateKey);
			restoreEnv("OPERATOR_RPC_RELAY_PUBLIC_KEY", originalPublicKey);
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
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

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
	} else {
		process.env[name] = value;
	}
}
