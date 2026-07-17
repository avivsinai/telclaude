import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import { registerHermesCommand } from "../../src/commands/hermes.js";

describe("hermes household memory probe CLI", () => {
	it("recognizes the separate household sibling surface and fails closed without allow-run", async () => {
		const stdout: string[] = [];
		const logSpy = vi.spyOn(console, "log").mockImplementation((...values: unknown[]) => {
			stdout.push(values.map(String).join(" "));
		});
		const program = new Command();
		registerHermesCommand(program);
		process.exitCode = undefined;
		try {
			await program.parseAsync([
				"node",
				"telclaude",
				"hermes",
				"probe",
				"served_mcp.household_memory",
				"--json",
			]);
			const report = JSON.parse(stdout.join("\n")) as Record<string, unknown>;
			expect(report).toMatchObject({
				probeId: "served_mcp.household_memory",
				status: "pending",
				ran: false,
			});
			expect(process.exitCode).toBe(2);
		} finally {
			process.exitCode = undefined;
			logSpy.mockRestore();
		}
	});
});
