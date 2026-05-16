import type { Command } from "commander";
import { type AgentRuntimeStatus, collectAgentRuntimeStatuses } from "../agent-runtime/status.js";

function formatRuntimeStatus(statuses: AgentRuntimeStatus[]): string {
	const lines = ["Agent runtimes"];
	for (const runtime of statuses) {
		lines.push(
			`- ${runtime.label}: ${runtime.readiness}${runtime.version ? ` (${runtime.version})` : ""}`,
		);
		lines.push(`  ${runtime.detail}`);
		if (runtime.remediation) {
			lines.push(`  try: ${runtime.remediation}`);
		}
	}
	return lines.join("\n");
}

export function registerRuntimesCommand(program: Command): void {
	const runtimes = program.command("runtimes").description("Inspect agent runtime readiness");

	runtimes
		.command("status")
		.description("Show Claude Code and Codex runtime readiness")
		.option("--json", "Output as JSON")
		.action((opts: { json?: boolean }) => {
			const statuses = collectAgentRuntimeStatuses();
			if (opts.json) {
				console.log(JSON.stringify({ runtimes: statuses }, null, 2));
				return;
			}
			console.log(formatRuntimeStatus(statuses));
		});
}
