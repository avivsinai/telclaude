import { afterEach, describe, expect, it } from "vitest";
import {
	collectAgentRuntimeStatuses,
	type RuntimeCommandRunner,
} from "../../src/agent-runtime/status.js";

const ORIGINAL_CODEX_HOME = process.env.CODEX_HOME;

function makeRunner(outputs: Record<string, { status: number; stdout?: string; stderr?: string }>) {
	const runner: RuntimeCommandRunner = (command, args) => {
		const key = [command, ...args].join(" ");
		const output = outputs[key];
		if (!output) {
			return { status: 127, stdout: "", stderr: "not found" };
		}
		return {
			status: output.status,
			stdout: output.stdout ?? "",
			stderr: output.stderr ?? "",
		};
	};
	return runner;
}

describe("agent runtime status", () => {
	afterEach(() => {
		if (ORIGINAL_CODEX_HOME === undefined) {
			delete process.env.CODEX_HOME;
		} else {
			process.env.CODEX_HOME = ORIGINAL_CODEX_HOME;
		}
	});

	it("reports Claude Code and Codex as ready when both CLIs are present and Codex has a controlled home", () => {
		process.env.CODEX_HOME = "/tmp/telclaude-codex-home";
		const statuses = collectAgentRuntimeStatuses({
			runner: makeRunner({
				"claude --version": { status: 0, stdout: "claude 1.2.3\n" },
				"codex --version": { status: 0, stdout: "codex-cli 0.130.0\n" },
				"codex exec --help": { status: 0, stdout: "Usage: codex exec\n  --json\n" },
			}),
		});

		expect(statuses.find((runtime) => runtime.id === "claude-code")).toMatchObject({
			readiness: "ready",
			version: "claude 1.2.3",
		});
		expect(statuses.find((runtime) => runtime.id === "codex")).toMatchObject({
			readiness: "ready",
			version: "codex-cli 0.130.0",
			capabilities: {
				jsonEvents: true,
				controlledHome: true,
			},
		});
	});

	it("warns when Codex is installed but would use global config", () => {
		delete process.env.CODEX_HOME;
		const statuses = collectAgentRuntimeStatuses({
			runner: makeRunner({
				"claude --version": { status: 0, stdout: "claude 1.2.3\n" },
				"codex --version": { status: 0, stdout: "codex-cli 0.130.0\n" },
				"codex exec --help": { status: 0, stdout: "Usage: codex exec\n  --json\n" },
			}),
		});

		expect(statuses.find((runtime) => runtime.id === "codex")).toMatchObject({
			readiness: "warning",
			capabilities: {
				controlledHome: false,
			},
		});
	});

	it("reports Codex missing when the CLI is absent", () => {
		const statuses = collectAgentRuntimeStatuses({
			runner: makeRunner({
				"claude --version": { status: 0, stdout: "claude 1.2.3\n" },
			}),
		});

		expect(statuses.find((runtime) => runtime.id === "codex")).toMatchObject({
			readiness: "missing",
			version: null,
		});
	});

	it("warns instead of reporting missing when Claude is installed but failing", () => {
		process.env.CODEX_HOME = "/tmp/telclaude-codex-home";
		const statuses = collectAgentRuntimeStatuses({
			runner: makeRunner({
				"claude --version": {
					status: 1,
					stderr: "database is locked",
				},
				"codex --version": { status: 0, stdout: "codex-cli 0.130.0\n" },
				"codex exec --help": { status: 0, stdout: "Usage: codex exec\n  --json\n" },
			}),
		});

		expect(statuses.find((runtime) => runtime.id === "claude-code")).toMatchObject({
			readiness: "warning",
			version: null,
			detail: expect.stringContaining("database is locked"),
		});
	});
});
