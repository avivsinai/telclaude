import { spawnSync } from "node:child_process";

export type AgentRuntimeId = "claude-code" | "codex";

export type AgentRuntimeReadiness = "ready" | "warning" | "missing";

export type AgentRuntimeStatus = {
	id: AgentRuntimeId;
	label: string;
	readiness: AgentRuntimeReadiness;
	version: string | null;
	detail: string;
	remediation?: string;
	capabilities: {
		streaming: boolean;
		jsonEvents: boolean;
		remoteServer: boolean;
		controlledHome: boolean;
	};
	paths: {
		command: string;
		homeEnv?: string;
	};
};

export type RuntimeCommandResult = {
	status: number | null;
	stdout: string;
	stderr: string;
	error?: unknown;
};

export type RuntimeCommandRunner = (command: string, args: string[]) => RuntimeCommandResult;

const defaultRunner: RuntimeCommandRunner = (command, args) => {
	const result = spawnSync(command, args, {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	return {
		status: result.status,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		error: result.error,
	};
};

function firstLine(text: string): string {
	return text.trim().split(/\r?\n/)[0]?.trim() ?? "";
}

function commandFailedBecauseMissing(result: RuntimeCommandResult): boolean {
	const code =
		result.error && typeof result.error === "object" && "code" in result.error
			? String((result.error as { code?: unknown }).code)
			: "";
	return code === "ENOENT" || (result.status === 127 && /not found|ENOENT/i.test(result.stderr));
}

function failureDetail(command: string, result: RuntimeCommandResult): string {
	const stderr = firstLine(result.stderr);
	const stdout = firstLine(result.stdout);
	const detail = stderr || stdout || String(result.error ?? "unknown error");
	return `${command} failed${result.status === null ? "" : ` with exit ${result.status}`}: ${detail}`;
}

function collectClaudeCodeStatus(runner: RuntimeCommandRunner): AgentRuntimeStatus {
	const version = runner("claude", ["--version"]);
	if (version.status !== 0) {
		const missing = commandFailedBecauseMissing(version);
		return {
			id: "claude-code",
			label: "Claude Code",
			readiness: missing ? "missing" : "warning",
			version: null,
			detail: missing ? "claude CLI not found on PATH" : failureDetail("claude --version", version),
			remediation: missing
				? "brew install anthropic-ai/cli/claude && claude login"
				: "run claude --version and repair the Claude Code installation or login state",
			capabilities: {
				streaming: true,
				jsonEvents: false,
				remoteServer: true,
				controlledHome: Boolean(process.env.CLAUDE_CONFIG_DIR || process.env.TELCLAUDE_CLAUDE_HOME),
			},
			paths: {
				command: "claude",
				...(process.env.CLAUDE_CONFIG_DIR ? { homeEnv: process.env.CLAUDE_CONFIG_DIR } : {}),
			},
		};
	}
	return {
		id: "claude-code",
		label: "Claude Code",
		readiness: "ready",
		version: firstLine(version.stdout) || "installed",
		detail: "Claude Code runtime available",
		capabilities: {
			streaming: true,
			jsonEvents: false,
			remoteServer: true,
			controlledHome: Boolean(process.env.CLAUDE_CONFIG_DIR || process.env.TELCLAUDE_CLAUDE_HOME),
		},
		paths: {
			command: "claude",
			...(process.env.CLAUDE_CONFIG_DIR ? { homeEnv: process.env.CLAUDE_CONFIG_DIR } : {}),
		},
	};
}

function collectCodexStatus(runner: RuntimeCommandRunner): AgentRuntimeStatus {
	const version = runner("codex", ["--version"]);
	if (version.status !== 0) {
		const missing = commandFailedBecauseMissing(version);
		return {
			id: "codex",
			label: "Codex",
			readiness: missing ? "missing" : "warning",
			version: null,
			detail: missing ? "codex CLI not found on PATH" : failureDetail("codex --version", version),
			remediation: missing
				? "install Codex CLI and configure a dedicated CODEX_HOME for telclaude"
				: "run codex --version and repair the Codex installation or auth state",
			capabilities: {
				streaming: false,
				jsonEvents: false,
				remoteServer: false,
				controlledHome: Boolean(process.env.CODEX_HOME),
			},
			paths: {
				command: "codex",
				...(process.env.CODEX_HOME ? { homeEnv: process.env.CODEX_HOME } : {}),
			},
		};
	}

	const help = runner("codex", ["exec", "--help"]);
	const supportsJson = help.status === 0 && help.stdout.includes("--json");
	const controlledHome = Boolean(process.env.CODEX_HOME);
	const readiness: AgentRuntimeReadiness =
		supportsJson && controlledHome ? "ready" : supportsJson ? "warning" : "missing";
	const details: string[] = [];
	if (supportsJson) {
		details.push("codex exec --json available");
	} else {
		details.push("codex exec --json unavailable");
	}
	if (controlledHome) {
		details.push("CODEX_HOME is set");
	} else {
		details.push("CODEX_HOME is not set; runtime would use global Codex config");
	}

	return {
		id: "codex",
		label: "Codex",
		readiness,
		version: firstLine(version.stdout) || "installed",
		detail: details.join("; "),
		...(controlledHome
			? {}
			: { remediation: "Set CODEX_HOME to a dedicated telclaude profile before enabling writes" }),
		capabilities: {
			streaming: false,
			jsonEvents: supportsJson,
			remoteServer: false,
			controlledHome,
		},
		paths: {
			command: "codex",
			...(process.env.CODEX_HOME ? { homeEnv: process.env.CODEX_HOME } : {}),
		},
	};
}

export function collectAgentRuntimeStatuses(options?: {
	runner?: RuntimeCommandRunner;
}): AgentRuntimeStatus[] {
	const runner = options?.runner ?? defaultRunner;
	return [collectClaudeCodeStatus(runner), collectCodexStatus(runner)];
}
