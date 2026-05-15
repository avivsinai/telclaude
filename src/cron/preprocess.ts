import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { CronPreprocessCommand } from "./types.js";

const SAFE_PATH_COMMANDS = new Set(["node", "python", "python3", "deno", "bun", "tsx"]);
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_STDOUT_BYTES = 16 * 1024;
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;

export type CronPreprocessInput = {
	routineId: string;
	trigger: "cron";
	input: Record<string, unknown>;
};

export type CronPreprocessResult = {
	stdout: string;
	stderr: string;
	truncatedStdout: boolean;
	truncatedStderr: boolean;
};

function clampPositive(value: number | undefined, fallback: number, max: number): number {
	if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
		return fallback;
	}
	return Math.min(Math.floor(value), max);
}

function validateToken(value: string, label: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`${label} must not be empty`);
	}
	if (/[\0\r\n]/.test(trimmed)) {
		throw new Error(`${label} must be a single-line string`);
	}
	return trimmed;
}

function ensureInsideRoot(candidatePath: string, root: string, label: string): string {
	const resolvedRoot = fs.existsSync(root) ? fs.realpathSync(root) : path.resolve(root);
	const candidate = fs.existsSync(candidatePath)
		? fs.realpathSync(candidatePath)
		: path.resolve(candidatePath);
	const rootWithSep = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
	if (candidate !== resolvedRoot && !candidate.startsWith(rootWithSep)) {
		throw new Error(`${label} must stay inside the telclaude working directory`);
	}
	return candidate;
}

function validateCommand(command: string, root: string): string {
	const trimmed = validateToken(command, "preprocess command");
	if (/\s/.test(trimmed) || /[;&|<>$`(){}[\]*?]/.test(trimmed)) {
		throw new Error("preprocess command must be an executable name or path, not shell syntax");
	}
	if (["sh", "bash", "zsh", "fish", "dash", "ksh"].includes(path.basename(trimmed))) {
		throw new Error("preprocess command must not be a shell");
	}
	if (path.isAbsolute(trimmed)) {
		return ensureInsideRoot(trimmed, root, "preprocess command path");
	}
	if (trimmed.includes(path.sep)) {
		return ensureInsideRoot(path.join(root, trimmed), root, "preprocess command path");
	}
	if (!SAFE_PATH_COMMANDS.has(trimmed)) {
		throw new Error(
			`preprocess command '${trimmed}' is not in the safe command allowlist; use a workspace-confined executable path instead`,
		);
	}
	return trimmed;
}

function resolveConfinedCwd(requested: string | undefined, root: string): string {
	const resolvedRoot = ensureInsideRoot(root, root, "preprocess root");
	if (!requested?.trim()) {
		return resolvedRoot;
	}
	const candidateRaw = path.isAbsolute(requested) ? requested : path.join(resolvedRoot, requested);
	const candidate = ensureInsideRoot(candidateRaw, resolvedRoot, "preprocess cwd");
	if (!fs.existsSync(candidate) || !fs.statSync(candidate).isDirectory()) {
		throw new Error("preprocess cwd must be an existing directory");
	}
	return candidate;
}

function appendCapped(
	current: Buffer[],
	chunk: Buffer,
	maxBytes: number,
): { chunks: Buffer[]; truncated: boolean } {
	const existingBytes = current.reduce((sum, item) => sum + item.byteLength, 0);
	if (existingBytes >= maxBytes) {
		return { chunks: current, truncated: true };
	}
	const remaining = maxBytes - existingBytes;
	if (chunk.byteLength <= remaining) {
		return { chunks: [...current, chunk], truncated: false };
	}
	return { chunks: [...current, chunk.subarray(0, remaining)], truncated: true };
}

export async function runCronPreprocess(
	config: CronPreprocessCommand,
	input: CronPreprocessInput,
	signal: AbortSignal,
	options?: { rootCwd?: string },
): Promise<CronPreprocessResult> {
	const rootCwd = options?.rootCwd ?? process.env.TELCLAUDE_AGENT_WORKDIR ?? process.cwd();
	const command = validateCommand(config.command, rootCwd);
	const args = (config.args ?? []).map((arg, index) =>
		validateToken(arg, `preprocess arg ${index}`),
	);
	const cwd = resolveConfinedCwd(config.cwd, rootCwd);
	const timeoutMs = clampPositive(config.timeoutMs, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
	const maxStdoutBytes = clampPositive(
		config.maxStdoutBytes,
		DEFAULT_MAX_STDOUT_BYTES,
		MAX_STDOUT_BYTES,
	);

	const controller = new AbortController();
	const timeout = setTimeout(() => {
		controller.abort(new Error(`preprocess timed out after ${timeoutMs}ms`));
	}, timeoutMs);
	if (typeof timeout === "object" && "unref" in timeout) timeout.unref();

	let parentAbortHandler: (() => void) | undefined;
	if (signal.aborted) {
		controller.abort(signal.reason);
	} else {
		parentAbortHandler = () => controller.abort(signal.reason);
		signal.addEventListener("abort", parentAbortHandler, { once: true });
	}

	try {
		return await new Promise<CronPreprocessResult>((resolve, reject) => {
			const child = spawn(command, args, {
				cwd,
				env: {
					PATH: process.env.PATH ?? "/usr/bin:/bin",
					LANG: process.env.LANG ?? "C.UTF-8",
					LC_ALL: process.env.LC_ALL ?? "C.UTF-8",
					TELCLAUDE_ROUTINE_ID: input.routineId,
				},
				shell: false,
				stdio: ["pipe", "pipe", "pipe"],
				signal: controller.signal,
			});

			let stdoutChunks: Buffer[] = [];
			let stderrChunks: Buffer[] = [];
			let truncatedStdout = false;
			let truncatedStderr = false;

			child.stdout.on("data", (chunk: Buffer) => {
				const result = appendCapped(stdoutChunks, chunk, maxStdoutBytes);
				stdoutChunks = result.chunks;
				truncatedStdout = truncatedStdout || result.truncated;
			});
			child.stderr.on("data", (chunk: Buffer) => {
				const result = appendCapped(stderrChunks, chunk, MAX_STDERR_BYTES);
				stderrChunks = result.chunks;
				truncatedStderr = truncatedStderr || result.truncated;
			});
			child.on("error", (err) => {
				reject(err);
			});
			child.on("close", (code, signalName) => {
				const stdout = Buffer.concat(stdoutChunks).toString("utf8");
				const stderr = Buffer.concat(stderrChunks).toString("utf8");
				if (code !== 0) {
					const reason = signalName ? `signal ${signalName}` : `exit code ${code ?? "unknown"}`;
					reject(new Error(`preprocess failed with ${reason}${stderr ? `: ${stderr}` : ""}`));
					return;
				}
				resolve({
					stdout,
					stderr,
					truncatedStdout,
					truncatedStderr,
				});
			});
			child.stdin.end(JSON.stringify(input));
		});
	} finally {
		clearTimeout(timeout);
		if (parentAbortHandler) {
			signal.removeEventListener("abort", parentAbortHandler);
		}
	}
}
