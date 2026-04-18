/**
 * `telclaude gateway` — lifecycle commands for the docker-compose stack.
 *
 * Wraps `docker compose` (build/up/down/logs/ps) with a friendly output layer
 * so operators don't need to remember the exact compose incantations. Pairs
 * with `telclaude onboard` (first-run wizard) and `telclaude dev doctor`
 * (health check) — onboard gets you a config, gateway starts/stops the
 * containers, doctor tells you what's broken.
 *
 * Design notes:
 * - Pure orchestration. No container config changes here; we only shell out.
 * - Docker vs native is detected via `getSandboxMode()`. In native mode the
 *   relay process itself is the supervisor, so lifecycle verbs are a no-op
 *   with a pointer to `telclaude relay`. `status` still works natively by
 *   inspecting host processes.
 * - Output is testable by injecting a `runner` (spawn wrapper) and a writer.
 *   The `registerGatewayCommand` path uses the default real runners; tests
 *   drive the pure `runGateway*` functions directly.
 * - Colors are ANSI-escaped manually (no chalk dep) and gated on TTY so
 *   CI captures don't get mangled.
 */

import { type SpawnSyncReturns, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import { getChildLogger } from "../logging.js";
import { getSandboxMode } from "../sandbox/index.js";

const logger = getChildLogger({ module: "cmd-gateway" });

// The six containers we expect in a full Docker deployment. Order here
// drives table row order.
const EXPECTED_SERVICES = [
	"telclaude",
	"telclaude-agent",
	"agent-social",
	"google-services",
	"totp",
	"vault",
] as const;

// Health-wait tuning — `docker compose up -d` returns as soon as containers
// start, but healthchecks can take a few seconds. Poll every POLL_MS up to
// MAX_WAIT_MS, then give up and report whatever we see.
const HEALTH_POLL_MS = 1_500;
const HEALTH_MAX_WAIT_MS = 45_000;

// ──────────────────────────────────────────────────────────────────────────
// Injectable runners — lets tests mock child_process without monkey-patching.
// ──────────────────────────────────────────────────────────────────────────

export interface GatewayRunners {
	/** Synchronous capture of stdout/stderr/status. Used for `docker compose ps`. */
	runSync: (cmd: string, args: string[], cwd: string) => SpawnSyncReturns<string>;
	/** Streaming command (inherits stdio). Resolves with exit code. Used for build/up/down/logs. */
	runStreaming: (cmd: string, args: string[], cwd: string) => Promise<number>;
}

export const defaultRunners: GatewayRunners = {
	runSync: (cmd, args, cwd) =>
		spawnSync(cmd, args, {
			cwd,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		}),
	runStreaming: (cmd, args, cwd) =>
		new Promise<number>((resolve) => {
			const child = spawn(cmd, args, {
				cwd,
				stdio: "inherit",
			});
			child.on("close", (code) => resolve(code ?? 1));
			child.on("error", (err) => {
				logger.error({ err: String(err) }, "gateway runner spawn error");
				resolve(1);
			});
		}),
};

// ──────────────────────────────────────────────────────────────────────────
// Docker compose discovery + shape
// ──────────────────────────────────────────────────────────────────────────

export interface GatewayContext {
	cwd: string;
	dockerDir: string;
	mode: "docker" | "native";
	runners: GatewayRunners;
	out: (line: string) => void;
	err: (line: string) => void;
	useColor: boolean;
}

export interface GatewayOptions {
	cwd?: string;
	runners?: GatewayRunners;
	out?: (line: string) => void;
	err?: (line: string) => void;
	useColor?: boolean;
	modeOverride?: "docker" | "native";
}

function buildContext(options: GatewayOptions = {}): GatewayContext {
	const cwd = options.cwd ?? process.cwd();
	const dockerDir = path.join(cwd, "docker");
	const mode = options.modeOverride ?? getSandboxMode();
	return {
		cwd,
		dockerDir,
		mode,
		runners: options.runners ?? defaultRunners,
		out: options.out ?? ((l) => console.log(l)),
		err: options.err ?? ((l) => console.error(l)),
		useColor: options.useColor ?? Boolean(process.stdout.isTTY),
	};
}

function ensureDockerDir(ctx: GatewayContext): boolean {
	const compose = path.join(ctx.dockerDir, "docker-compose.yml");
	if (!fs.existsSync(compose)) {
		ctx.err(`docker-compose.yml not found at ${compose}`);
		ctx.err("Gateway commands must run from the repo root (where docker/ lives).");
		return false;
	}
	return true;
}

function ensureDockerCli(ctx: GatewayContext): boolean {
	const res = ctx.runners.runSync("docker", ["--version"], ctx.cwd);
	if (res.status !== 0) {
		ctx.err("docker CLI not available. Install Docker Desktop (macOS) or docker-ce (Linux).");
		return false;
	}
	return true;
}

function ensureDockerMode(ctx: GatewayContext, verb: string): boolean {
	if (ctx.mode === "docker") return true;
	// Currently the process itself may be running inside Docker while managing
	// the host stack. We only refuse mutation verbs in native mode; status
	// still works (it'll report relay process liveness).
	ctx.out("Native mode detected (no Docker stack).");
	ctx.out(
		`Native mode is supervised by the relay process; use \`telclaude relay --profile X\` instead of \`telclaude gateway ${verb}\`.`,
	);
	return false;
}

// ──────────────────────────────────────────────────────────────────────────
// Verb implementations — each returns an exit code.
// ──────────────────────────────────────────────────────────────────────────

export async function runGatewayInstall(options: GatewayOptions = {}): Promise<number> {
	const ctx = buildContext(options);
	// Order matters: mode check runs first so native mode can exit cleanly
	// without requiring docker/ or the docker CLI to be present.
	if (!ensureDockerMode(ctx, "install")) return 0;
	if (!ensureDockerDir(ctx)) return 1;
	if (!ensureDockerCli(ctx)) return 1;

	ctx.out("Building telclaude images (docker compose build)...");
	const code = await ctx.runners.runStreaming("docker", ["compose", "build"], ctx.dockerDir);
	if (code === 0) {
		ctx.out("Build complete.");
	} else {
		ctx.err(`docker compose build failed with exit code ${code}.`);
	}
	return code;
}

export async function runGatewayStart(options: GatewayOptions = {}): Promise<number> {
	const ctx = buildContext(options);
	if (!ensureDockerMode(ctx, "start")) return 0;
	if (!ensureDockerDir(ctx)) return 1;
	if (!ensureDockerCli(ctx)) return 1;

	ctx.out("Starting telclaude stack (docker compose up -d)...");
	const code = await ctx.runners.runStreaming("docker", ["compose", "up", "-d"], ctx.dockerDir);
	if (code !== 0) {
		ctx.err(`docker compose up failed with exit code ${code}.`);
		return code;
	}

	ctx.out("Waiting for containers to become healthy...");
	const final = await waitForHealth(ctx, HEALTH_MAX_WAIT_MS, HEALTH_POLL_MS);
	renderStatusTable(ctx, final);

	if (allRunningAndHealthy(final)) {
		ctx.out("All containers are up and healthy.");
		return 0;
	}
	ctx.err("Some containers are not yet healthy — see table above.");
	ctx.err(
		"Retry with `telclaude gateway status` or inspect with `telclaude gateway logs <service>`.",
	);
	return 1;
}

export async function runGatewayStop(options: GatewayOptions = {}): Promise<number> {
	const ctx = buildContext(options);
	if (!ensureDockerMode(ctx, "stop")) return 0;
	if (!ensureDockerDir(ctx)) return 1;
	if (!ensureDockerCli(ctx)) return 1;

	ctx.out("Stopping telclaude stack (docker compose down)...");
	// No -v: we preserve named volumes by default. Operators can nuke state
	// with `cd docker && docker compose down -v` if they know what they want.
	const code = await ctx.runners.runStreaming("docker", ["compose", "down"], ctx.dockerDir);
	if (code === 0) {
		ctx.out("Stack stopped. Volumes preserved.");
	} else {
		ctx.err(`docker compose down failed with exit code ${code}.`);
	}
	return code;
}

export async function runGatewayRestart(options: GatewayOptions = {}): Promise<number> {
	const stopCode = await runGatewayStop(options);
	if (stopCode !== 0) return stopCode;
	return runGatewayStart(options);
}

export async function runGatewayStatus(options: GatewayOptions = {}): Promise<number> {
	const ctx = buildContext(options);

	if (ctx.mode === "native") {
		return runNativeStatus(ctx);
	}

	if (!ensureDockerDir(ctx)) return 1;
	if (!ensureDockerCli(ctx)) return 1;

	const snapshot = captureStatus(ctx);
	renderStatusTable(ctx, snapshot);
	return allRunningAndHealthy(snapshot) ? 0 : 1;
}

export async function runGatewayLogs(
	service: string | undefined,
	options: GatewayOptions & { follow?: boolean; tail?: number } = {},
): Promise<number> {
	const ctx = buildContext(options);
	if (!ensureDockerMode(ctx, "logs")) return 0;
	if (!ensureDockerDir(ctx)) return 1;
	if (!ensureDockerCli(ctx)) return 1;

	if (service && !EXPECTED_SERVICES.includes(service as (typeof EXPECTED_SERVICES)[number])) {
		ctx.err(`Unknown service: ${service}. Known services: ${EXPECTED_SERVICES.join(", ")}.`);
		return 1;
	}

	const tail = String(options.tail ?? 200);
	const args = ["compose", "logs", "--tail", tail];
	if (options.follow) args.push("--follow");
	if (service) args.push(service);

	return ctx.runners.runStreaming("docker", args, ctx.dockerDir);
}

// ──────────────────────────────────────────────────────────────────────────
// Status shape + renderer
// ──────────────────────────────────────────────────────────────────────────

export interface ContainerStatus {
	service: string;
	/** container name (if known) */
	name: string | null;
	state: string; // running / exited / created / paused / missing
	health: string; // healthy / unhealthy / starting / none / missing
	/** raw `Status` string from docker, e.g. "Up 2 hours (healthy)" */
	status: string | null;
	/** Last few lines of container logs for quick glance. Only populated on `status` verb. */
	lastLog: string | null;
}

/**
 * Parse `docker compose ps --format json` output. Compose emits either a
 * JSON array or one JSON object per line depending on version; handle both.
 */
export function parseComposePs(raw: string): Array<Record<string, unknown>> {
	const trimmed = raw.trim();
	if (!trimmed) return [];
	// Newline-delimited JSON (compose v2 default).
	if (trimmed.startsWith("{")) {
		const out: Array<Record<string, unknown>> = [];
		for (const line of trimmed.split(/\r?\n/)) {
			const clean = line.trim();
			if (!clean) continue;
			try {
				out.push(JSON.parse(clean) as Record<string, unknown>);
			} catch (err) {
				logger.debug({ err: String(err), line: clean }, "failed to parse compose ps line");
			}
		}
		return out;
	}
	// Array form (older compose, or --format json=array).
	try {
		const parsed = JSON.parse(trimmed);
		if (Array.isArray(parsed)) return parsed as Array<Record<string, unknown>>;
	} catch (err) {
		logger.debug({ err: String(err) }, "failed to parse compose ps array");
	}
	return [];
}

function stringField(row: Record<string, unknown>, ...keys: string[]): string | null {
	for (const key of keys) {
		const v = row[key];
		if (typeof v === "string" && v.length > 0) return v;
	}
	return null;
}

export function statusesFromComposePs(raw: string): ContainerStatus[] {
	const rows = parseComposePs(raw);
	const byService = new Map<string, ContainerStatus>();
	for (const row of rows) {
		const service = stringField(row, "Service", "service");
		if (!service) continue;
		byService.set(service, {
			service,
			name: stringField(row, "Name", "name"),
			state: stringField(row, "State", "state") ?? "unknown",
			health: stringField(row, "Health", "health") ?? "none",
			status: stringField(row, "Status", "status"),
			lastLog: null,
		});
	}
	const out: ContainerStatus[] = [];
	for (const expected of EXPECTED_SERVICES) {
		const found = byService.get(expected);
		if (found) {
			out.push(found);
		} else {
			out.push({
				service: expected,
				name: null,
				state: "missing",
				health: "missing",
				status: null,
				lastLog: null,
			});
		}
	}
	return out;
}

function captureStatus(ctx: GatewayContext): ContainerStatus[] {
	const res = ctx.runners.runSync(
		"docker",
		["compose", "ps", "--all", "--format", "json"],
		ctx.dockerDir,
	);
	if (res.status !== 0) {
		const stderr = (res.stderr ?? "").toString().trim();
		ctx.err(`docker compose ps failed (exit ${res.status}): ${stderr || "no stderr output"}`);
		return EXPECTED_SERVICES.map((service) => ({
			service,
			name: null,
			state: "unknown",
			health: "unknown",
			status: null,
			lastLog: null,
		}));
	}
	const statuses = statusesFromComposePs((res.stdout ?? "").toString());
	// Annotate each with a short log tail for the table. Best-effort; skip
	// on failure so the table still renders.
	for (const entry of statuses) {
		if (entry.state === "missing" || !entry.name) continue;
		const logRes = ctx.runners.runSync(
			"docker",
			["logs", "--tail", "1", entry.name],
			ctx.dockerDir,
		);
		if (logRes.status === 0) {
			const line =
				((logRes.stdout ?? "").toString() || (logRes.stderr ?? "").toString())
					.split(/\r?\n/)
					.filter((l) => l.trim().length > 0)
					.pop() ?? null;
			if (line) entry.lastLog = line.length > 80 ? `${line.slice(0, 77)}...` : line;
		}
	}
	return statuses;
}

async function waitForHealth(
	ctx: GatewayContext,
	maxWaitMs: number,
	pollMs: number,
): Promise<ContainerStatus[]> {
	const deadline = Date.now() + maxWaitMs;
	let snapshot = captureStatus(ctx);
	while (!allRunningAndHealthy(snapshot) && Date.now() < deadline) {
		await new Promise<void>((resolve) => {
			setTimeout(resolve, pollMs);
		});
		snapshot = captureStatus(ctx);
	}
	return snapshot;
}

export function allRunningAndHealthy(snapshot: ContainerStatus[]): boolean {
	if (snapshot.length === 0) return false;
	for (const entry of snapshot) {
		if (entry.state !== "running") return false;
		if (entry.health === "unhealthy") return false;
		// `starting` is tolerated during start-up but should resolve before we
		// call the stack healthy. `none` means the container has no healthcheck,
		// which we treat as healthy-by-default (vault/totp have no healthcheck).
		if (entry.health === "starting") return false;
	}
	return true;
}

// ── Rendering ─────────────────────────────────────────────────────────────

const ANSI = {
	reset: "\u001b[0m",
	dim: "\u001b[2m",
	green: "\u001b[32m",
	yellow: "\u001b[33m",
	red: "\u001b[31m",
	cyan: "\u001b[36m",
};

function colorize(useColor: boolean, code: string, text: string): string {
	return useColor ? `${code}${text}${ANSI.reset}` : text;
}

function stateColor(useColor: boolean, state: string, health: string): string {
	if (state === "running" && (health === "healthy" || health === "none")) {
		return colorize(useColor, ANSI.green, state);
	}
	if (state === "running" && health === "starting") {
		return colorize(useColor, ANSI.yellow, state);
	}
	if (state === "missing") {
		return colorize(useColor, ANSI.red, state);
	}
	if (state === "running") {
		// running-but-unhealthy
		return colorize(useColor, ANSI.yellow, state);
	}
	return colorize(useColor, ANSI.red, state);
}

function healthColor(useColor: boolean, health: string): string {
	switch (health) {
		case "healthy":
			return colorize(useColor, ANSI.green, health);
		case "starting":
			return colorize(useColor, ANSI.yellow, health);
		case "unhealthy":
			return colorize(useColor, ANSI.red, health);
		case "missing":
			return colorize(useColor, ANSI.red, health);
		default:
			return colorize(useColor, ANSI.dim, health);
	}
}

export function renderStatusTable(ctx: GatewayContext, snapshot: ContainerStatus[]): void {
	// Header
	const headers = ["SERVICE", "STATE", "HEALTH", "LAST LOG"];
	const widths = [
		Math.max(headers[0].length, ...snapshot.map((s) => s.service.length)),
		Math.max(headers[1].length, ...snapshot.map((s) => s.state.length)),
		Math.max(headers[2].length, ...snapshot.map((s) => s.health.length)),
		// Last-log column width is capped so the table stays readable.
		Math.min(80, Math.max(headers[3].length, ...snapshot.map((s) => (s.lastLog ?? "").length))),
	];

	const pad = (text: string, width: number) => text + " ".repeat(Math.max(0, width - text.length));

	const header = headers.map((h, i) => pad(h, widths[i] ?? 0)).join("  ");
	ctx.out(colorize(ctx.useColor, ANSI.cyan, header));
	ctx.out(widths.map((w) => "-".repeat(w)).join("  "));

	for (const entry of snapshot) {
		const row = [
			pad(entry.service, widths[0] ?? 0),
			// state / health are coloured — we pad BEFORE applying color so
			// width calc is correct; ANSI escapes don't count toward visible width.
			wrapColored(pad(entry.state, widths[1] ?? 0), entry.state, () =>
				stateColor(ctx.useColor, entry.state, entry.health),
			),
			wrapColored(pad(entry.health, widths[2] ?? 0), entry.health, () =>
				healthColor(ctx.useColor, entry.health),
			),
			pad((entry.lastLog ?? "").slice(0, widths[3] ?? 0), widths[3] ?? 0),
		];
		ctx.out(row.join("  "));
	}
}

/**
 * Replace the first occurrence of `token` in `padded` with the colored
 * version. Preserves the outer padding so the table stays aligned when
 * ANSI escapes are present.
 */
function wrapColored(padded: string, token: string, recolor: () => string): string {
	const idx = padded.indexOf(token);
	if (idx < 0) return padded;
	return padded.slice(0, idx) + recolor() + padded.slice(idx + token.length);
}

// ──────────────────────────────────────────────────────────────────────────
// Native-mode status: inspect host processes.
// ──────────────────────────────────────────────────────────────────────────

function runNativeStatus(ctx: GatewayContext): number {
	ctx.out("Native mode — inspecting host processes.");
	const relayRunning = isRelayProcessRunning(ctx);
	if (relayRunning) {
		ctx.out(colorize(ctx.useColor, ANSI.green, "relay: running"));
		ctx.out("Use `telclaude status` for runtime details.");
		return 0;
	}
	ctx.out(colorize(ctx.useColor, ANSI.red, "relay: not running"));
	ctx.out("Start the relay in this shell: `telclaude relay --profile simple` (or strict / test).");
	return 1;
}

function isRelayProcessRunning(ctx: GatewayContext): boolean {
	// Try `pgrep -f` first; fall back to `ps -A -o` parse on platforms that
	// ship ps but not pgrep (BSDs). Ignore our own process.
	const myPid = String(process.pid);

	const pgrepRes = ctx.runners.runSync("pgrep", ["-f", "telclaude relay"], ctx.cwd);
	if (pgrepRes.status === 0) {
		const lines = (pgrepRes.stdout ?? "")
			.split(/\r?\n/)
			.map((l) => l.trim())
			.filter((l) => l.length > 0 && l !== myPid);
		if (lines.length > 0) return true;
	}

	const psRes = ctx.runners.runSync("ps", ["-Ao", "pid=,command="], ctx.cwd);
	if (psRes.status === 0) {
		for (const line of (psRes.stdout ?? "").split(/\r?\n/)) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			if (trimmed.startsWith(`${myPid} `)) continue;
			if (/telclaude\s+relay\b/.test(trimmed)) return true;
		}
	}
	return false;
}

// ──────────────────────────────────────────────────────────────────────────
// Command registration
// ──────────────────────────────────────────────────────────────────────────

export function registerGatewayCommand(program: Command): void {
	const gateway = program
		.command("gateway")
		.description("Manage the docker-compose stack (install, start, stop, restart, status, logs)");

	gateway
		.command("install")
		.description("Build telclaude images (docker compose build). Idempotent.")
		.action(async () => {
			const code = await runGatewayInstall();
			process.exitCode = code;
		});

	gateway
		.command("start")
		.description("Start the stack (docker compose up -d) and wait for health.")
		.action(async () => {
			const code = await runGatewayStart();
			process.exitCode = code;
		});

	gateway
		.command("stop")
		.description("Stop the stack (docker compose down). Volumes preserved.")
		.action(async () => {
			const code = await runGatewayStop();
			process.exitCode = code;
		});

	gateway
		.command("restart")
		.description("Stop then start the stack.")
		.action(async () => {
			const code = await runGatewayRestart();
			process.exitCode = code;
		});

	gateway
		.command("status")
		.description("Show per-container state, health, and last log line.")
		.action(async () => {
			const code = await runGatewayStatus();
			process.exitCode = code;
		});

	gateway
		.command("logs [service]")
		.description(
			"Tail the last 200 lines of logs. Optionally restrict to one service or use --follow.",
		)
		.option("-f, --follow", "Stream logs continuously")
		.option("-n, --tail <lines>", "Number of lines to show (default: 200)", (v) =>
			Number.parseInt(v, 10),
		)
		.action(async (service: string | undefined, opts: { follow?: boolean; tail?: number }) => {
			const code = await runGatewayLogs(service, {
				follow: opts.follow,
				tail: opts.tail,
			});
			process.exitCode = code;
		});
}

// Exported for tests.
export const __internals = {
	EXPECTED_SERVICES,
	HEALTH_POLL_MS,
	HEALTH_MAX_WAIT_MS,
	buildContext,
	ensureDockerDir,
	ensureDockerCli,
	ensureDockerMode,
	parseComposePs,
	statusesFromComposePs,
	allRunningAndHealthy,
	captureStatus,
	waitForHealth,
	runNativeStatus,
	isRelayProcessRunning,
	renderStatusTable,
	wrapColored,
};
